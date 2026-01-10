#include "engine/pe_loader.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include "engine/mapped_file.h"

namespace engine {

namespace {

constexpr std::uint16_t kDosMagic = 0x5a4d;
constexpr std::uint32_t kPeSignature = 0x00004550;
constexpr std::uint16_t kPeMagic32 = 0x10b;
constexpr std::uint16_t kPeMagic64 = 0x20b;

constexpr std::uint16_t kMachineX86 = 0x14c;
constexpr std::uint16_t kMachineX64 = 0x8664;

constexpr std::uint32_t kImageScnMemExecute = 0x20000000;
constexpr std::uint32_t kImageScnMemRead = 0x40000000;
constexpr std::uint32_t kImageScnMemWrite = 0x80000000;

constexpr std::uint32_t kPfExec = 0x1;
constexpr std::uint32_t kPfWrite = 0x2;
constexpr std::uint32_t kPfRead = 0x4;

constexpr std::uint64_t kShfAlloc = 0x2;
constexpr std::uint64_t kShfExecInstr = 0x4;

constexpr std::uint32_t kDirectoryExport = 0;
constexpr std::uint32_t kDirectoryImport = 1;
constexpr std::uint32_t kDirectoryReloc = 5;
constexpr std::uint32_t kDirectoryDelayImport = 13;

constexpr std::uint16_t kRelocTypeAbsolute = 0;
constexpr std::uint16_t kRelocTypeHighLow = 3;
constexpr std::uint16_t kRelocTypeDir64 = 10;

constexpr std::uint8_t kPeSymbolFunc = 0x02;

#pragma pack(push, 1)
struct DosHeader {
    std::uint16_t e_magic;
    std::uint8_t unused[58];
    std::uint32_t e_lfanew;
};

struct FileHeader {
    std::uint16_t machine;
    std::uint16_t number_of_sections;
    std::uint32_t time_date_stamp;
    std::uint32_t pointer_to_symbol_table;
    std::uint32_t number_of_symbols;
    std::uint16_t size_of_optional_header;
    std::uint16_t characteristics;
};

struct SectionHeader {
    char name[8];
    std::uint32_t virtual_size;
    std::uint32_t virtual_address;
    std::uint32_t size_of_raw_data;
    std::uint32_t pointer_to_raw_data;
    std::uint32_t pointer_to_relocations;
    std::uint32_t pointer_to_linenumbers;
    std::uint16_t number_of_relocations;
    std::uint16_t number_of_linenumbers;
    std::uint32_t characteristics;
};

struct DataDirectory {
    std::uint32_t virtual_address;
    std::uint32_t size;
};

struct ExportDirectory {
    std::uint32_t characteristics;
    std::uint32_t time_date_stamp;
    std::uint16_t major_version;
    std::uint16_t minor_version;
    std::uint32_t name;
    std::uint32_t base;
    std::uint32_t number_of_functions;
    std::uint32_t number_of_names;
    std::uint32_t address_of_functions;
    std::uint32_t address_of_names;
    std::uint32_t address_of_name_ordinals;
};

struct ImportDescriptor {
    std::uint32_t original_first_thunk;
    std::uint32_t time_date_stamp;
    std::uint32_t forwarder_chain;
    std::uint32_t name;
    std::uint32_t first_thunk;
};

struct DelayImportDescriptor {
    std::uint32_t attributes;
    std::uint32_t name;
    std::uint32_t module_handle;
    std::uint32_t delay_import_address_table;
    std::uint32_t delay_import_name_table;
    std::uint32_t bound_delay_import_table;
    std::uint32_t unload_delay_import_table;
    std::uint32_t time_date_stamp;
};

struct BaseRelocationBlock {
    std::uint32_t virtual_address;
    std::uint32_t size_of_block;
};
#pragma pack(pop)

struct SectionView {
    std::string name;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_ptr = 0;
    std::uint32_t characteristics = 0;
};

struct PeView {
    std::span<const std::uint8_t> data;

    bool read_u8(std::size_t offset, std::uint8_t& value) const {
        if (offset + 1 > data.size()) {
            return false;
        }
        value = data[offset];
        return true;
    }

    bool read_u16(std::size_t offset, std::uint16_t& value) const {
        if (offset + 2 > data.size()) {
            return false;
        }
        value = static_cast<std::uint16_t>(data[offset]) |
                (static_cast<std::uint16_t>(data[offset + 1]) << 8);
        return true;
    }

    bool read_u32(std::size_t offset, std::uint32_t& value) const {
        if (offset + 4 > data.size()) {
            return false;
        }
        value = static_cast<std::uint32_t>(data[offset]) |
                (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
                (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
                (static_cast<std::uint32_t>(data[offset + 3]) << 24);
        return true;
    }

    bool read_u64(std::size_t offset, std::uint64_t& value) const {
        if (offset + 8 > data.size()) {
            return false;
        }
        value = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(data[offset + i]) << (i * 8);
        }
        return true;
    }

    bool slice(std::size_t offset, std::size_t size, std::span<const std::uint8_t>& out) const {
        if (offset + size > data.size()) {
            return false;
        }
        out = std::span<const std::uint8_t>(data.data() + offset, size);
        return true;
    }

    bool read_cstring(std::size_t offset, std::string& out, std::size_t max_len = 4096) const {
        out.clear();
        if (offset >= data.size()) {
            return false;
        }
        for (std::size_t i = 0; offset + i < data.size() && i < max_len; ++i) {
            const char c = static_cast<char>(data[offset + i]);
            if (c == '\0') {
                return true;
            }
            out.push_back(c);
        }
        return !out.empty();
    }
};

std::uint32_t map_segment_flags(std::uint32_t characteristics) {
    std::uint32_t flags = 0;
    if ((characteristics & kImageScnMemExecute) != 0) {
        flags |= kPfExec;
    }
    if ((characteristics & kImageScnMemWrite) != 0) {
        flags |= kPfWrite;
    }
    if ((characteristics & kImageScnMemRead) != 0) {
        flags |= kPfRead;
    }
    return flags;
}

std::uint64_t map_section_flags(std::uint32_t characteristics) {
    std::uint64_t flags = 0;
    if ((characteristics & (kImageScnMemExecute | kImageScnMemRead | kImageScnMemWrite)) != 0) {
        flags |= kShfAlloc;
    }
    if ((characteristics & kImageScnMemExecute) != 0) {
        flags |= kShfExecInstr;
    }
    return flags;
}

std::string section_name(const char name[8]) {
    std::string out;
    out.reserve(8);
    for (char c : std::string_view(name, 8)) {
        if (c == '\0') {
            break;
        }
        out.push_back(c);
    }
    return out;
}

bool is_ascii_printable(const std::string& text) {
    for (unsigned char c : text) {
        if (c < 0x20 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

bool rva_to_file_offset(std::uint32_t rva,
                        const std::vector<SectionView>& sections,
                        std::uint32_t size_of_headers,
                        std::size_t file_size,
                        std::size_t& out_offset) {
    if (rva < size_of_headers) {
        out_offset = static_cast<std::size_t>(rva);
        return out_offset <= file_size;
    }
    for (const auto& section : sections) {
        const std::uint32_t mem_size = std::max(section.virtual_size, section.raw_size);
        if (mem_size == 0) {
            continue;
        }
        if (rva >= section.virtual_address && rva < section.virtual_address + mem_size) {
            const std::uint32_t delta = rva - section.virtual_address;
            const std::uint64_t offset = static_cast<std::uint64_t>(section.raw_ptr) + delta;
            if (offset > file_size) {
                return false;
            }
            out_offset = static_cast<std::size_t>(offset);
            return true;
        }
    }
    return false;
}

const BinarySection* find_section_by_rva(const std::vector<BinarySection>& sections,
                                        std::uint64_t image_base,
                                        std::uint32_t rva) {
    const std::uint64_t addr = image_base + rva;
    for (const auto& section : sections) {
        if (addr >= section.addr && addr < (section.addr + section.size)) {
            return &section;
        }
    }
    return nullptr;
}

bool read_export_symbols(const PeView& view,
                         const std::vector<SectionView>& raw_sections,
                         const std::vector<BinarySection>& sections,
                         std::uint64_t image_base,
                         std::uint32_t size_of_headers,
                         const DataDirectory& directory,
                         std::vector<BinarySymbol>& out_symbols) {
    if (directory.virtual_address == 0 || directory.size < sizeof(ExportDirectory)) {
        return true;
    }

    std::size_t dir_offset = 0;
    if (!rva_to_file_offset(directory.virtual_address, raw_sections, size_of_headers, view.data.size(), dir_offset)) {
        return false;
    }

    std::span<const std::uint8_t> dir_span;
    if (!view.slice(dir_offset, sizeof(ExportDirectory), dir_span)) {
        return false;
    }
    ExportDirectory dir = {};
    std::memcpy(&dir, dir_span.data(), sizeof(dir));

    if (dir.number_of_functions == 0) {
        return true;
    }

    std::unordered_map<std::uint32_t, std::string> names_by_ordinal;
    if (dir.number_of_names > 0 && dir.address_of_names != 0 && dir.address_of_name_ordinals != 0) {
        std::size_t names_offset = 0;
        std::size_t ordinals_offset = 0;
        if (rva_to_file_offset(dir.address_of_names, raw_sections, size_of_headers, view.data.size(), names_offset) &&
            rva_to_file_offset(dir.address_of_name_ordinals, raw_sections, size_of_headers, view.data.size(),
                               ordinals_offset)) {
            for (std::uint32_t i = 0; i < dir.number_of_names; ++i) {
                std::uint32_t name_rva = 0;
                std::uint16_t ordinal = 0;
                if (!view.read_u32(names_offset + i * 4, name_rva)) {
                    break;
                }
                if (!view.read_u16(ordinals_offset + i * 2, ordinal)) {
                    break;
                }
                std::size_t name_offset = 0;
                if (!rva_to_file_offset(name_rva, raw_sections, size_of_headers, view.data.size(), name_offset)) {
                    continue;
                }
                std::string name;
                if (!view.read_cstring(name_offset, name)) {
                    continue;
                }
                if (name.empty() || !is_ascii_printable(name)) {
                    continue;
                }
                names_by_ordinal[static_cast<std::uint32_t>(ordinal)] = name;
            }
        }
    }

    std::size_t functions_offset = 0;
    if (!rva_to_file_offset(dir.address_of_functions, raw_sections, size_of_headers, view.data.size(),
                            functions_offset)) {
        return true;
    }

    for (std::uint32_t i = 0; i < dir.number_of_functions; ++i) {
        std::uint32_t func_rva = 0;
        if (!view.read_u32(functions_offset + i * 4, func_rva)) {
            break;
        }
        if (func_rva == 0) {
            continue;
        }
        BinarySymbol sym;
        const std::uint32_t ordinal = dir.base + i;
        auto name_it = names_by_ordinal.find(i);
        if (name_it != names_by_ordinal.end()) {
            sym.name = name_it->second;
        } else {
            sym.name = "#" + std::to_string(ordinal);
        }

        const bool is_forwarder =
            func_rva >= directory.virtual_address && func_rva < (directory.virtual_address + directory.size);
        if (!is_forwarder) {
            sym.value = image_base + func_rva;
            sym.info = kPeSymbolFunc;
            if (const BinarySection* section = find_section_by_rva(sections, image_base, func_rva)) {
                sym.shndx = static_cast<std::uint16_t>(section - sections.data());
            }
        }
        out_symbols.push_back(std::move(sym));
    }

    return true;
}

bool read_import_symbols(const PeView& view,
                         const std::vector<SectionView>& raw_sections,
                         const std::vector<BinarySection>& sections,
                         std::uint64_t image_base,
                         std::uint32_t size_of_headers,
                         const DataDirectory& directory,
                         bool is_64,
                         std::vector<BinarySymbol>& out_symbols) {
    if (directory.virtual_address == 0 || directory.size < sizeof(ImportDescriptor)) {
        return true;
    }

    std::size_t imp_offset = 0;
    if (!rva_to_file_offset(directory.virtual_address, raw_sections, size_of_headers, view.data.size(), imp_offset)) {
        return false;
    }

    const std::size_t entry_size = sizeof(ImportDescriptor);
    for (std::size_t index = 0;; ++index) {
        std::span<const std::uint8_t> desc_span;
        if (!view.slice(imp_offset + index * entry_size, entry_size, desc_span)) {
            break;
        }
        ImportDescriptor desc = {};
        std::memcpy(&desc, desc_span.data(), sizeof(desc));
        if (desc.original_first_thunk == 0 && desc.first_thunk == 0 && desc.name == 0) {
            break;
        }

        std::size_t name_offset = 0;
        std::string dll_name;
        if (desc.name != 0 &&
            rva_to_file_offset(desc.name, raw_sections, size_of_headers, view.data.size(), name_offset) &&
            view.read_cstring(name_offset, dll_name)) {
            if (!is_ascii_printable(dll_name)) {
                dll_name.clear();
            }
        }
        if (dll_name.empty()) {
            dll_name = "<unknown>";
        }

        const std::uint32_t thunk_rva = desc.original_first_thunk != 0 ? desc.original_first_thunk : desc.first_thunk;
        if (thunk_rva == 0 || desc.first_thunk == 0) {
            continue;
        }

        std::size_t thunk_offset = 0;
        if (!rva_to_file_offset(thunk_rva, raw_sections, size_of_headers, view.data.size(), thunk_offset)) {
            continue;
        }

        const std::size_t entry_bytes = is_64 ? 8 : 4;
        const std::uint64_t ordinal_flag = is_64 ? (1ull << 63) : (1ull << 31);
        for (std::size_t thunk_index = 0;; ++thunk_index) {
            std::uint64_t thunk = 0;
            if (is_64) {
                if (!view.read_u64(thunk_offset + thunk_index * entry_bytes, thunk)) {
                    break;
                }
            } else {
                std::uint32_t thunk32 = 0;
                if (!view.read_u32(thunk_offset + thunk_index * entry_bytes, thunk32)) {
                    break;
                }
                thunk = thunk32;
            }
            if (thunk == 0) {
                break;
            }

            std::string import_name;
            if ((thunk & ordinal_flag) != 0) {
                const std::uint16_t ordinal = static_cast<std::uint16_t>(thunk & 0xffff);
                import_name = "#" + std::to_string(ordinal);
            } else {
                const std::uint32_t name_rva = static_cast<std::uint32_t>(thunk & (is_64 ? 0xffffffffull : 0x7fffffffull));
                std::size_t import_name_offset = 0;
                if (rva_to_file_offset(name_rva, raw_sections, size_of_headers, view.data.size(),
                                       import_name_offset)) {
                    std::string name;
                    if (view.read_cstring(import_name_offset + 2, name) && is_ascii_printable(name)) {
                        import_name = std::move(name);
                    }
                }
                if (import_name.empty()) {
                    import_name = "<unnamed>";
                }
            }

            BinarySymbol sym;
            sym.name = dll_name + "!" + import_name;
            sym.value = image_base + desc.first_thunk + thunk_index * entry_bytes;
            sym.size = entry_bytes;
            if (const BinarySection* section = find_section_by_rva(sections, image_base,
                                                                  desc.first_thunk +
                                                                      static_cast<std::uint32_t>(thunk_index * entry_bytes))) {
                sym.shndx = static_cast<std::uint16_t>(section - sections.data());
            }
            out_symbols.push_back(std::move(sym));
        }
    }

    return true;
}

bool read_delay_import_symbols(const PeView& view,
                               const std::vector<SectionView>& raw_sections,
                               const std::vector<BinarySection>& sections,
                               std::uint64_t image_base,
                               std::uint32_t size_of_headers,
                               const DataDirectory& directory,
                               bool is_64,
                               std::vector<BinarySymbol>& out_symbols) {
    if (directory.virtual_address == 0 || directory.size < sizeof(DelayImportDescriptor)) {
        return true;
    }

    std::size_t imp_offset = 0;
    if (!rva_to_file_offset(directory.virtual_address, raw_sections, size_of_headers, view.data.size(), imp_offset)) {
        return false;
    }

    const std::size_t entry_size = sizeof(DelayImportDescriptor);
    for (std::size_t index = 0;; ++index) {
        std::span<const std::uint8_t> desc_span;
        if (!view.slice(imp_offset + index * entry_size, entry_size, desc_span)) {
            break;
        }
        DelayImportDescriptor desc = {};
        std::memcpy(&desc, desc_span.data(), sizeof(desc));
        if (desc.name == 0 || desc.delay_import_address_table == 0 || desc.delay_import_name_table == 0) {
            if (desc.name == 0 && desc.delay_import_address_table == 0) {
                break;
            }
            continue;
        }

        std::size_t name_offset = 0;
        std::string dll_name;
        if (rva_to_file_offset(desc.name, raw_sections, size_of_headers, view.data.size(), name_offset) &&
            view.read_cstring(name_offset, dll_name)) {
            if (!is_ascii_printable(dll_name)) {
                dll_name.clear();
            }
        }
        if (dll_name.empty()) {
            dll_name = "<unknown>";
        }

        std::size_t thunk_offset = 0;
        if (!rva_to_file_offset(desc.delay_import_name_table, raw_sections, size_of_headers, view.data.size(),
                                thunk_offset)) {
            continue;
        }

        const std::size_t entry_bytes = is_64 ? 8 : 4;
        const std::uint64_t ordinal_flag = is_64 ? (1ull << 63) : (1ull << 31);
        for (std::size_t thunk_index = 0;; ++thunk_index) {
            std::uint64_t thunk = 0;
            if (is_64) {
                if (!view.read_u64(thunk_offset + thunk_index * entry_bytes, thunk)) {
                    break;
                }
            } else {
                std::uint32_t thunk32 = 0;
                if (!view.read_u32(thunk_offset + thunk_index * entry_bytes, thunk32)) {
                    break;
                }
                thunk = thunk32;
            }
            if (thunk == 0) {
                break;
            }

            std::string import_name;
            if ((thunk & ordinal_flag) != 0) {
                const std::uint16_t ordinal = static_cast<std::uint16_t>(thunk & 0xffff);
                import_name = "#" + std::to_string(ordinal);
            } else {
                const std::uint32_t name_rva = static_cast<std::uint32_t>(thunk & (is_64 ? 0xffffffffull : 0x7fffffffull));
                std::size_t import_name_offset = 0;
                if (rva_to_file_offset(name_rva, raw_sections, size_of_headers, view.data.size(),
                                       import_name_offset)) {
                    std::string name;
                    if (view.read_cstring(import_name_offset + 2, name) && is_ascii_printable(name)) {
                        import_name = std::move(name);
                    }
                }
                if (import_name.empty()) {
                    import_name = "<unnamed>";
                }
            }

            BinarySymbol sym;
            sym.name = dll_name + "!" + import_name;
            sym.value = image_base + desc.delay_import_address_table + thunk_index * entry_bytes;
            sym.size = entry_bytes;
            if (const BinarySection* section = find_section_by_rva(sections, image_base,
                                                                  desc.delay_import_address_table +
                                                                      static_cast<std::uint32_t>(thunk_index * entry_bytes))) {
                sym.shndx = static_cast<std::uint16_t>(section - sections.data());
            }
            out_symbols.push_back(std::move(sym));
        }
    }

    return true;
}

bool read_base_relocations(const PeView& view,
                           const std::vector<SectionView>& raw_sections,
                           const std::vector<BinarySection>& sections,
                           std::uint64_t image_base,
                           std::uint32_t size_of_headers,
                           const DataDirectory& directory,
                           const LoadedImage& image,
                           bool is_64,
                           std::vector<BinaryRelocation>& out_relocations) {
    if (directory.virtual_address == 0 || directory.size < sizeof(BaseRelocationBlock)) {
        return true;
    }

    std::size_t reloc_offset = 0;
    if (!rva_to_file_offset(directory.virtual_address, raw_sections, size_of_headers, view.data.size(), reloc_offset)) {
        return false;
    }

    const std::size_t end = reloc_offset + directory.size;
    std::size_t cursor = reloc_offset;
    while (cursor + sizeof(BaseRelocationBlock) <= end) {
        std::span<const std::uint8_t> block_span;
        if (!view.slice(cursor, sizeof(BaseRelocationBlock), block_span)) {
            break;
        }
        BaseRelocationBlock block = {};
        std::memcpy(&block, block_span.data(), sizeof(block));
        if (block.size_of_block < sizeof(BaseRelocationBlock)) {
            break;
        }
        const std::size_t entries_size = block.size_of_block - sizeof(BaseRelocationBlock);
        const std::size_t entry_count = entries_size / sizeof(std::uint16_t);
        std::size_t entries_offset = cursor + sizeof(BaseRelocationBlock);
        for (std::size_t i = 0; i < entry_count; ++i) {
            std::uint16_t entry = 0;
            if (!view.read_u16(entries_offset + i * 2, entry)) {
                break;
            }
            const std::uint16_t type = static_cast<std::uint16_t>(entry >> 12);
            const std::uint16_t offset = static_cast<std::uint16_t>(entry & 0x0fff);
            if (type == kRelocTypeAbsolute) {
                continue;
            }
            if (!is_64 && type != kRelocTypeHighLow) {
                continue;
            }
            if (is_64 && type != kRelocTypeDir64) {
                continue;
            }

            const std::uint64_t reloc_rva = static_cast<std::uint64_t>(block.virtual_address) + offset;
            const std::uint64_t reloc_addr = image_base + reloc_rva;
            std::vector<std::uint8_t> data;
            const std::size_t width = is_64 ? 8 : 4;
            if (!image.read_bytes(reloc_addr, width, data) || data.size() != width) {
                continue;
            }

            std::uint64_t raw_value = 0;
            for (std::size_t j = 0; j < data.size(); ++j) {
                raw_value |= static_cast<std::uint64_t>(data[j]) << (j * 8);
            }
            const std::int64_t addend =
                static_cast<std::int64_t>(raw_value) - static_cast<std::int64_t>(image_base);

            BinaryRelocation reloc;
            reloc.offset = reloc_addr;
            reloc.type = type;
            reloc.addend = addend;
            if (const BinarySection* section = find_section_by_rva(sections, image_base,
                                                                  static_cast<std::uint32_t>(reloc_rva))) {
                reloc.target_section = section->name;
            }
            out_relocations.push_back(std::move(reloc));
        }

        if (block.size_of_block == 0) {
            break;
        }
        cursor += block.size_of_block;
    }

    return true;
}

}  // namespace

bool load_pe(const std::string& path,
             BinaryInfo& info,
             std::vector<BinarySegment>& segments,
             std::string& error) {
    std::vector<BinarySection> sections;
    std::vector<BinarySymbol> symbols;
    std::vector<BinaryRelocation> relocations;
    LoadedImage image;
    return load_pe_image_with_symbols_and_relocations(path,
                                                      info,
                                                      segments,
                                                      sections,
                                                      symbols,
                                                      relocations,
                                                      image,
                                                      error);
}

bool load_pe_image_with_symbols(const std::string& path,
                                BinaryInfo& info,
                                std::vector<BinarySegment>& segments,
                                std::vector<BinarySection>& sections,
                                std::vector<BinarySymbol>& symbols,
                                LoadedImage& image,
                                std::string& error) {
    std::vector<BinaryRelocation> relocations;
    return load_pe_image_with_symbols_and_relocations(path,
                                                      info,
                                                      segments,
                                                      sections,
                                                      symbols,
                                                      relocations,
                                                      image,
                                                      error);
}

bool load_pe_image(const std::string& path,
                   BinaryInfo& info,
                   std::vector<BinarySegment>& segments,
                   std::vector<BinarySection>& sections,
                   LoadedImage& image,
                   std::string& error) {
    std::vector<BinarySymbol> symbols;
    std::vector<BinaryRelocation> relocations;
    return load_pe_image_with_symbols_and_relocations(path,
                                                      info,
                                                      segments,
                                                      sections,
                                                      symbols,
                                                      relocations,
                                                      image,
                                                      error);
}

bool load_pe_image_with_symbols_and_relocations(const std::string& path,
                                                BinaryInfo& info,
                                                std::vector<BinarySegment>& segments,
                                                std::vector<BinarySection>& sections,
                                                std::vector<BinarySymbol>& symbols,
                                                std::vector<BinaryRelocation>& relocations,
                                                LoadedImage& image,
                                                std::string& error) {
    info = {};
    segments.clear();
    sections.clear();
    symbols.clear();
    relocations.clear();
    image.segments.clear();
    error.clear();

    MappedFile file;
    if (!file.open(path, error)) {
        if (error.empty()) {
            error = "failed to open file";
        }
        return false;
    }

    const PeView view{file.bytes()};
    if (view.data.size() < sizeof(DosHeader)) {
        error = "file too small for PE";
        return false;
    }

    DosHeader dos = {};
    std::memcpy(&dos, view.data.data(), sizeof(dos));
    if (dos.e_magic != kDosMagic) {
        error = "not a PE file";
        return false;
    }

    if (dos.e_lfanew == 0 || dos.e_lfanew > static_cast<std::uint32_t>(view.data.size() - 4)) {
        error = "invalid PE header offset";
        return false;
    }

    std::uint32_t signature = 0;
    if (!view.read_u32(dos.e_lfanew, signature)) {
        error = "failed to read PE signature";
        return false;
    }
    if (signature != kPeSignature) {
        error = "invalid PE signature";
        return false;
    }

    const std::size_t file_header_offset = static_cast<std::size_t>(dos.e_lfanew) + 4;
    if (file_header_offset + sizeof(FileHeader) > view.data.size()) {
        error = "failed to read PE file header";
        return false;
    }

    FileHeader file_header = {};
    std::memcpy(&file_header, view.data.data() + file_header_offset, sizeof(file_header));
    if (file_header.number_of_sections == 0) {
        error = "PE has no sections";
        return false;
    }
    if (file_header.machine != kMachineX86 && file_header.machine != kMachineX64) {
        error = "unsupported PE machine";
        return false;
    }

    const std::size_t optional_offset = file_header_offset + sizeof(FileHeader);
    if (optional_offset + file_header.size_of_optional_header > view.data.size()) {
        error = "failed to read optional header";
        return false;
    }

    std::span<const std::uint8_t> optional_header;
    if (!view.slice(optional_offset, file_header.size_of_optional_header, optional_header)) {
        error = "failed to read optional header";
        return false;
    }

    std::uint16_t magic = 0;
    if (optional_header.size() < 2) {
        error = "invalid optional header";
        return false;
    }
    magic = static_cast<std::uint16_t>(optional_header[0]) |
            (static_cast<std::uint16_t>(optional_header[1]) << 8);
    const bool is_64 = (magic == kPeMagic64);
    if (magic != kPeMagic32 && magic != kPeMagic64) {
        error = "unsupported PE optional header magic";
        return false;
    }

    std::uint32_t entry_rva = 0;
    if (!view.read_u32(optional_offset + 16, entry_rva)) {
        error = "invalid PE entry point";
        return false;
    }

    std::uint64_t image_base = 0;
    if (is_64) {
        if (!view.read_u64(optional_offset + 24, image_base)) {
            error = "invalid PE image base";
            return false;
        }
    } else {
        std::uint32_t base32 = 0;
        if (!view.read_u32(optional_offset + 28, base32)) {
            error = "invalid PE image base";
            return false;
        }
        image_base = base32;
    }

    std::uint32_t size_of_headers = 0;
    if (!view.read_u32(optional_offset + 60, size_of_headers)) {
        error = "invalid PE header size";
        return false;
    }

    std::uint32_t number_of_rva_and_sizes = 0;
    const std::size_t dir_count_offset = is_64 ? (optional_offset + 108) : (optional_offset + 92);
    if (!view.read_u32(dir_count_offset, number_of_rva_and_sizes)) {
        error = "invalid PE data directory count";
        return false;
    }

    const std::size_t directories_offset = is_64 ? (optional_offset + 112) : (optional_offset + 96);
    std::vector<DataDirectory> directories;
    directories.reserve(number_of_rva_and_sizes);
    for (std::uint32_t i = 0; i < number_of_rva_and_sizes; ++i) {
        DataDirectory dir = {};
        const std::size_t entry_offset = directories_offset + i * sizeof(DataDirectory);
        if (entry_offset + sizeof(DataDirectory) > view.data.size()) {
            break;
        }
        std::memcpy(&dir, view.data.data() + entry_offset, sizeof(DataDirectory));
        directories.push_back(dir);
    }

    info.format = BinaryFormat::kPe;
    info.machine = (file_header.machine == kMachineX64) ? BinaryMachine::kX86_64 : BinaryMachine::kX86;
    info.is_64 = is_64;
    info.little_endian = true;
    info.entry = image_base + entry_rva;
    info.image_base = image_base;

    std::vector<SectionView> raw_sections;
    raw_sections.reserve(file_header.number_of_sections);

    const std::size_t section_headers_offset = optional_offset + file_header.size_of_optional_header;
    if (section_headers_offset > view.data.size()) {
        error = "invalid section header offset";
        return false;
    }

    for (std::uint16_t i = 0; i < file_header.number_of_sections; ++i) {
        const std::size_t header_offset = section_headers_offset + i * sizeof(SectionHeader);
        if (header_offset + sizeof(SectionHeader) > view.data.size()) {
            error = "failed to read section header";
            return false;
        }
        SectionHeader sh = {};
        std::memcpy(&sh, view.data.data() + header_offset, sizeof(SectionHeader));

        SectionView section_view;
        section_view.name = section_name(sh.name);
        section_view.virtual_address = sh.virtual_address;
        section_view.virtual_size = sh.virtual_size;
        section_view.raw_size = sh.size_of_raw_data;
        section_view.raw_ptr = sh.pointer_to_raw_data;
        section_view.characteristics = sh.characteristics;
        raw_sections.push_back(std::move(section_view));
    }

    if (size_of_headers > 0) {
        const std::size_t header_size = static_cast<std::size_t>(size_of_headers);
        LoadedSegment loaded = {};
        loaded.vaddr = image_base;
        loaded.memsz = header_size;
        loaded.data.resize(header_size, 0);

        const std::size_t to_read = std::min(header_size, view.data.size());
        if (to_read > 0) {
            std::copy(view.data.begin(), view.data.begin() + static_cast<std::ptrdiff_t>(to_read),
                      loaded.data.begin());
        }

        BinarySegment seg = {};
        seg.type = 0;
        seg.flags = kPfRead;
        seg.offset = 0;
        seg.vaddr = image_base;
        seg.filesz = size_of_headers;
        seg.memsz = size_of_headers;
        segments.push_back(seg);
        image.segments.push_back(std::move(loaded));
    }

    for (const auto& sh : raw_sections) {
        const std::uint32_t raw_size = sh.raw_size;
        const std::uint32_t virtual_size = sh.virtual_size;
        const std::uint64_t mem_size = std::max<std::uint32_t>(virtual_size, raw_size);
        if (mem_size == 0) {
            continue;
        }
        if (sh.raw_ptr > view.data.size()) {
            error = "section raw data offset out of range";
            return false;
        }
        if (raw_size > 0 && sh.raw_ptr + raw_size > view.data.size()) {
            error = "section raw data out of range";
            return false;
        }

        BinarySection section = {};
        section.name = sh.name;
        section.type = sh.characteristics;
        section.flags = map_section_flags(sh.characteristics);
        section.addr = image_base + sh.virtual_address;
        section.offset = sh.raw_ptr;
        section.size = mem_size;
        sections.push_back(section);

        BinarySegment segment = {};
        segment.type = 0;
        segment.flags = map_segment_flags(sh.characteristics);
        segment.offset = sh.raw_ptr;
        segment.vaddr = image_base + sh.virtual_address;
        segment.filesz = raw_size;
        segment.memsz = mem_size;
        segments.push_back(segment);

        LoadedSegment loaded = {};
        loaded.vaddr = segment.vaddr;
        loaded.memsz = mem_size;
        loaded.data.resize(static_cast<std::size_t>(mem_size), 0);
        if (raw_size > 0) {
            const std::size_t start = static_cast<std::size_t>(sh.raw_ptr);
            std::copy(view.data.begin() + static_cast<std::ptrdiff_t>(start),
                      view.data.begin() + static_cast<std::ptrdiff_t>(start + raw_size),
                      loaded.data.begin());
        }
        image.segments.push_back(std::move(loaded));
    }

    info.ph_num = static_cast<std::uint16_t>(segments.size());
    info.sh_num = static_cast<std::uint16_t>(sections.size());

    if (kDirectoryExport < directories.size()) {
        if (!read_export_symbols(view, raw_sections, sections, image_base, size_of_headers,
                                 directories[kDirectoryExport], symbols)) {
            error = "failed to read PE exports";
            return false;
        }
    }

    if (kDirectoryImport < directories.size()) {
        if (!read_import_symbols(view, raw_sections, sections, image_base, size_of_headers,
                                 directories[kDirectoryImport], is_64, symbols)) {
            error = "failed to read PE imports";
            return false;
        }
    }

    if (kDirectoryDelayImport < directories.size()) {
        if (!read_delay_import_symbols(view, raw_sections, sections, image_base, size_of_headers,
                                       directories[kDirectoryDelayImport], is_64, symbols)) {
            error = "failed to read PE delay imports";
            return false;
        }
    }

    if (kDirectoryReloc < directories.size()) {
        if (!read_base_relocations(view, raw_sections, sections, image_base, size_of_headers,
                                   directories[kDirectoryReloc], image, is_64, relocations)) {
            error = "failed to read PE relocations";
            return false;
        }
    }

    return true;
}

}  // namespace engine
