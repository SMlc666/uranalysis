#include "engine/elf_loader.h"
#include "engine/log.h"


#include <fstream>
#include <unordered_map>

namespace engine {

namespace {

constexpr std::uint8_t kElfMagic[4] = {0x7f, 'E', 'L', 'F'};
constexpr std::uint8_t kElfClass32 = 1;
constexpr std::uint8_t kElfClass64 = 2;
constexpr std::uint8_t kElfData2Lsb = 1;
constexpr std::uint16_t kElfMachineAarch64 = 183;

struct Elf64_Ehdr {
    std::uint8_t e_ident[16];
    std::uint16_t e_type;
    std::uint16_t e_machine;
    std::uint32_t e_version;
    std::uint64_t e_entry;
    std::uint64_t e_phoff;
    std::uint64_t e_shoff;
    std::uint32_t e_flags;
    std::uint16_t e_ehsize;
    std::uint16_t e_phentsize;
    std::uint16_t e_phnum;
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;
    std::uint16_t e_shstrndx;
};

struct Elf64_Phdr {
    std::uint32_t p_type;
    std::uint32_t p_flags;
    std::uint64_t p_offset;
    std::uint64_t p_vaddr;
    std::uint64_t p_paddr;
    std::uint64_t p_filesz;
    std::uint64_t p_memsz;
    std::uint64_t p_align;
};

struct Elf64_Shdr {
    std::uint32_t sh_name;
    std::uint32_t sh_type;
    std::uint64_t sh_flags;
    std::uint64_t sh_addr;
    std::uint64_t sh_offset;
    std::uint64_t sh_size;
    std::uint32_t sh_link;
    std::uint32_t sh_info;
    std::uint64_t sh_addralign;
    std::uint64_t sh_entsize;
};

struct Elf64_Sym {
    std::uint32_t st_name;
    std::uint8_t st_info;
    std::uint8_t st_other;
    std::uint16_t st_shndx;
    std::uint64_t st_value;
    std::uint64_t st_size;
};

struct Elf64_Rel {
    std::uint64_t r_offset;
    std::uint64_t r_info;
};

struct Elf64_Rela {
    std::uint64_t r_offset;
    std::uint64_t r_info;
    std::int64_t r_addend;
};

bool read_exact(std::ifstream& stream, void* out, std::size_t size) {
    stream.read(static_cast<char*>(out), static_cast<std::streamsize>(size));
    return stream.good();
}

bool read_u64_le(const std::vector<std::uint8_t>& data, std::size_t offset, std::uint64_t& value) {
    if (offset + 8 > data.size()) {
        return false;
    }
    value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(data[offset + i]) << (i * 8);
    }
    return true;
}

bool read_addend_from_image(const LoadedImage& image, std::uint64_t address, std::int64_t& addend) {
    std::vector<std::uint8_t> data;
    if (!image.read_bytes(address, 8, data) || data.size() < 8) {
        return false;
    }
    std::uint64_t value = 0;
    if (!read_u64_le(data, 0, value)) {
        return false;
    }
    addend = static_cast<std::int64_t>(value);
    return true;
}

bool read_addend_from_file(std::ifstream& file,
                           const Elf64_Shdr& target_section,
                           std::uint64_t reloc_offset,
                           std::int64_t& addend) {
    if (target_section.sh_size < 8) {
        return false;
    }
    std::uint64_t file_offset = 0;
    bool has_offset = false;
    if (reloc_offset >= target_section.sh_addr) {
        const std::uint64_t delta = reloc_offset - target_section.sh_addr;
        if (delta + 8 <= target_section.sh_size) {
            file_offset = target_section.sh_offset + delta;
            has_offset = true;
        }
    }
    if (!has_offset && reloc_offset + 8 <= target_section.sh_size) {
        file_offset = target_section.sh_offset + reloc_offset;
        has_offset = true;
    }
    if (!has_offset) {
        return false;
    }

    const auto saved_pos = file.tellg();
    file.clear();
    file.seekg(static_cast<std::streamoff>(file_offset), std::ios::beg);
    if (!file.good()) {
        file.clear();
        file.seekg(saved_pos);
        return false;
    }
    std::vector<std::uint8_t> data(8);
    if (!read_exact(file, data.data(), data.size())) {
        file.clear();
        file.seekg(saved_pos);
        return false;
    }
    file.clear();
    file.seekg(saved_pos);

    std::uint64_t value = 0;
    if (!read_u64_le(data, 0, value)) {
        return false;
    }
    addend = static_cast<std::int64_t>(value);
    return true;
}

bool is_address_in_segments(const std::vector<ElfSegment>& segments, std::uint64_t address) {
    for (const auto& seg : segments) {
        if (address >= seg.vaddr && address < (seg.vaddr + seg.memsz)) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool load_elf(const std::string& path, ElfInfo& info, std::vector<ElfSegment>& segments, std::string& error) {
    std::vector<ElfSection> sections;
    std::vector<ElfSymbol> symbols;
    LoadedImage image;
    return load_elf_image(path, info, segments, sections, image, error);
}

bool load_elf_image_with_symbols_and_relocations(const std::string& path,
                                                 ElfInfo& info,
                                                 std::vector<ElfSegment>& segments,
                                                 std::vector<ElfSection>& sections,
                                                 std::vector<ElfSymbol>& symbols,
                                                 std::vector<ElfRelocation>& relocations,
                                                 LoadedImage& image,
                                                 std::string& error) {
    info = {};
    segments.clear();
    sections.clear();
    symbols.clear();
    relocations.clear();
    image.segments.clear();
    error.clear();

    engine::log::info("Loading ELF file: {}", path);

    std::ifstream file(path, std::ios::binary);

    if (!file) {
        error = "failed to open file";
        return false;
    }

    Elf64_Ehdr header = {};
    if (!read_exact(file, &header, sizeof(header))) {
        error = "failed to read ELF header";
        return false;
    }

    if (header.e_ident[0] != kElfMagic[0] || header.e_ident[1] != kElfMagic[1] ||
        header.e_ident[2] != kElfMagic[2] || header.e_ident[3] != kElfMagic[3]) {
        error = "not an ELF file";
        return false;
    }

    if (header.e_ident[4] != kElfClass64) {
        error = "only ELF64 is supported";
        return false;
    }

    if (header.e_ident[5] != kElfData2Lsb) {
        error = "only little-endian ELF is supported";
        return false;
    }

    info.is_64 = true;
    info.little_endian = true;
    info.entry = header.e_entry;
    info.image_base = 0;
    info.ph_num = header.e_phnum;
    info.sh_num = header.e_shnum;
    if (header.e_machine == kElfMachineAarch64) {
        engine::log::info("Detected AArch64 architecture");
        info.machine = BinaryMachine::kAarch64;
    }


    if (header.e_phoff != 0 && header.e_phnum != 0) {
        if (header.e_phentsize != sizeof(Elf64_Phdr)) {
            error = "unexpected program header entry size";
            return false;
        }

        file.seekg(static_cast<std::streamoff>(header.e_phoff), std::ios::beg);
        if (!file.good()) {
            error = "failed to seek to program headers";
            return false;
        }

        for (std::uint16_t i = 0; i < header.e_phnum; ++i) {
            Elf64_Phdr phdr = {};
            if (!read_exact(file, &phdr, sizeof(phdr))) {
                error = "failed to read program header";
                return false;
            }
            ElfSegment segment = {};
            segment.type = phdr.p_type;
            segment.flags = phdr.p_flags;
            segment.offset = phdr.p_offset;
            segment.vaddr = phdr.p_vaddr;
            segment.filesz = phdr.p_filesz;
            segment.memsz = phdr.p_memsz;
            segments.push_back(segment);

            if (phdr.p_type == 1 && phdr.p_memsz > 0) {
                LoadedSegment loaded = {};
                loaded.vaddr = phdr.p_vaddr;
                loaded.memsz = phdr.p_memsz;
                loaded.data.resize(static_cast<std::size_t>(phdr.p_memsz), 0);

                if (phdr.p_filesz > 0) {
                    file.seekg(static_cast<std::streamoff>(phdr.p_offset), std::ios::beg);
                    if (!file.good()) {
                        error = "failed to seek to segment data";
                        return false;
                    }
                    if (!read_exact(file, loaded.data.data(), static_cast<std::size_t>(phdr.p_filesz))) {
                        error = "failed to read segment data";
                        return false;
                    }
                }
                image.segments.push_back(std::move(loaded));
            }
        }
    }

    if (header.e_shoff != 0 && header.e_shnum != 0) {
        if (header.e_shentsize != sizeof(Elf64_Shdr)) {
            error = "unexpected section header entry size";
            return false;
        }

        std::vector<Elf64_Shdr> raw_sections;
        raw_sections.resize(header.e_shnum);

        file.seekg(static_cast<std::streamoff>(header.e_shoff), std::ios::beg);
        if (!file.good()) {
            error = "failed to seek to section headers";
            return false;
        }

        for (std::uint16_t i = 0; i < header.e_shnum; ++i) {
            if (!read_exact(file, &raw_sections[i], sizeof(Elf64_Shdr))) {
                error = "failed to read section header";
                return false;
            }
        }

        std::vector<char> shstrtab;
        if (header.e_shstrndx < raw_sections.size()) {
            const auto& shstr = raw_sections[header.e_shstrndx];
            if (shstr.sh_size > 0) {
                shstrtab.resize(static_cast<std::size_t>(shstr.sh_size));
                file.seekg(static_cast<std::streamoff>(shstr.sh_offset), std::ios::beg);
                if (!file.good()) {
                    error = "failed to seek to section string table";
                    return false;
                }
                if (!read_exact(file, shstrtab.data(), shstrtab.size())) {
                    error = "failed to read section string table";
                    return false;
                }
            }
        }

        for (const auto& shdr : raw_sections) {
            ElfSection section = {};
            if (!shstrtab.empty() && shdr.sh_name < shstrtab.size()) {
                section.name = &shstrtab[shdr.sh_name];
            }
            section.type = shdr.sh_type;
            section.flags = shdr.sh_flags;
            section.addr = shdr.sh_addr;
            section.offset = shdr.sh_offset;
            section.size = shdr.sh_size;
            sections.push_back(std::move(section));
        }

        std::unordered_map<std::size_t, std::vector<ElfSymbol>> symbols_by_section;
        for (std::size_t sh_idx = 0; sh_idx < raw_sections.size(); ++sh_idx) {
            const auto& shdr = raw_sections[sh_idx];
            if (shdr.sh_type != 2 && shdr.sh_type != 11) {
                continue;
            }
            if (shdr.sh_entsize == 0 || shdr.sh_size == 0) {
                continue;
            }
            const std::size_t count = static_cast<std::size_t>(shdr.sh_size / shdr.sh_entsize);
            if (count == 0) {
                continue;
            }
            if (shdr.sh_link >= raw_sections.size()) {
                continue;
            }

            std::vector<char> strtab;
            const auto& str_section = raw_sections[shdr.sh_link];
            if (str_section.sh_size > 0) {
                strtab.resize(static_cast<std::size_t>(str_section.sh_size));
                file.seekg(static_cast<std::streamoff>(str_section.sh_offset), std::ios::beg);
                if (!file.good()) {
                    error = "failed to seek to symbol string table";
                    return false;
                }
            if (!read_exact(file, strtab.data(), strtab.size())) {
                error = "failed to read symbol string table";
                return false;
            }
        }

            std::vector<ElfSymbol> local_symbols;
            local_symbols.reserve(count);
            file.seekg(static_cast<std::streamoff>(shdr.sh_offset), std::ios::beg);
            if (!file.good()) {
                error = "failed to seek to symbol table";
                return false;
            }

            for (std::size_t i = 0; i < count; ++i) {
                Elf64_Sym sym = {};
                if (!read_exact(file, &sym, sizeof(sym))) {
                    error = "failed to read symbol entry";
                    return false;
                }
                ElfSymbol out = {};
                if (!strtab.empty() && sym.st_name < strtab.size()) {
                    out.name = &strtab[sym.st_name];
                }
                out.value = sym.st_value;
                out.size = sym.st_size;
                out.info = sym.st_info;
                out.other = sym.st_other;
                out.shndx = sym.st_shndx;
                local_symbols.push_back(out);
                symbols.push_back(std::move(out));
            }
            symbols_by_section.emplace(sh_idx, std::move(local_symbols));
        }

        for (std::size_t sh_idx = 0; sh_idx < raw_sections.size(); ++sh_idx) {
            const auto& shdr = raw_sections[sh_idx];
            if (shdr.sh_type != 4 && shdr.sh_type != 9) {
                continue;
            }
            if (shdr.sh_entsize == 0 || shdr.sh_size == 0) {
                continue;
            }
            if (shdr.sh_type == 4 && shdr.sh_entsize != sizeof(Elf64_Rela)) {
                error = "unexpected relocation entry size";
                return false;
            }
            if (shdr.sh_type == 9 && shdr.sh_entsize != sizeof(Elf64_Rel)) {
                error = "unexpected relocation entry size";
                return false;
            }
            const std::size_t count = static_cast<std::size_t>(shdr.sh_size / shdr.sh_entsize);
            if (count == 0) {
                continue;
            }
            file.seekg(static_cast<std::streamoff>(shdr.sh_offset), std::ios::beg);
            if (!file.good()) {
                error = "failed to seek to relocation table";
                return false;
            }
            for (std::size_t i = 0; i < count; ++i) {
                ElfRelocation out = {};
                if (shdr.sh_type == 4) {
                    Elf64_Rela rela = {};
                    if (!read_exact(file, &rela, sizeof(rela))) {
                        error = "failed to read relocation entry";
                        return false;
                    }
                    out.offset = rela.r_offset;
                    out.info = rela.r_info;
                    out.addend = rela.r_addend;
                    out.type = static_cast<std::uint32_t>(rela.r_info & 0xffffffff);
                    out.sym = static_cast<std::uint32_t>(rela.r_info >> 32);
                } else {
                    Elf64_Rel rel = {};
                    if (!read_exact(file, &rel, sizeof(rel))) {
                        error = "failed to read relocation entry";
                        return false;
                    }
                    out.offset = rel.r_offset;
                    out.info = rel.r_info;
                    out.type = static_cast<std::uint32_t>(rel.r_info & 0xffffffff);
                    out.sym = static_cast<std::uint32_t>(rel.r_info >> 32);
                    std::int64_t addend = 0;
                    if (!read_addend_from_image(image, out.offset, addend)) {
                        if (shdr.sh_info < raw_sections.size()) {
                            read_addend_from_file(file, raw_sections[shdr.sh_info], out.offset, addend);
                        }
                    }
                    out.addend = addend;
                }
                if (shdr.sh_info < raw_sections.size()) {
                    const auto& target = raw_sections[shdr.sh_info];
                    if (target.sh_addr != 0 && target.sh_size > out.offset) {
                        const std::uint64_t candidate = target.sh_addr + out.offset;
                        if (is_address_in_segments(segments, candidate) &&
                            !is_address_in_segments(segments, out.offset)) {
                            out.offset = candidate;
                        }
                    }
                    if (shdr.sh_info < sections.size()) {
                        out.target_section = sections[shdr.sh_info].name;
                    }
                }
                auto sym_it = symbols_by_section.find(shdr.sh_link);
                if (sym_it != symbols_by_section.end()) {
                    const auto& table = sym_it->second;
                    if (out.sym < table.size()) {
                        out.symbol_value = table[out.sym].value;
                        out.symbol_name = table[out.sym].name;
                    }
                }
                relocations.push_back(std::move(out));
            }
        }
    }

    return true;
}

bool load_elf_image_with_symbols(const std::string& path,
                                 ElfInfo& info,
                                 std::vector<ElfSegment>& segments,
                                 std::vector<ElfSection>& sections,
                                 std::vector<ElfSymbol>& symbols,
                                 LoadedImage& image,
                                 std::string& error) {
    std::vector<ElfRelocation> relocations;
    return load_elf_image_with_symbols_and_relocations(path, info, segments, sections, symbols, relocations, image,
                                                       error);
}

bool load_elf_image(const std::string& path,
                    ElfInfo& info,
                    std::vector<ElfSegment>& segments,
                    std::vector<ElfSection>& sections,
                    LoadedImage& image,
                    std::string& error) {
    std::vector<ElfSymbol> symbols;
    std::vector<ElfRelocation> relocations;
    return load_elf_image_with_symbols_and_relocations(path, info, segments, sections, symbols, relocations, image,
                                                       error);
}

}  // namespace engine
