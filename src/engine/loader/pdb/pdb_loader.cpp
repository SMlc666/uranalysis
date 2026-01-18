#include "engine/pdb_loader.h"

#include "engine/mapped_file.h"

#include <algorithm>
#include <filesystem>
#include <unordered_set>

// raw_pdb headers
#include "PDB.h"
#include "PDB_RawFile.h"
#include "PDB_DBIStream.h"
#include "PDB_TPIStream.h"
#include "PDB_InfoStream.h"
#include "PDB_ModuleInfoStream.h"
#include "PDB_ModuleSymbolStream.h"

namespace engine {

namespace {

/// Symbol info byte for function type (matches ELF STT_FUNC)
constexpr std::uint8_t kSymbolInfoFunc = 0x02;

/// Symbol info byte for object/data (matches ELF STT_OBJECT)
constexpr std::uint8_t kSymbolInfoObject = 0x01;

/// Check if a symbol record is a function
bool is_function_record(PDB::CodeView::DBI::SymbolRecordKind kind) {
    switch (kind) {
        case PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32:
        case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32:
        case PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID:
        case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID:
        case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_DPC:
        case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_DPC_ID:
            return true;
        default:
            return false;
    }
}

/// Check if a symbol record is a thunk
bool is_thunk_record(PDB::CodeView::DBI::SymbolRecordKind kind) {
    return kind == PDB::CodeView::DBI::SymbolRecordKind::S_THUNK32;
}

/// Check if a symbol record is data
bool is_data_record(PDB::CodeView::DBI::SymbolRecordKind kind) {
    switch (kind) {
        case PDB::CodeView::DBI::SymbolRecordKind::S_GDATA32:
        case PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32:
        case PDB::CodeView::DBI::SymbolRecordKind::S_GTHREAD32:
        case PDB::CodeView::DBI::SymbolRecordKind::S_LTHREAD32:
            return true;
        default:
            return false;
    }
}

/// Check if a public symbol is a function
bool is_public_function(PDB::CodeView::DBI::PublicSymbolFlags flags) {
    using Flags = PDB::CodeView::DBI::PublicSymbolFlags;
    const auto as_int = static_cast<std::uint32_t>(flags);
    const auto code = static_cast<std::uint32_t>(Flags::Code);
    const auto func = static_cast<std::uint32_t>(Flags::Function);
    return (as_int & code) != 0 || (as_int & func) != 0;
}

/// Convert section:offset to RVA and then to VA
std::uint64_t section_offset_to_va(const PDB::ImageSectionStream& sections,
                                   std::uint16_t section,
                                   std::uint32_t offset,
                                   std::uint64_t image_base) {
    if (section == 0) {
        return 0;
    }
    const std::uint32_t rva = sections.ConvertSectionOffsetToRVA(section, offset);
    if (rva == 0 && offset != 0) {
        // Conversion failed
        return 0;
    }
    return image_base + rva;
}

/// Add a symbol to the vector, optionally replacing existing symbols at the same address
void add_symbol(std::vector<BinarySymbol>& symbols,
                std::unordered_set<std::uint64_t>& seen_addresses,
                const std::string& name,
                std::uint64_t address,
                std::uint64_t size,
                std::uint8_t info,
                bool replace_existing) {
    if (address == 0) {
        return;
    }
    if (name.empty()) {
        return;
    }

    if (replace_existing) {
        // Check if we already have a symbol at this address
        if (seen_addresses.count(address) > 0) {
            // Find and update the existing symbol
            for (auto& sym : symbols) {
                if (sym.value == address) {
                    // Only replace if the new symbol has more info
                    if (sym.name.empty() || (size > sym.size)) {
                        sym.name = name;
                        if (size > sym.size) {
                            sym.size = size;
                        }
                        if (info != 0 && sym.info == 0) {
                            sym.info = info;
                        }
                    }
                    return;
                }
            }
        }
    } else {
        // Skip if we already have this address
        if (seen_addresses.count(address) > 0) {
            return;
        }
    }

    seen_addresses.insert(address);

    BinarySymbol sym;
    sym.name = name;
    sym.value = address;
    sym.size = size;
    sym.info = info;
    symbols.push_back(std::move(sym));
}

/// Process public symbols from the public symbol stream
std::size_t process_public_symbols(const PDB::RawFile& raw_file,
                                   const PDB::DBIStream& dbi_stream,
                                   const PDB::ImageSectionStream& section_stream,
                                   std::uint64_t image_base,
                                   std::vector<BinarySymbol>& symbols,
                                   std::unordered_set<std::uint64_t>& seen_addresses,
                                   bool replace_existing) {
    if (dbi_stream.HasValidPublicSymbolStream(raw_file) != PDB::ErrorCode::Success) {
        return 0;
    }

    const PDB::PublicSymbolStream public_stream = dbi_stream.CreatePublicSymbolStream(raw_file);
    const PDB::CoalescedMSFStream symbol_record_stream = dbi_stream.CreateSymbolRecordStream(raw_file);

    std::size_t count = 0;
    const auto records = public_stream.GetRecords();
    for (std::size_t i = 0; i < records.GetLength(); ++i) {
        const PDB::HashRecord& hash_record = records[i];
        const PDB::CodeView::DBI::Record* record = public_stream.GetRecord(symbol_record_stream, hash_record);
        if (!record) {
            continue;
        }

        if (record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_PUB32) {
            continue;
        }

        const auto& pub = record->data.S_PUB32;
        const std::uint64_t address = section_offset_to_va(section_stream, pub.section, pub.offset, image_base);
        const std::uint8_t info = is_public_function(pub.flags) ? kSymbolInfoFunc : kSymbolInfoObject;

        add_symbol(symbols, seen_addresses, pub.name, address, 0, info, replace_existing);
        ++count;
    }

    return count;
}

/// Process global symbols from the global symbol stream
std::size_t process_global_symbols(const PDB::RawFile& raw_file,
                                   const PDB::DBIStream& dbi_stream,
                                   const PDB::ImageSectionStream& section_stream,
                                   std::uint64_t image_base,
                                   std::vector<BinarySymbol>& symbols,
                                   std::unordered_set<std::uint64_t>& seen_addresses,
                                   bool replace_existing,
                                   std::size_t& function_count) {
    if (dbi_stream.HasValidGlobalSymbolStream(raw_file) != PDB::ErrorCode::Success) {
        return 0;
    }

    const PDB::GlobalSymbolStream global_stream = dbi_stream.CreateGlobalSymbolStream(raw_file);
    const PDB::CoalescedMSFStream symbol_record_stream = dbi_stream.CreateSymbolRecordStream(raw_file);

    std::size_t count = 0;
    function_count = 0;
    const auto records = global_stream.GetRecords();
    for (std::size_t i = 0; i < records.GetLength(); ++i) {
        const PDB::HashRecord& hash_record = records[i];
        const PDB::CodeView::DBI::Record* record = global_stream.GetRecord(symbol_record_stream, hash_record);
        if (!record) {
            continue;
        }

        const auto kind = record->header.kind;

        if (is_function_record(kind)) {
            // Function symbol (S_GPROC32, S_LPROC32, etc.)
            const auto& proc = record->data.S_GPROC32;
            const std::uint64_t address = section_offset_to_va(section_stream, proc.section, proc.offset, image_base);

            add_symbol(symbols, seen_addresses, proc.name, address, proc.codeSize, kSymbolInfoFunc, replace_existing);
            ++count;
            ++function_count;
        } else if (is_thunk_record(kind)) {
            // Thunk symbol
            const auto& thunk = record->data.S_THUNK32;
            const std::uint64_t address = section_offset_to_va(section_stream, thunk.section, thunk.offset, image_base);

            add_symbol(symbols, seen_addresses, thunk.name, address, thunk.length, kSymbolInfoFunc, replace_existing);
            ++count;
            ++function_count;
        } else if (is_data_record(kind)) {
            // Data symbol (S_GDATA32, S_LDATA32, etc.)
            const auto& data = record->data.S_GDATA32;
            const std::uint64_t address = section_offset_to_va(section_stream, data.section, data.offset, image_base);

            add_symbol(symbols, seen_addresses, data.name, address, 0, kSymbolInfoObject, replace_existing);
            ++count;
        }
    }

    return count;
}

/// Process symbols from module streams
std::size_t process_module_symbols(const PDB::RawFile& raw_file,
                                   const PDB::DBIStream& dbi_stream,
                                   const PDB::ImageSectionStream& section_stream,
                                   std::uint64_t image_base,
                                   std::vector<BinarySymbol>& symbols,
                                   std::unordered_set<std::uint64_t>& seen_addresses,
                                   bool replace_existing,
                                   std::size_t& function_count) {
    const PDB::ModuleInfoStream module_info_stream = dbi_stream.CreateModuleInfoStream(raw_file);

    std::size_t count = 0;
    function_count = 0;

    const auto modules = module_info_stream.GetModules();
    for (std::size_t m = 0; m < modules.GetLength(); ++m) {
        const PDB::ModuleInfoStream::Module& module = modules[m];
        
        if (!module.HasSymbolStream()) {
            continue;
        }

        const PDB::ModuleSymbolStream module_symbol_stream = module.CreateSymbolStream(raw_file);

        module_symbol_stream.ForEachSymbol([&](const PDB::CodeView::DBI::Record* record) {
            const auto kind = record->header.kind;

            if (is_function_record(kind)) {
                const auto& proc = record->data.S_GPROC32;
                const std::uint64_t address = section_offset_to_va(section_stream, proc.section, proc.offset, image_base);

                add_symbol(symbols, seen_addresses, proc.name, address, proc.codeSize, kSymbolInfoFunc, replace_existing);
                ++count;
                ++function_count;
            } else if (is_thunk_record(kind)) {
                const auto& thunk = record->data.S_THUNK32;
                const std::uint64_t address = section_offset_to_va(section_stream, thunk.section, thunk.offset, image_base);

                add_symbol(symbols, seen_addresses, thunk.name, address, thunk.length, kSymbolInfoFunc, replace_existing);
                ++count;
                ++function_count;
            } else if (is_data_record(kind)) {
                const auto& data = record->data.S_GDATA32;
                const std::uint64_t address = section_offset_to_va(section_stream, data.section, data.offset, image_base);

                add_symbol(symbols, seen_addresses, data.name, address, 0, kSymbolInfoObject, replace_existing);
                ++count;
            }
        });
    }

    return count;
}

}  // namespace

PdbLoadResult load_pdb_symbols(const std::string& pdb_path,
                               std::uint64_t image_base,
                               std::vector<BinarySymbol>& symbols,
                               const PdbLoadOptions& options) {
    PdbLoadResult result;

    // Open and memory-map the PDB file
    MappedFile mapped_file;
    std::string open_error;
    if (!mapped_file.open(pdb_path, open_error)) {
        result.error = "failed to open PDB file: " + open_error;
        return result;
    }

    const auto bytes = mapped_file.bytes();
    if (bytes.empty()) {
        result.error = "PDB file is empty";
        return result;
    }

    // Validate the PDB file
    const PDB::ErrorCode validate_error = PDB::ValidateFile(bytes.data(), bytes.size());
    if (validate_error != PDB::ErrorCode::Success) {
        result.error = "invalid PDB file (error code " + std::to_string(static_cast<int>(validate_error)) + ")";
        return result;
    }

    // Create the raw file handle
    const PDB::RawFile raw_file = PDB::CreateRawFile(bytes.data());

    // Check for valid DBI stream
    if (PDB::HasValidDBIStream(raw_file) != PDB::ErrorCode::Success) {
        result.error = "PDB has no valid DBI stream";
        return result;
    }

    // Create the DBI stream
    const PDB::DBIStream dbi_stream = PDB::CreateDBIStream(raw_file);

    // Check for valid image section stream
    if (dbi_stream.HasValidImageSectionStream(raw_file) != PDB::ErrorCode::Success) {
        result.error = "PDB has no valid image section stream";
        return result;
    }

    // Create the image section stream for RVA conversion
    const PDB::ImageSectionStream section_stream = dbi_stream.CreateImageSectionStream(raw_file);

    // Track seen addresses to avoid duplicates
    std::unordered_set<std::uint64_t> seen_addresses;

    // Reserve space for existing symbols
    for (const auto& sym : symbols) {
        if (sym.value != 0) {
            seen_addresses.insert(sym.value);
        }
    }

    // Process public symbols
    if (options.load_public_symbols) {
        result.public_symbols = process_public_symbols(raw_file, dbi_stream, section_stream,
                                                       image_base, symbols, seen_addresses,
                                                       options.replace_existing);
    }

    // Process global symbols
    if (options.load_global_symbols) {
        std::size_t func_count = 0;
        result.global_symbols = process_global_symbols(raw_file, dbi_stream, section_stream,
                                                       image_base, symbols, seen_addresses,
                                                       options.replace_existing, func_count);
        result.function_symbols += func_count;
    }

    // Process module symbols
    if (options.load_module_symbols) {
        std::size_t func_count = 0;
        result.module_symbols = process_module_symbols(raw_file, dbi_stream, section_stream,
                                                       image_base, symbols, seen_addresses,
                                                       options.replace_existing, func_count);
        result.function_symbols += func_count;
    }

    result.success = true;
    return result;
}

bool find_pdb_for_pe(const std::string& pe_path, std::string& pdb_path) {
    namespace fs = std::filesystem;

    // Strategy 1: Same directory, same name with .pdb extension
    const fs::path pe_fs_path(pe_path);
    fs::path candidate = pe_fs_path;
    candidate.replace_extension(".pdb");

    if (fs::exists(candidate) && fs::is_regular_file(candidate)) {
        pdb_path = candidate.string();
        return true;
    }

    // Strategy 2: Same directory, lowercase .pdb extension
    candidate = pe_fs_path.parent_path() / (pe_fs_path.stem().string() + ".pdb");
    if (fs::exists(candidate) && fs::is_regular_file(candidate)) {
        pdb_path = candidate.string();
        return true;
    }

    // Strategy 3: Same directory, uppercase .PDB extension
    candidate = pe_fs_path.parent_path() / (pe_fs_path.stem().string() + ".PDB");
    if (fs::exists(candidate) && fs::is_regular_file(candidate)) {
        pdb_path = candidate.string();
        return true;
    }

    return false;
}

bool is_valid_pdb(const std::string& path) {
    MappedFile mapped_file;
    std::string error;
    if (!mapped_file.open(path, error)) {
        return false;
    }

    const auto bytes = mapped_file.bytes();
    if (bytes.empty()) {
        return false;
    }

    return PDB::ValidateFile(bytes.data(), bytes.size()) == PDB::ErrorCode::Success;
}

}  // namespace engine
