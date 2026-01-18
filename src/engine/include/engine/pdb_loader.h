#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "engine/binary_format.h"

namespace engine {

/// Result of PDB symbol loading
struct PdbLoadResult {
    bool success = false;
    std::size_t public_symbols = 0;
    std::size_t global_symbols = 0;
    std::size_t function_symbols = 0;
    std::size_t module_symbols = 0;
    std::string error;
};

/// Options for PDB loading
struct PdbLoadOptions {
    bool load_public_symbols = true;
    bool load_global_symbols = true;
    bool load_function_symbols = true;
    bool load_module_symbols = true;
    /// If true, existing symbols with the same address are replaced
    bool replace_existing = true;
};

/// Load symbols from a PDB file into a symbol vector.
/// @param pdb_path Path to the PDB file
/// @param image_base Image base address of the PE file
/// @param symbols Output vector to append symbols to
/// @param options Loading options
/// @return Result containing statistics and any error message
PdbLoadResult load_pdb_symbols(const std::string& pdb_path,
                               std::uint64_t image_base,
                               std::vector<BinarySymbol>& symbols,
                               const PdbLoadOptions& options = {});

/// Try to find a PDB file corresponding to a PE file.
/// Searches for:
/// 1. Same directory as PE with .pdb extension
/// 2. Path embedded in PE debug directory (if available)
/// @param pe_path Path to the PE file
/// @param pdb_path Output path if found
/// @return true if a PDB file was found
bool find_pdb_for_pe(const std::string& pe_path, std::string& pdb_path);

/// Check if a file is a valid PDB file
/// @param path Path to the file
/// @return true if the file is a valid PDB
bool is_valid_pdb(const std::string& path);

}  // namespace engine
