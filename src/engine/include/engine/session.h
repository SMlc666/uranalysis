#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "engine/disasm.h"
#include "engine/dwarf.h"
#include "engine/eh_frame.h"
#include "engine/binary_loader.h"
#include "engine/function_boundaries.h"
#include "engine/function_discovery.h"
#include "engine/llir.h"
#include "engine/mlil.h"
#include "engine/llir_ssa.h"
#include "engine/mlil_ssa.h"
#include "engine/mlil_opt.h"
#include "engine/hlil.h"
#include "engine/hlil_lift.h"
#include "engine/rtti.h"
#include "engine/symbols.h"
#include "engine/strings.h"
#include "engine/xrefs.h"
#include "engine/pdb_loader.h"

namespace engine {

class Session {
public:
    bool open(const std::string& path, std::string& error);
    void close();

    bool loaded() const;
    const std::string& path() const;
    const BinaryInfo& binary_info() const;
    const std::vector<BinarySegment>& segments() const;
    const std::vector<BinarySection>& sections() const;
    const std::vector<BinarySymbol>& symbols() const;
    const std::vector<BinaryRelocation>& relocations() const;
    const symbols::SymbolTable& symbol_table() const;
    const rtti::RttiCatalog& rtti_catalog() const;
    const dwarf::DwarfCatalog& dwarf_catalog() const;
    const ehframe::EhFrameCatalog& eh_frame_catalog() const;
    const strings::StringCatalog& string_catalog() const;
    bool find_xrefs_to_address(std::uint64_t target,
                               std::size_t max_results,
                               std::vector<xrefs::XrefEntry>& out) const;
    const LoadedImage& image() const;

    /// Load symbols from a PDB file
    /// @param pdb_path Path to the PDB file
    /// @param options Loading options
    /// @return Result containing statistics and any error message
    PdbLoadResult load_pdb(const std::string& pdb_path, const PdbLoadOptions& options = {});

    /// Check if PDB symbols have been loaded
    bool has_pdb_symbols() const;

    /// Get the path to the loaded PDB file (empty if none)
    const std::string& pdb_path() const;

    std::uint64_t cursor() const;
    void set_cursor(std::uint64_t addr);

    bool disasm_arm64(std::uint64_t start,
                      std::size_t max_bytes,
                      std::size_t max_instructions,
                      std::vector<DisasmLine>& out,
                      std::string& error) const;
    bool disasm_x86_64(std::uint64_t start,
                       std::size_t max_bytes,
                       std::size_t max_instructions,
                       std::vector<DisasmLine>& out,
                       std::string& error) const;

    bool build_llir_cfg_arm64(std::uint64_t entry,
                              std::size_t max_instructions,
                              llir::Function& function,
                              std::string& error) const;
    bool build_llir_cfg_x86_64(std::uint64_t entry,
                               std::size_t max_instructions,
                               llir::Function& function,
                               std::string& error) const;

    bool build_llir_ssa_arm64(std::uint64_t entry,
                              std::size_t max_instructions,
                              llir::Function& function,
                              std::string& error) const;

    bool build_mlil_ssa_arm64(std::uint64_t entry,
                              std::size_t max_instructions,
                              mlil::Function& function,
                              std::string& error) const;

    bool build_hlil_arm64(std::uint64_t entry,
                          std::size_t max_instructions,
                          hlil::Function& function,
                          std::string& error) const;
    bool build_llir_ssa_x86_64(std::uint64_t entry,
                               std::size_t max_instructions,
                               llir::Function& function,
                               std::string& error) const;

    bool build_mlil_ssa_x86_64(std::uint64_t entry,
                               std::size_t max_instructions,
                               mlil::Function& function,
                               std::string& error) const;

    bool build_hlil_x86_64(std::uint64_t entry,
                           std::size_t max_instructions,
                           hlil::Function& function,
                           std::string& error) const;

    bool discover_llir_functions_arm64(std::uint64_t entry,
                                       std::size_t max_instructions_per_function,
                                       const analysis::FunctionDiscoveryOptions& options,
                                       std::vector<llir::Function>& functions,
                                       std::string& error) const;
    bool discover_llir_functions_x86_64(std::uint64_t entry,
                                        std::size_t max_instructions_per_function,
                                        const analysis::FunctionDiscoveryOptions& options,
                                        std::vector<llir::Function>& functions,
                                        std::string& error) const;

    bool discover_function_ranges_arm64(std::uint64_t entry,
                                        std::size_t max_instructions_per_function,
                                        const analysis::FunctionDiscoveryOptions& options,
                                        std::vector<analysis::FunctionRange>& ranges,
                                        std::string& error) const;
    bool discover_function_ranges_x86_64(std::uint64_t entry,
                                         std::size_t max_instructions_per_function,
                                         const analysis::FunctionDiscoveryOptions& options,
                                         std::vector<analysis::FunctionRange>& ranges,
                                         std::string& error) const;

private:
    void apply_relocations();
    void try_load_pdb();

    bool loaded_ = false;
    std::string path_;
    std::string pdb_path_;
    bool has_pdb_symbols_ = false;
    BinaryInfo binary_info_;
    std::vector<BinarySegment> segments_;
    std::vector<BinarySection> sections_;
    std::vector<BinarySymbol> symbols_;
    std::vector<BinaryRelocation> relocations_;
    symbols::SymbolTable symbol_table_;
    rtti::RttiCatalog rtti_catalog_;
    dwarf::DwarfCatalog dwarf_catalog_;
    ehframe::EhFrameCatalog eh_frame_catalog_;
    strings::StringCatalog string_catalog_;
    LoadedImage image_;
    std::uint64_t cursor_ = 0;
};

}  // namespace engine
