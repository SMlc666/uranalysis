#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "engine/binary_format.h"
#include "engine/eh_frame.h"
#include "engine/llir.h"
#include "engine/dwarf.h"

namespace engine::analysis {

enum class SeedKind {
    kEntry = 0,
    kManual = 1,
    kSymbol = 2,
    kPlt = 3,
    kInitArray = 4,
    kEhFrame = 5,
    kPrologue = 6,
    kDwarf = 7,
    kLinearSweep = 8
};

struct SeedEntry {
    std::uint64_t address = 0;
    SeedKind kind = SeedKind::kEntry;
};

struct FunctionDiscoveryOptions {
    std::vector<std::uint64_t> entry_points;
    bool follow_calls = true;
    bool follow_tail_jumps = true;
    bool include_indirect_targets = true;
    bool include_symbol_entries = true;
    bool include_plt_entries = true;
    bool include_init_array_entries = true;
    bool include_eh_frame_entries = true;
    bool include_prologue_entries = true;
    bool include_dwarf_entries = true;
    bool include_linear_sweep_entries = false;
    const std::vector<BinarySymbol>* symbols = nullptr;
    const std::vector<BinarySection>* sections = nullptr;
    const std::vector<BinarySegment>* segments = nullptr;
    const std::vector<BinaryRelocation>* relocations = nullptr;
    const BinaryInfo* binary_info = nullptr;
    const ehframe::EhFrameCatalog* eh_frame = nullptr;
    const dwarf::DwarfCatalog* dwarf = nullptr;
};

bool discover_functions_arm64(const LoadedImage& image,
                              std::uint64_t entry,
                              std::size_t max_instructions_per_function,
                              const FunctionDiscoveryOptions& options,
                              std::vector<llir::Function>& functions,
                              std::string& error);

bool discover_functions_x86_64(const LoadedImage& image,
                               std::uint64_t entry,
                               std::size_t max_instructions_per_function,
                               const FunctionDiscoveryOptions& options,
                               std::vector<llir::Function>& functions,
                               std::string& error);

void collect_seed_entries(const LoadedImage& image,
                          std::uint64_t entry,
                          const FunctionDiscoveryOptions& options,
                          std::vector<SeedEntry>& out);

}  // namespace engine::analysis
