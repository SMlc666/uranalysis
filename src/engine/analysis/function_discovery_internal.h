#pragma once

#include <cstdint>
#include <vector>

#include "engine/binary_format.h"
#include "engine/image.h"
#include "engine/eh_frame.h"
#include "engine/llir.h"
#include "engine/dwarf.h"

namespace engine::analysis::detail {

void collect_symbol_entry_points(const std::vector<BinarySymbol>& symbols,
                                 const BinaryInfo* binary_info,
                                 std::vector<std::uint64_t>& out);
void collect_tailcall_entry_points(const llir::Function& function, std::vector<std::uint64_t>& out);
void collect_plt_entry_points(const std::vector<BinarySection>& sections,
                              const std::vector<BinarySegment>* segments,
                              const std::vector<BinaryRelocation>* relocations,
                              std::vector<std::uint64_t>& out);
void collect_init_array_entry_points(const LoadedImage& image,
                                     const std::vector<BinarySection>& sections,
                                     const std::vector<BinarySegment>* segments,
                                     const BinaryInfo* binary_info,
                                     std::vector<std::uint64_t>& out);
void collect_eh_frame_entry_points(const ehframe::EhFrameCatalog& catalog,
                                   const std::vector<BinarySegment>* segments,
                                   std::vector<std::uint64_t>& out);
void collect_dwarf_entry_points(const dwarf::DwarfCatalog& catalog, std::vector<std::uint64_t>& out);
void collect_linear_sweep_entry_points(const LoadedImage& image,
                                       const std::vector<BinarySection>& sections,
                                       const std::vector<BinarySegment>* segments,
                                       const dwarf::DwarfCatalog* dwarf,
                                       const ehframe::EhFrameCatalog* eh_frame,
                                       std::vector<std::uint64_t>& out);

}  // namespace engine::analysis::detail
