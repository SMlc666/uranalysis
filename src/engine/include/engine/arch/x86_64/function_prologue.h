#pragma once

#include <cstdint>
#include <vector>

#include "engine/binary_format.h"
#include "engine/image.h"

namespace engine::arch::x86_64 {

void collect_prologue_entry_points(const LoadedImage& image,
                                   const std::vector<BinarySection>& sections,
                                   const std::vector<BinarySegment>* segments,
                                   std::vector<std::uint64_t>& out);

}  // namespace engine::arch::x86_64
