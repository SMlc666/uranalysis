#pragma once

#include <string>
#include <vector>

#include "engine/llir.h"
#include "engine/binary_loader.h"

namespace engine::llir {

bool lift_stack_vars(Function& function, std::string& error);
bool resolve_indirect_branches(Function& function, std::string& error);
bool resolve_jump_tables(Function& function,
                         const LoadedImage& image,
                         const std::vector<BinarySegment>& segments,
                         std::string& error);

}  // namespace engine::llir
