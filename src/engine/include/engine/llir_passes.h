#pragma once

#include <string>

#include "engine/llir.h"

namespace engine::llir {

bool lift_stack_vars(Function& function, std::string& error);
bool resolve_indirect_branches(Function& function, std::string& error);

}  // namespace engine::llir
