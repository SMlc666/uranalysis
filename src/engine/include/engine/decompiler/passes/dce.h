#pragma once

#include "engine/decompiler.h"

namespace engine::decompiler::passes {

// Dead Code Elimination Pass
// Removes assignments to unused variables and NOP instructions.
// Preserves calls, volatile accesses, and memory stores.
void eliminate_dead_code(Function& function);

} // namespace engine::decompiler::passes
