#pragma once

#include "engine/decompiler.h"

namespace engine::decompiler::passes {

// Constant Propagation Pass
// Propagates constant values through variables to simplify expressions and control flow.
// Handles integer constants and simple arithmetic.
void propagate_constants(Function& function);

} // namespace engine::decompiler::passes
