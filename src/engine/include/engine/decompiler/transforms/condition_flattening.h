#pragma once

#include "engine/decompiler.h"

namespace engine::decompiler::transforms {

// Condition Flattening Pass
// Flattens nested if statements that should be && or ||.
// Simplifies complex boolean logic.
void flatten_conditions(Function& function);

} // namespace engine::decompiler::transforms
