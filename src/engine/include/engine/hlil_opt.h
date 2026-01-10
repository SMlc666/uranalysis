#pragma once

#include "engine/hlil.h"

#include <string>

namespace engine::hlil {

struct HlilOptOptions {
    bool simplify_control_flow = true;
    bool propagate_expressions = true;
    bool eliminate_dead_code = true;
};

// Performs high-level optimizations on the structured HLIL AST.
bool optimize_hlil(Function& function, const HlilOptOptions& options, std::string& error);

}  // namespace engine::hlil
