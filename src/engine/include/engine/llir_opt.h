#pragma once

#include <string>

#include "engine/llir.h"

namespace engine::llir {

struct LlilOptOptions {
    bool fold_constants = true;
    bool copy_propagation = true;
    bool dead_code_elim = true;
    bool inline_flag_exprs = true;
};

bool optimize_llil_ssa(Function& function, const LlilOptOptions& options, std::string& error);

}  // namespace engine::llir
