#pragma once

#include <string>

#include "engine/mlil.h"

namespace engine::mlil {

struct MlilOptOptions {
    bool fold_constants = true;
    bool copy_propagation = true;
    bool dead_code_elim = true;
};

bool optimize_mlil_ssa(Function& function, const MlilOptOptions& options, std::string& error);

}  // namespace engine::mlil
