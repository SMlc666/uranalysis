#pragma once

#include <string>

#include "engine/llir.h"
#include "engine/mlil.h"

namespace engine::mlil {

bool build_mlil_from_llil_ssa(const llir::Function& llil_function,
                              Function& mlil_function,
                              std::string& error);

}  // namespace engine::mlil
