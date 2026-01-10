#pragma once

#include <string>

#include "engine/mlil.h"

namespace engine::decompiler::passes {

void split_critical_edges(mlil::Function& function);
bool lower_mlil_ssa(mlil::Function& function, std::string& error);

}  // namespace engine::decompiler::passes
