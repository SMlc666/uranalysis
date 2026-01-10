#pragma once

#include "engine/decompiler/types/type_solver.h"
#include "engine/mlil.h"

namespace engine::decompiler::types {

void collect_constraints_mlil(const mlil::Function& function, TypeSolver& solver);

}  // namespace engine::decompiler::types
