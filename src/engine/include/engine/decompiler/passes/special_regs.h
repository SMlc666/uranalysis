#pragma once

#include "engine/mlil.h"

namespace engine::decompiler::passes {

void rewrite_special_registers(mlil::Function& function);

}  // namespace engine::decompiler::passes
