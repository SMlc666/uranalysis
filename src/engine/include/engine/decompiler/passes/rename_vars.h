#pragma once

#include <unordered_map>

#include "engine/decompiler/types/type_system.h"
#include "engine/mlil.h"

namespace engine::decompiler::passes {

void rename_vars(mlil::Function& function,
                 const std::unordered_map<types::SsaVarKey, std::string, types::SsaVarKeyHash, types::SsaVarKeyEq>& names);

}  // namespace engine::decompiler::passes
