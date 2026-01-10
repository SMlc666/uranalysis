#pragma once

#include <vector>

#include "engine/decompiler/types/type_system.h"
#include "engine/mlil.h"

namespace engine::decompiler::passes {

struct ParamInfo {
    types::SsaVarKey key;
    int index = -1;
};

std::vector<ParamInfo> collect_abi_params(const mlil::Function& function);
std::string infer_return_type(const mlil::Function& function);
void prune_call_args(mlil::Function& function);

}  // namespace engine::decompiler::passes
