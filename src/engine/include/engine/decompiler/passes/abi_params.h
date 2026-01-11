#pragma once

#include <vector>

#include "engine/decompiler/types/type_system.h"
#include "engine/mlil.h"
#include <functional>

namespace engine::decompiler::passes {

struct ParamInfo {
    types::SsaVarKey key;
    int index = -1;
};

using ParamCountProvider = std::function<int(std::uint64_t)>;

std::vector<ParamInfo> collect_abi_params(const mlil::Function& function);
std::string infer_return_type(const mlil::Function& function);
void prune_call_args(mlil::Function& function, ParamCountProvider provider = nullptr);

}  // namespace engine::decompiler::passes
