#pragma once

#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "engine/decompiler/types/type_system.h"
#include "engine/mlil.h"

namespace engine::decompiler::passes {

struct SsaGroups {
    std::unordered_map<types::SsaVarKey, std::size_t, types::SsaVarKeyHash, types::SsaVarKeyEq> group_of;
    std::unordered_map<std::size_t, std::vector<types::SsaVarKey>> members;
};

SsaGroups build_phi_groups(const mlil::Function& function);

}  // namespace engine::decompiler::passes
