#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "engine/decompiler.h"
#include "engine/decompiler/passes/abi_params.h"
#include "engine/decompiler/passes/ssa_groups.h"
#include "engine/decompiler/types/type_solver.h"
#include "engine/hlil.h"
#include "engine/mlil.h"

namespace engine::decompiler::passes {

struct NamingResult {
    std::unordered_map<types::SsaVarKey, std::string, types::SsaVarKeyHash, types::SsaVarKeyEq> names;
    std::vector<VarDecl> params;
    std::vector<VarDecl> locals;
    std::unordered_set<std::string> implicit_names;
};

NamingResult build_naming(const mlil::Function& function,
                          const hlil::Function& hlil_ssa,
                          const types::TypeSolver& solver,
                          const SsaGroups& groups,
                          const std::vector<ParamInfo>& params,
                          const std::vector<VarDecl>* param_hints);

}  // namespace engine::decompiler::passes
