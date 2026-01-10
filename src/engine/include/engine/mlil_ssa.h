#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "engine/mlil.h"

namespace engine::mlil {

struct MlilDefUse {
    std::vector<VarRef> uses;
    std::vector<VarRef> defs;
};

struct MlilDefUseSite {
    std::size_t block_index = 0;
    std::size_t inst_index = 0;
    std::size_t stmt_index = 0;
    bool is_phi = false;
};

struct VarRefKey {
    std::string name;
    int version = -1;
};

struct VarRefKeyHash {
    std::size_t operator()(const VarRefKey& key) const;
};

struct VarRefKeyEq {
    bool operator()(const VarRefKey& a, const VarRefKey& b) const;
};

struct MlilSsaDefUse {
    std::unordered_map<VarRefKey, MlilDefUseSite, VarRefKeyHash, VarRefKeyEq> defs;
    std::unordered_map<VarRefKey, std::vector<MlilDefUseSite>, VarRefKeyHash, VarRefKeyEq> uses;
};

MlilDefUse compute_def_use(const MlilStmt& stmt);
void compute_def_use(const MlilStmt& stmt, std::vector<VarRef>& uses, std::vector<VarRef>& defs);
bool build_ssa_def_use(const Function& function, MlilSsaDefUse& out, std::string& error);

bool build_ssa(Function& function, std::string& error);
bool build_ssa_with_call_clobbers(Function& function,
                                  const std::vector<VarRef>& call_clobbers,
                                  std::string& error);

}  // namespace engine::mlil
