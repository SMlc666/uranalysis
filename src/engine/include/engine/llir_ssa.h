#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "engine/llir.h"

namespace engine::llir {

struct LlilDefUse {
    std::vector<RegRef> uses;
    std::vector<RegRef> defs;
};

struct LlilDefUseSite {
    std::size_t block_index = 0;
    std::size_t inst_index = 0;
    std::size_t stmt_index = 0;
    bool is_phi = false;
};

struct RegRefKey {
    std::string name;
    int version = -1;
};

struct RegRefKeyHash {
    std::size_t operator()(const RegRefKey& key) const;
};

struct RegRefKeyEq {
    bool operator()(const RegRefKey& a, const RegRefKey& b) const;
};

struct LlilSsaDefUse {
    std::unordered_map<RegRefKey, LlilDefUseSite, RegRefKeyHash, RegRefKeyEq> defs;
    std::unordered_map<RegRefKey, std::vector<LlilDefUseSite>, RegRefKeyHash, RegRefKeyEq> uses;
};

LlilDefUse compute_def_use(const LlilStmt& stmt);
void compute_def_use(const LlilStmt& stmt, std::vector<RegRef>& uses, std::vector<RegRef>& defs);
bool build_ssa_def_use(const Function& function, LlilSsaDefUse& out, std::string& error);

bool build_ssa(Function& function, std::string& error);
bool build_ssa_with_call_clobbers(Function& function,
                                  const std::vector<RegRef>& call_clobbers,
                                  std::string& error);

}  // namespace engine::llir
