#include "engine/decompiler/passes/ssa_groups.h"

#include <string>
#include <unordered_map>

#include "engine/mlil_ssa.h"

namespace engine::decompiler::passes {

namespace {

using types::SsaVarKey;

bool param_index_for_name(const std::string& name, int& index) {
    static const std::unordered_map<std::string, int> kAarch64 = {
        {"reg.x0", 0}, {"reg.x1", 1}, {"reg.x2", 2}, {"reg.x3", 3},
        {"reg.x4", 4}, {"reg.x5", 5}, {"reg.x6", 6}, {"reg.x7", 7},
        {"reg.w0", 0}, {"reg.w1", 1}, {"reg.w2", 2}, {"reg.w3", 3},
        {"reg.w4", 4}, {"reg.w5", 5}, {"reg.w6", 6}, {"reg.w7", 7},
        {"x0", 0}, {"x1", 1}, {"x2", 2}, {"x3", 3},
        {"x4", 4}, {"x5", 5}, {"x6", 6}, {"x7", 7},
        {"w0", 0}, {"w1", 1}, {"w2", 2}, {"w3", 3},
        {"w4", 4}, {"w5", 5}, {"w6", 6}, {"w7", 7},
    };
    static const std::unordered_map<std::string, int> kSysV = {
        {"reg.rdi", 0}, {"reg.rsi", 1}, {"reg.rdx", 2}, {"reg.rcx", 3},
        {"reg.r8", 4}, {"reg.r9", 5},
        {"rdi", 0}, {"rsi", 1}, {"rdx", 2}, {"rcx", 3},
        {"r8", 4}, {"r9", 5},
    };
    static const std::unordered_map<std::string, int> kWin64 = {
        {"reg.rcx", 0}, {"reg.rdx", 1}, {"reg.r8", 2}, {"reg.r9", 3},
        {"rcx", 0}, {"rdx", 1}, {"r8", 2}, {"r9", 3},
    };

    auto it = kAarch64.find(name);
    if (it != kAarch64.end()) {
        index = it->second;
        return true;
    }
    it = kSysV.find(name);
    if (it != kSysV.end()) {
        index = it->second;
        return true;
    }
    it = kWin64.find(name);
    if (it != kWin64.end()) {
        index = it->second;
        return true;
    }
    return false;
}

SsaVarKey make_key(const mlil::VarRef& var) {
    SsaVarKey key;
    key.name = var.name;
    key.version = var.version;
    return key;
}

struct UnionFind {
    std::unordered_map<SsaVarKey, std::size_t, types::SsaVarKeyHash, types::SsaVarKeyEq> index;
    std::vector<std::size_t> parent;
    std::vector<std::size_t> rank;

    std::size_t ensure(const SsaVarKey& key) {
        auto it = index.find(key);
        if (it != index.end()) {
            return it->second;
        }
        std::size_t idx = parent.size();
        index.emplace(key, idx);
        parent.push_back(idx);
        rank.push_back(0);
        return idx;
    }

    std::size_t find(std::size_t idx) {
        if (parent[idx] == idx) {
            return idx;
        }
        parent[idx] = find(parent[idx]);
        return parent[idx];
    }

    void unite(std::size_t a, std::size_t b) {
        a = find(a);
        b = find(b);
        if (a == b) {
            return;
        }
        if (rank[a] < rank[b]) {
            std::swap(a, b);
        }
        parent[b] = a;
        if (rank[a] == rank[b]) {
            ++rank[a];
        }
    }
};

void add_var(const mlil::VarRef& var, UnionFind& uf) {
    if (var.name.empty()) {
        return;
    }
    uf.ensure(make_key(var));
}

void add_expr_vars(const mlil::MlilExpr& expr, UnionFind& uf) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        add_var(expr.var, uf);
    }
    for (const auto& arg : expr.args) {
        add_expr_vars(arg, uf);
    }
}

}  // namespace

SsaGroups build_phi_groups(const mlil::Function& function) {
    UnionFind uf;
    mlil::MlilSsaDefUse def_use;
    std::string def_use_error;
    const bool have_def_use = mlil::build_ssa_def_use(function, def_use, def_use_error);
    for (const auto& block : function.blocks) {
        for (const auto& phi : block.phis) {
            if (phi.kind != mlil::MlilStmtKind::kPhi) {
                continue;
            }
            add_var(phi.var, uf);
            bool phi_used = true;
            if (have_def_use) {
                mlil::VarRefKey key;
                key.name = phi.var.name;
                key.version = phi.var.version;
                phi_used = def_use.uses.find(key) != def_use.uses.end();
            }
            int primary_param = -1;
            bool multi_param = false;
            if (phi_used) {
                int idx = -1;
                if (param_index_for_name(phi.var.name, idx)) {
                    primary_param = idx;
                }
                for (const auto& arg : phi.expr.args) {
                    if (arg.kind != mlil::MlilExprKind::kVar) {
                        continue;
                    }
                    int arg_idx = -1;
                    if (!param_index_for_name(arg.var.name, arg_idx)) {
                        continue;
                    }
                    if (primary_param == -1) {
                        primary_param = arg_idx;
                    } else if (arg_idx != primary_param) {
                        multi_param = true;
                        break;
                    }
                }
            }
            const std::size_t phi_idx = uf.ensure(make_key(phi.var));
            for (const auto& arg : phi.expr.args) {
                if (arg.kind != mlil::MlilExprKind::kVar) {
                    continue;
                }
                add_var(arg.var, uf);
                const std::size_t arg_idx = uf.ensure(make_key(arg.var));
                if (phi_used && !multi_param) {
                    uf.unite(phi_idx, arg_idx);
                }
            }
        }
        for (const auto& inst : block.instructions) {
            for (const auto& stmt : inst.stmts) {
                add_var(stmt.var, uf);
                for (const auto& ret : stmt.returns) {
                    add_var(ret, uf);
                }
                add_expr_vars(stmt.expr, uf);
                add_expr_vars(stmt.target, uf);
                add_expr_vars(stmt.condition, uf);
                for (const auto& arg : stmt.args) {
                    add_expr_vars(arg, uf);
                }

                // Coalesce copies
                if (stmt.kind == mlil::MlilStmtKind::kAssign && stmt.expr.kind == mlil::MlilExprKind::kVar) {
                    if (stmt.var.size == stmt.expr.var.size) {
                        // Only coalesce if sizes match to avoid confusion
                        uf.unite(uf.ensure(make_key(stmt.var)), uf.ensure(make_key(stmt.expr.var)));
                    }
                }
            }
        }
    }

    SsaGroups groups;
    for (const auto& [key, idx] : uf.index) {
        const std::size_t root = uf.find(idx);
        groups.group_of.emplace(key, root);
        groups.members[root].push_back(key);
    }
    return groups;
}

}  // namespace engine::decompiler::passes
