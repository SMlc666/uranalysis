#include "engine/decompiler/passes/rename_vars.h"

namespace engine::decompiler::passes {

namespace {

using types::SsaVarKey;

void rename_var(mlil::VarRef& var,
                const std::unordered_map<SsaVarKey, std::string, types::SsaVarKeyHash, types::SsaVarKeyEq>& names) {
    if (var.name.empty()) {
        return;
    }
    SsaVarKey key{var.name, var.version};
    auto it = names.find(key);
    if (it != names.end()) {
        var.name = it->second;
    }
}

void rename_expr(mlil::MlilExpr& expr,
                 const std::unordered_map<SsaVarKey, std::string, types::SsaVarKeyHash, types::SsaVarKeyEq>& names) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        rename_var(expr.var, names);
    }
    for (auto& arg : expr.args) {
        rename_expr(arg, names);
    }
}

void rename_stmt(mlil::MlilStmt& stmt,
                 const std::unordered_map<SsaVarKey, std::string, types::SsaVarKeyHash, types::SsaVarKeyEq>& names) {
    rename_var(stmt.var, names);
    for (auto& ret : stmt.returns) {
        rename_var(ret, names);
    }
    rename_expr(stmt.expr, names);
    rename_expr(stmt.target, names);
    rename_expr(stmt.condition, names);
    for (auto& arg : stmt.args) {
        rename_expr(arg, names);
    }
}

}  // namespace

void rename_vars(mlil::Function& function,
                 const std::unordered_map<SsaVarKey, std::string, types::SsaVarKeyHash, types::SsaVarKeyEq>& names) {
    for (auto& block : function.blocks) {
        for (auto& phi : block.phis) {
            rename_stmt(phi, names);
        }
        for (auto& inst : block.instructions) {
            for (auto& stmt : inst.stmts) {
                rename_stmt(stmt, names);
            }
        }
    }
}

}  // namespace engine::decompiler::passes
