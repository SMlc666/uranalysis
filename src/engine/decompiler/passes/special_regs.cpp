#include "engine/decompiler/passes/special_regs.h"

namespace engine::decompiler::passes {

namespace {

bool is_zero_reg(const std::string& name) {
    return name == "reg.xzr" || name == "reg.wzr" || name == "xzr" || name == "wzr";
}

void rewrite_expr(mlil::MlilExpr& expr) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        if (is_zero_reg(expr.var.name)) {
            expr.kind = mlil::MlilExprKind::kImm;
            expr.imm = 0;
            expr.var = {};
            expr.args.clear();
            expr.size = expr.size != 0 ? expr.size : 8;
            return;
        }
    }
    for (auto& arg : expr.args) {
        rewrite_expr(arg);
    }
}

void rewrite_stmt(mlil::MlilStmt& stmt) {
    if (stmt.kind == mlil::MlilStmtKind::kAssign && is_zero_reg(stmt.var.name)) {
        stmt.kind = mlil::MlilStmtKind::kNop;
        stmt.comment = "drop zero reg assign";
        return;
    }
    rewrite_expr(stmt.expr);
    rewrite_expr(stmt.target);
    rewrite_expr(stmt.condition);
    for (auto& arg : stmt.args) {
        rewrite_expr(arg);
    }
}

}  // namespace

void rewrite_special_registers(mlil::Function& function) {
    for (auto& block : function.blocks) {
        for (auto& phi : block.phis) {
            rewrite_stmt(phi);
        }
        for (auto& inst : block.instructions) {
            for (auto& stmt : inst.stmts) {
                rewrite_stmt(stmt);
            }
        }
    }
}

}  // namespace engine::decompiler::passes
