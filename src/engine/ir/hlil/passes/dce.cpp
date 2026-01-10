#include "dce.h"
#include <algorithm>

namespace engine::hlil::passes {

using Expr = mlil::MlilExpr;

bool DeadCodeEliminator::run(Function& function) {
    std::unordered_map<std::string, int> counts;
    count_usages(function.stmts, counts);
    
    bool modified = false;
    eliminate(function.stmts, counts, modified);
    return modified;
}

void DeadCodeEliminator::count_usages(const std::vector<HlilStmt>& stmts, std::unordered_map<std::string, int>& counts) {
    for (const auto& stmt : stmts) {
        auto visit_expr = [&](const Expr& e) {
            auto recursive = [&](const Expr& sub, auto& self) -> void {
                if (sub.kind == mlil::MlilExprKind::kVar) {
                    counts[sub.var.name]++;
                }
                for (const auto& arg : sub.args) self(arg, self);
            };
            recursive(e, recursive);
        };

        switch (stmt.kind) {
            case HlilStmtKind::kAssign: visit_expr(stmt.expr); break;
            case HlilStmtKind::kStore: visit_expr(stmt.target); visit_expr(stmt.expr); break;
            case HlilStmtKind::kCall:
                visit_expr(stmt.target);
                for (const auto& a : stmt.args) visit_expr(a);
                break;
            case HlilStmtKind::kRet: visit_expr(stmt.expr); break;
            case HlilStmtKind::kIf:
                visit_expr(stmt.condition);
                count_usages(stmt.then_body, counts);
                count_usages(stmt.else_body, counts);
                break;
            case HlilStmtKind::kWhile:
            case HlilStmtKind::kFor:
                visit_expr(stmt.condition);
                count_usages(stmt.body, counts);
                count_usages(stmt.then_body, counts);
                count_usages(stmt.else_body, counts);
                break;
            default: break;
        }
    }
}

void DeadCodeEliminator::eliminate(std::vector<HlilStmt>& stmts, const std::unordered_map<std::string, int>& counts, bool& modified) {
    for (auto& stmt : stmts) {
        if (stmt.kind == HlilStmtKind::kAssign) {
            auto it = counts.find(stmt.var.name);

            if (it == counts.end() || it->second <= 0) {

                stmt.kind = HlilStmtKind::kNop;
                modified = true;
            }
        } else if (stmt.kind == HlilStmtKind::kIf) {
            eliminate(stmt.then_body, counts, modified);
            eliminate(stmt.else_body, counts, modified);
        } else if (stmt.kind == HlilStmtKind::kWhile || stmt.kind == HlilStmtKind::kFor) {
            eliminate(stmt.body, counts, modified);
            eliminate(stmt.then_body, counts, modified);
            eliminate(stmt.else_body, counts, modified);
        }
    }
    
    // Cleanup Nops
    auto it = std::remove_if(stmts.begin(), stmts.end(), [](const HlilStmt& s) {
        return s.kind == HlilStmtKind::kNop && s.comment.empty();
    });
    if (it != stmts.end()) {
        stmts.erase(it, stmts.end());
        modified = true;
    }
}

}  // namespace engine::hlil::passes
