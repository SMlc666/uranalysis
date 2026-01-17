#include "dce.h"
#include <algorithm>
#include <unordered_set>

namespace engine::hlil::passes {

using Expr = mlil::MlilExpr;

namespace {

// Collect all variables defined in a block (including nested control flow)
void collect_defined_vars(const std::vector<HlilStmt>& stmts, std::unordered_set<std::string>& defined) {
    for (const auto& stmt : stmts) {
        if (stmt.kind == HlilStmtKind::kAssign && !stmt.var.name.empty()) {
            defined.insert(stmt.var.name);
        } else if (stmt.kind == HlilStmtKind::kCall) {
            for (const auto& ret : stmt.returns) {
                if (!ret.name.empty()) {
                    defined.insert(ret.name);
                }
            }
        } else if (stmt.kind == HlilStmtKind::kIf) {
            collect_defined_vars(stmt.then_body, defined);
            collect_defined_vars(stmt.else_body, defined);
        } else if (stmt.kind == HlilStmtKind::kWhile || 
                   stmt.kind == HlilStmtKind::kDoWhile || 
                   stmt.kind == HlilStmtKind::kFor) {
            collect_defined_vars(stmt.body, defined);
            collect_defined_vars(stmt.then_body, defined);
            collect_defined_vars(stmt.else_body, defined);
        }
    }
}

} // namespace

bool DeadCodeEliminator::run(Function& function) {
    std::unordered_map<std::string, int> counts;
    std::unordered_set<std::string> loop_live;  // Variables that are live in loops
    count_usages(function.stmts, counts, loop_live, false);
    
    // Variables used in loops are always considered live (loop-carried dependencies)
    for (const auto& var : loop_live) {
        counts[var] = std::max(counts[var], 1);
    }
    
    bool modified = false;
    eliminate(function.stmts, counts, modified);
    return modified;
}

void DeadCodeEliminator::count_usages(const std::vector<HlilStmt>& stmts, 
                                       std::unordered_map<std::string, int>& counts,
                                       std::unordered_set<std::string>& loop_live,
                                       bool in_loop) {
    for (const auto& stmt : stmts) {
        auto visit_expr = [&](const Expr& e) {
            auto recursive = [&](const Expr& sub, auto& self) -> void {
                if (sub.kind == mlil::MlilExprKind::kVar) {
                    counts[sub.var.name]++;
                    if (in_loop) {
                        loop_live.insert(sub.var.name);
                    }
                }
                for (const auto& arg : sub.args) self(arg, self);
            };
            recursive(e, recursive);
        };

        switch (stmt.kind) {
            case HlilStmtKind::kAssign: 
                visit_expr(stmt.expr); 
                // For loop-carried dependencies: if we're in a loop and this variable
                // is both defined and used in the loop, mark it as live
                if (in_loop && !stmt.var.name.empty()) {
                    // Check if RHS uses any variable defined in the loop (including itself)
                    // This handles patterns like: x = f(x) inside a loop
                    loop_live.insert(stmt.var.name);
                }
                break;
            case HlilStmtKind::kStore: visit_expr(stmt.target); visit_expr(stmt.expr); break;
            case HlilStmtKind::kCall:
                visit_expr(stmt.target);
                for (const auto& a : stmt.args) visit_expr(a);
                break;
            case HlilStmtKind::kRet: visit_expr(stmt.expr); break;
            case HlilStmtKind::kIf:
                visit_expr(stmt.condition);
                count_usages(stmt.then_body, counts, loop_live, in_loop);
                count_usages(stmt.else_body, counts, loop_live, in_loop);
                break;
            case HlilStmtKind::kWhile:
            case HlilStmtKind::kDoWhile:
            case HlilStmtKind::kFor: {
                visit_expr(stmt.condition);
                // All variables used/defined in loop body need special handling
                count_usages(stmt.body, counts, loop_live, true);
                count_usages(stmt.then_body, counts, loop_live, true);
                count_usages(stmt.else_body, counts, loop_live, true);
                break;
            }
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
