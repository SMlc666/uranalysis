#include "loops.h"
#include "engine/hlil_opt.h"

namespace engine::hlil::passes {

namespace {

using Expr = mlil::MlilExpr;

bool is_infinite_loop(const HlilStmt& stmt) {
    if (stmt.kind != HlilStmtKind::kWhile) return false;
    if (stmt.condition.kind == mlil::MlilExprKind::kImm) {
        return stmt.condition.imm != 0;
    }
    return false;
}

Expr invert_condition(Expr cond) {
    if (cond.kind == mlil::MlilExprKind::kImm && cond.size == 1) {
        cond.imm = (cond.imm & 1) ? 0 : 1;
        return cond;
    }
    if (cond.kind == mlil::MlilExprKind::kOp && cond.size == 1) {
        switch (cond.op) {
            case mlil::MlilOp::kEq: cond.op = mlil::MlilOp::kNe; return cond;
            case mlil::MlilOp::kNe: cond.op = mlil::MlilOp::kEq; return cond;
            case mlil::MlilOp::kLt: cond.op = mlil::MlilOp::kGe; return cond;
            case mlil::MlilOp::kLe: cond.op = mlil::MlilOp::kGt; return cond;
            case mlil::MlilOp::kGt: cond.op = mlil::MlilOp::kLe; return cond;
            case mlil::MlilOp::kGe: cond.op = mlil::MlilOp::kLt; return cond;
            default: break;
        }
    }
    // Fallback: cond == 0
    Expr eq_zero;
    eq_zero.kind = mlil::MlilExprKind::kOp;
    eq_zero.op = mlil::MlilOp::kEq;
    eq_zero.size = 1;
    eq_zero.args.push_back(std::move(cond));
    Expr zero; 
    zero.kind = mlil::MlilExprKind::kImm; 
    zero.imm = 0; 
    zero.size = 1;
    eq_zero.args.push_back(std::move(zero));
    return eq_zero;
}

} // namespace

bool LoopReconstructor::run(Function& function) {
    return process_stmts(function.stmts);
}

bool LoopReconstructor::process_stmts(std::vector<HlilStmt>& stmts) {
    bool modified = false;
    
    std::vector<HlilStmt> next_stmts;
    next_stmts.reserve(stmts.size());

    for (std::size_t i = 0; i < stmts.size(); ++i) {
        auto& s = stmts[i];
        visit(s, modified);

        // 1. Try to match Do-While: while(1) { ... if(c) break; }
        if (is_infinite_loop(s) && !s.body.empty()) {
            auto& last = s.body.back();
            if (last.kind == HlilStmtKind::kIf) {
                // Check pattern: if (c) break;
                bool then_break = !last.then_body.empty() && 
                                  last.then_body.front().kind == HlilStmtKind::kBreak &&
                                  last.then_body.size() == 1;
                bool else_empty = last.else_body.empty();

                // Check pattern: if (c) {} else break;
                bool then_empty = last.then_body.empty();
                bool else_break = !last.else_body.empty() && 
                                  last.else_body.front().kind == HlilStmtKind::kBreak &&
                                  last.else_body.size() == 1;

                if (then_break && else_empty) {
                    // while(1) { ... if(c) break; }  => do { ... } while(!c);
                    s.kind = HlilStmtKind::kDoWhile;
                    s.condition = invert_condition(std::move(last.condition));
                    s.body.pop_back(); // Remove the break-if
                    modified = true;
                } else if (then_empty && else_break) {
                    // while(1) { ... if(c) {} else break; } => do { ... } while(c);
                    s.kind = HlilStmtKind::kDoWhile;
                    s.condition = std::move(last.condition);
                    s.body.pop_back(); // Remove the break-if
                    modified = true;
                }
            }
        }

        // 2. Try to match For: Init; While (DoWhile is rare for 'for')
        if (i + 1 < stmts.size() && s.kind == HlilStmtKind::kAssign && stmts[i+1].kind == HlilStmtKind::kWhile) {
            auto& next = stmts[i+1];
            if (!next.body.empty() && next.body.back().kind == HlilStmtKind::kAssign) {
                auto& step = next.body.back();
                // Check if step modifies the same variable as init
                if (step.var.name == s.var.name) {
                    // Success: Create For loop
                    HlilStmt for_stmt;
                    for_stmt.kind = HlilStmtKind::kFor;
                    for_stmt.condition = std::move(next.condition);
                    for_stmt.then_body.push_back(std::move(s)); // Init
                    for_stmt.else_body.push_back(std::move(step)); // Step
                    
                    next.body.pop_back(); // Remove step from body
                    for_stmt.body = std::move(next.body);
                    
                    next_stmts.push_back(std::move(for_stmt));
                    i++; // Skip the while statement
                    modified = true;
                    continue;
                }
            }
        }
        next_stmts.push_back(std::move(s));
    }
    
    stmts = std::move(next_stmts);
    return modified;
}

void LoopReconstructor::visit(HlilStmt& stmt, bool& modified) {
    if (stmt.kind == HlilStmtKind::kIf) {
        if (process_stmts(stmt.then_body)) modified = true;
        if (process_stmts(stmt.else_body)) modified = true;
    } else if (stmt.kind == HlilStmtKind::kWhile || stmt.kind == HlilStmtKind::kFor || stmt.kind == HlilStmtKind::kDoWhile) {
        if (process_stmts(stmt.body)) modified = true;
    }
}

}  // namespace engine::hlil::passes
