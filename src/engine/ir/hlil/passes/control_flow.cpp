#include "control_flow.h"
#include "engine/hlil_opt.h" // For helper functions if needed, or we reimplement them
#include <algorithm>

namespace engine::hlil::passes {

using Expr = mlil::MlilExpr;

Expr ControlFlowSimplifier::invert_condition(Expr cond) {
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

bool ControlFlowSimplifier::run(Function& function) {
    return process_stmts(function.stmts);
}

bool ControlFlowSimplifier::process_stmts(std::vector<HlilStmt>& stmts) {
    bool modified = false;
    
    remove_nops(stmts, modified);
    
    std::vector<HlilStmt> flattened;
    flattened.reserve(stmts.size());
    
    for (auto& stmt : stmts) {
        visit(stmt, modified); 

        if (stmt.kind == HlilStmtKind::kIf && !stmt.else_body.empty()) {
            if (block_ends_in_terminator(stmt.then_body)) {
                // Flatten: Keep IF (with then), move ELSE to main stream
                std::vector<HlilStmt> else_stmts = std::move(stmt.else_body);
                stmt.else_body.clear();
                flattened.push_back(std::move(stmt));
                flattened.insert(flattened.end(), std::make_move_iterator(else_stmts.begin()), std::make_move_iterator(else_stmts.end()));
                modified = true;
                continue;
            } else if (block_ends_in_terminator(stmt.else_body)) {

                stmt.condition = invert_condition(std::move(stmt.condition));
                std::swap(stmt.then_body, stmt.else_body);
                
                std::vector<HlilStmt> else_stmts = std::move(stmt.else_body); // Was 'then'
                stmt.else_body.clear();
                flattened.push_back(std::move(stmt));
                flattened.insert(flattened.end(), std::make_move_iterator(else_stmts.begin()), std::make_move_iterator(else_stmts.end()));
                modified = true;
                continue;
            }
        }
        flattened.push_back(std::move(stmt));
    }

    stmts = std::move(flattened);
    if (modified) {
        remove_nops(stmts, modified);
    }
    
    return modified;
}

void ControlFlowSimplifier::visit(HlilStmt& stmt, bool& modified) {
    if (stmt.kind == HlilStmtKind::kIf) {

        if (process_stmts(stmt.then_body)) modified = true;
        if (process_stmts(stmt.else_body)) modified = true;

        bool then_empty = is_empty_block(stmt.then_body);
        bool else_empty = is_empty_block(stmt.else_body);

        if (then_empty && else_empty) {
            stmt.kind = HlilStmtKind::kNop;
            stmt.then_body.clear();
            stmt.else_body.clear();
            modified = true;
            return;
        }

        if (then_empty && !else_empty) {
            stmt.condition = invert_condition(std::move(stmt.condition));
            std::swap(stmt.then_body, stmt.else_body);
            modified = true;
            // Update flags
            then_empty = false; 
            else_empty = true; 
        }

        // 3. Merge Nested Ifs (AND Merge): if (c1) { if (c2) body; } -> if (c1 && c2) body;
        if (else_empty && stmt.then_body.size() == 1) {
            auto& inner = stmt.then_body[0];
            if (inner.kind == HlilStmtKind::kIf && is_empty_block(inner.else_body)) {
                Expr combined_cond;
                combined_cond.kind = mlil::MlilExprKind::kOp;
                combined_cond.op = mlil::MlilOp::kAnd;
                combined_cond.size = 1;
                combined_cond.args.push_back(std::move(stmt.condition));
                combined_cond.args.push_back(std::move(inner.condition));
                
                stmt.condition = std::move(combined_cond);
                std::vector<HlilStmt> merged_body = std::move(inner.then_body);
                stmt.then_body = std::move(merged_body);
                
                modified = true;
                visit(stmt, modified); // Re-visit
            }
        }

    } else if (stmt.kind == HlilStmtKind::kWhile) {
        if (process_stmts(stmt.body)) modified = true;
        
        // Eliminate dead loops: while(0), while(false)
        // Condition is constant 0 - loop never executes
        if (stmt.condition.kind == mlil::MlilExprKind::kImm && stmt.condition.imm == 0) {
            stmt.kind = HlilStmtKind::kNop;
            stmt.body.clear();
            stmt.condition = {};
            modified = true;
        }
    } else if (stmt.kind == HlilStmtKind::kDoWhile) {
        if (process_stmts(stmt.body)) modified = true;
    }
}

bool ControlFlowSimplifier::block_ends_in_terminator(const std::vector<HlilStmt>& stmts) {
    if (stmts.empty()) return false;
    const auto& last = stmts.back();
    return last.kind == HlilStmtKind::kRet || 
           last.kind == HlilStmtKind::kBreak || 
           last.kind == HlilStmtKind::kContinue ||
           last.kind == HlilStmtKind::kGoto;
}

void ControlFlowSimplifier::remove_nops(std::vector<HlilStmt>& stmts, bool& modified) {
    auto it = std::remove_if(stmts.begin(), stmts.end(), [&](const HlilStmt& s) {
        bool is_nop = s.kind == HlilStmtKind::kNop && s.comment.empty();
        if (is_nop) modified = true;
        return is_nop;
    });
    stmts.erase(it, stmts.end());
}

bool ControlFlowSimplifier::is_empty_block(const std::vector<HlilStmt>& stmts) {
    for (const auto& s : stmts) {
        if (s.kind == HlilStmtKind::kNop) continue;
        if (s.kind == HlilStmtKind::kLabel) continue;
        if (s.kind == HlilStmtKind::kAssign) {
            const std::string& name = s.var.name;
            if (name == "sp" || name.rfind("sp_", 0) == 0 || 
                name == "reg.sp" || name == "reg.wsp") {
                continue;
            }
        }
        return false;
    }
    return true;
}

}  // namespace engine::hlil::passes
