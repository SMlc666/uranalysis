#include "engine/decompiler/transforms.h"

#include <algorithm>
#include <functional>

namespace engine::decompiler {

namespace {

mlil::MlilExpr make_bool_and(mlil::MlilExpr lhs, mlil::MlilExpr rhs) {
    mlil::MlilExpr expr;
    expr.kind = mlil::MlilExprKind::kOp;
    expr.op = mlil::MlilOp::kAnd;
    expr.size = 1;
    expr.args.push_back(std::move(lhs));
    expr.args.push_back(std::move(rhs));
    return expr;
}

void merge_nested_ifs_block(std::vector<Stmt>& stmts) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            merge_nested_ifs_block(stmt.then_body);
            merge_nested_ifs_block(stmt.else_body);
            if (stmt.else_body.empty() && stmt.then_body.size() == 1 &&
                stmt.then_body[0].kind == StmtKind::kIf &&
                stmt.then_body[0].else_body.empty()) {
                Stmt inner = std::move(stmt.then_body[0]);
                stmt.condition = make_bool_and(std::move(stmt.condition), std::move(inner.condition));
                stmt.then_body = std::move(inner.then_body);
            }
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            merge_nested_ifs_block(stmt.body);
            merge_nested_ifs_block(stmt.then_body);
            merge_nested_ifs_block(stmt.else_body);
        }
    }
}

bool expr_key_equal(const mlil::MlilExpr& a, const mlil::MlilExpr& b) {
    const std::string ka = expr_key(a);
    const std::string kb = expr_key(b);
    if (ka.empty() || kb.empty()) {
        return false;
    }
    return ka == kb;
}

bool stmt_is_store_return_pair(const std::vector<Stmt>& body,
                               mlil::MlilExpr& store_target,
                               mlil::MlilExpr& store_expr,
                               mlil::MlilExpr& ret_expr) {
    if (body.size() < 2) {
        return false;
    }
    const Stmt& store = body[body.size() - 2];
    const Stmt& ret = body[body.size() - 1];
    if (store.kind != StmtKind::kStore || ret.kind != StmtKind::kReturn) {
        return false;
    }
    if (expr_key(store.target).empty() || expr_key(store.expr).empty() || expr_key(ret.expr).empty()) {
        return false;
    }
    store_target = store.target;
    store_expr = store.expr;
    ret_expr = ret.expr;
    return true;
}

bool store_return_equal(const mlil::MlilExpr& tgt_a,
                        const mlil::MlilExpr& expr_a,
                        const mlil::MlilExpr& ret_a,
                        const mlil::MlilExpr& tgt_b,
                        const mlil::MlilExpr& expr_b,
                        const mlil::MlilExpr& ret_b) {
    return expr_key_equal(tgt_a, tgt_b) &&
           expr_key_equal(expr_a, expr_b) &&
           expr_key_equal(ret_a, ret_b);
}

void merge_tail_returns_block(std::vector<Stmt>& stmts) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            merge_tail_returns_block(stmt.then_body);
            merge_tail_returns_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            merge_tail_returns_block(stmt.body);
            merge_tail_returns_block(stmt.then_body);
            merge_tail_returns_block(stmt.else_body);
        }
    }

    for (std::size_t i = 0; i < stmts.size(); ++i) {
        Stmt& stmt = stmts[i];
        if (stmt.kind != StmtKind::kIf || stmt.then_body.empty() || stmt.else_body.empty()) {
            continue;
        }
        mlil::MlilExpr then_tgt, then_expr, then_ret;
        mlil::MlilExpr else_tgt, else_expr, else_ret;
        if (!stmt_is_store_return_pair(stmt.then_body, then_tgt, then_expr, then_ret)) {
            continue;
        }
        if (!stmt_is_store_return_pair(stmt.else_body, else_tgt, else_expr, else_ret)) {
            continue;
        }
        if (!store_return_equal(then_tgt, then_expr, then_ret, else_tgt, else_expr, else_ret)) {
            continue;
        }
        stmt.then_body.pop_back();
        stmt.then_body.pop_back();
        stmt.else_body.pop_back();
        stmt.else_body.pop_back();

        Stmt store;
        store.kind = StmtKind::kStore;
        store.target = then_tgt;
        store.expr = then_expr;

        Stmt ret;
        ret.kind = StmtKind::kReturn;
        ret.expr = then_ret;

        stmts.insert(stmts.begin() + static_cast<std::ptrdiff_t>(i + 1), std::move(ret));
        stmts.insert(stmts.begin() + static_cast<std::ptrdiff_t>(i + 1), std::move(store));
        i += 2;
    }
}

bool is_return_guard(const std::vector<Stmt>& body) {
    return body.size() == 1 && body.front().kind == StmtKind::kReturn;
}

bool is_compare_op(mlil::MlilOp op) {
    switch (op) {
        case mlil::MlilOp::kLt:
        case mlil::MlilOp::kLe:
        case mlil::MlilOp::kGt:
        case mlil::MlilOp::kGe:
        case mlil::MlilOp::kEq:
        case mlil::MlilOp::kNe:
            return true;
        default:
            return false;
    }
}

mlil::MlilExpr invert_condition_expr(const mlil::MlilExpr& expr) {
    mlil::MlilExpr out = expr;
    if (out.kind == mlil::MlilExprKind::kOp && out.args.size() == 2 && is_compare_op(out.op)) {
        switch (out.op) {
            case mlil::MlilOp::kLt: out.op = mlil::MlilOp::kGe; return out;
            case mlil::MlilOp::kLe: out.op = mlil::MlilOp::kGt; return out;
            case mlil::MlilOp::kGt: out.op = mlil::MlilOp::kLe; return out;
            case mlil::MlilOp::kGe: out.op = mlil::MlilOp::kLt; return out;
            case mlil::MlilOp::kEq: out.op = mlil::MlilOp::kNe; return out;
            case mlil::MlilOp::kNe: out.op = mlil::MlilOp::kEq; return out;
            default: break;
        }
    }
    if (out.kind == mlil::MlilExprKind::kOp && out.op == mlil::MlilOp::kNot && out.args.size() == 1) {
        return out.args.front();
    }
    mlil::MlilExpr neg;
    neg.kind = mlil::MlilExprKind::kOp;
    neg.op = mlil::MlilOp::kNot;
    neg.size = 1;
    neg.args.push_back(out);
    return neg;
}

void flatten_guard_clauses_block(std::vector<Stmt>& stmts) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            flatten_guard_clauses_block(stmt.then_body);
            flatten_guard_clauses_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            flatten_guard_clauses_block(stmt.body);
            flatten_guard_clauses_block(stmt.then_body);
            flatten_guard_clauses_block(stmt.else_body);
        }
    }

    for (std::size_t i = 0; i < stmts.size(); ++i) {
        Stmt& stmt = stmts[i];
        if (stmt.kind != StmtKind::kIf) {
            continue;
        }
        if (stmt.then_body.empty()) {
            continue;
        }
        if (!stmt.else_body.empty() && is_return_guard(stmt.then_body)) {
            std::vector<Stmt> tail = std::move(stmt.else_body);
            stmt.else_body.clear();
            stmts.insert(stmts.begin() + static_cast<std::ptrdiff_t>(i + 1),
                         std::make_move_iterator(tail.begin()),
                         std::make_move_iterator(tail.end()));
            continue;
        }
        if (!stmt.else_body.empty() && is_return_guard(stmt.else_body)) {
            std::vector<Stmt> tail = std::move(stmt.then_body);
            stmt.then_body = std::move(stmt.else_body);
            stmt.else_body.clear();
            stmt.condition = invert_condition_expr(stmt.condition);
            stmts.insert(stmts.begin() + static_cast<std::ptrdiff_t>(i + 1),
                         std::make_move_iterator(tail.begin()),
                         std::make_move_iterator(tail.end()));
            continue;
        }
    }
}

bool extract_switch_case(const Stmt& stmt, mlil::MlilExpr& cond_expr, std::uint64_t& case_val) {
    if (stmt.kind != StmtKind::kIf) {
        return false;
    }
    // Match: if (x == c)
    if (stmt.condition.kind == mlil::MlilExprKind::kOp && stmt.condition.op == mlil::MlilOp::kEq &&
        stmt.condition.args.size() == 2) {
        std::uint64_t imm = 0;
        if (get_imm_value(stmt.condition.args[1], imm)) {
            cond_expr = stmt.condition.args[0];
            case_val = imm;
            return true;
        }
        if (get_imm_value(stmt.condition.args[0], imm)) {
            cond_expr = stmt.condition.args[1];
            case_val = imm;
            return true;
        }
    }
    return false;
}

void normalize_switch_statements_block(std::vector<Stmt>& stmts) {
    // First recurse into nested structures
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            normalize_switch_statements_block(stmt.then_body);
            normalize_switch_statements_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            normalize_switch_statements_block(stmt.body);
            normalize_switch_statements_block(stmt.then_body);
            normalize_switch_statements_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kSwitch) {
            for (auto& case_body : stmt.case_bodies) {
                normalize_switch_statements_block(case_body);
            }
            normalize_switch_statements_block(stmt.default_body);
        }
    }

    // Look for if-else chains that can be converted to switch
    for (std::size_t i = 0; i < stmts.size(); ++i) {
        Stmt& stmt = stmts[i];
        if (stmt.kind != StmtKind::kIf) {
            continue;
        }

        // Try to form a switch
        mlil::MlilExpr switch_cond;
        std::uint64_t first_case_val = 0;
        if (!extract_switch_case(stmt, switch_cond, first_case_val)) {
            continue;
        }

        // Collect if-else chain
        std::vector<std::uint64_t> case_values;
        std::vector<std::vector<Stmt>> case_bodies;
        std::vector<Stmt> default_body;
        
        Stmt* current = &stmt;
        int chain_length = 0;
        const int kMinCases = 3;  // Minimum cases to form a switch
        
        while (current && current->kind == StmtKind::kIf) {
            mlil::MlilExpr cond;
            std::uint64_t val = 0;
            if (!extract_switch_case(*current, cond, val)) {
                // This if doesn't match switch pattern, treat else_body as default
                if (chain_length > 0 && !current->else_body.empty()) {
                    // The else of this mismatched if becomes part of default
                    for (auto& s : current->else_body) {
                        default_body.push_back(std::move(s));
                    }
                }
                break;
            }
            if (!expr_key_equal(cond, switch_cond)) {
                // Different switch variable, stop here
                break;
            }
            
            case_values.push_back(val);
            case_bodies.push_back(current->then_body);
            chain_length++;
            
            // Move to else branch
            if (current->else_body.size() == 1 && current->else_body[0].kind == StmtKind::kIf) {
                current = &current->else_body[0];
            } else if (!current->else_body.empty()) {
                // else_body is the default case
                default_body = current->else_body;
                break;
            } else {
                break;
            }
        }
        
        // Only convert to switch if we have enough cases
        if (chain_length >= kMinCases) {
            Stmt switch_stmt;
            switch_stmt.kind = StmtKind::kSwitch;
            switch_stmt.condition = switch_cond;
            switch_stmt.case_values = std::move(case_values);
            switch_stmt.case_bodies = std::move(case_bodies);
            switch_stmt.default_body = std::move(default_body);
            
            stmts[i] = std::move(switch_stmt);
        }
    }
}

} // namespace

void recover_switch_statements(Function& function) {
    normalize_switch_statements_block(function.stmts);
}

void merge_nested_ifs(Function& function) {
    merge_nested_ifs_block(function.stmts);
}

void merge_tail_returns(Function& function) {
    merge_tail_returns_block(function.stmts);
}

void flatten_guard_clauses(Function& function) {
    flatten_guard_clauses_block(function.stmts);
}

} // namespace engine::decompiler