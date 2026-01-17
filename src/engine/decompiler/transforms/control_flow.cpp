#include "engine/decompiler/transforms.h"

#include <algorithm>
#include <functional>
#include <unordered_set>

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

// Compare expressions by variable name only (ignoring size), for switch detection
// where the same variable may have different sizes in different conditions
bool expr_var_name_equal(const mlil::MlilExpr& a, const mlil::MlilExpr& b) {
    // Both must be variables
    if (a.kind != mlil::MlilExprKind::kVar || b.kind != mlil::MlilExprKind::kVar) {
        // Fall back to full key comparison
        return expr_key_equal(a, b);
    }
    // Compare only variable names
    if (a.var.name.empty() || b.var.name.empty()) {
        return false;
    }
    return a.var.name == b.var.name;
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

// Helper to check if an expression is a simple variable (no nested ops)
bool is_simple_var_expr(const mlil::MlilExpr& expr) {
    return expr.kind == mlil::MlilExprKind::kVar && !expr.var.name.empty();
}

// Try to extract (x - c) pattern from an expression
bool extract_sub_const(const mlil::MlilExpr& expr, mlil::MlilExpr& var_out, std::uint64_t& const_out) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kSub || expr.args.size() != 2) {
        return false;
    }
    std::uint64_t imm = 0;
    if (get_imm_value(expr.args[1], imm)) {
        var_out = expr.args[0];
        const_out = imm;
        return true;
    }
    return false;
}

// Check if expression is valid for use as switch condition
bool is_valid_switch_cond(const mlil::MlilExpr& expr) {
    if (expr.kind == mlil::MlilExprKind::kInvalid ||
        expr.kind == mlil::MlilExprKind::kUnknown ||
        expr.kind == mlil::MlilExprKind::kUndef) {
        return false;
    }
    // Ensure variable expressions have a name
    if (expr.kind == mlil::MlilExprKind::kVar) {
        return !expr.var.name.empty();
    }
    // For operations, ensure we have operands
    if (expr.kind == mlil::MlilExprKind::kOp) {
        // Binary ops need 2 args
        if (is_compare_op(expr.op) || expr.op == mlil::MlilOp::kSub ||
            expr.op == mlil::MlilOp::kAdd) {
            return expr.args.size() >= 2;
        }
        // Unary ops need 1 arg
        if (expr.op == mlil::MlilOp::kNot || expr.op == mlil::MlilOp::kNeg) {
            return expr.args.size() >= 1;
        }
    }
    return true;
}

// Extract case value from range check pattern: (x - c) < limit
// Used to detect switch range checks like: if (x > 6) goto default;
bool extract_range_check(const mlil::MlilExpr& cond, mlil::MlilExpr& var_out, std::uint64_t& limit_out) {
    if (cond.kind != mlil::MlilExprKind::kOp || cond.args.size() != 2) {
        return false;
    }
    
    // Pattern: x > c  (where c is the max case value)
    if (cond.op == mlil::MlilOp::kGt || cond.op == mlil::MlilOp::kGe) {
        std::uint64_t imm = 0;
        if (get_imm_value(cond.args[1], imm) && is_valid_switch_cond(cond.args[0])) {
            var_out = cond.args[0];
            limit_out = (cond.op == mlil::MlilOp::kGt) ? imm : imm - 1;
            return true;
        }
    }
    
    // Pattern: c < x  (equivalent to x > c)
    if (cond.op == mlil::MlilOp::kLt || cond.op == mlil::MlilOp::kLe) {
        std::uint64_t imm = 0;
        if (get_imm_value(cond.args[0], imm) && is_valid_switch_cond(cond.args[1])) {
            var_out = cond.args[1];
            limit_out = (cond.op == mlil::MlilOp::kLt) ? imm : imm - 1;
            return true;
        }
    }
    
    return false;
}

// Make a copy of condition and simplify it for pattern matching
mlil::MlilExpr simplify_condition_for_switch(const mlil::MlilExpr& cond) {
    mlil::MlilExpr result = cond;
    simplify_expr(result);
    return result;
}

// Overload that allows specifying if we're already in a switch context
// When in_switch_context is true, we allow eq(x, 0) as case 0
bool extract_switch_case(const Stmt& stmt, mlil::MlilExpr& cond_expr, std::uint64_t& case_val,
                         bool in_switch_context = false) {
    if (stmt.kind != StmtKind::kIf) {
        return false;
    }
    
    // Guard against invalid conditions
    if (stmt.condition.kind == mlil::MlilExprKind::kInvalid ||
        stmt.condition.kind == mlil::MlilExprKind::kUnknown) {
        return false;
    }
    
    // IMPORTANT: Reject patterns that look like null/zero checks, not switch cases
    // ne(x, 0) or eq(x, 0) without subtraction are typically pointer/boolean checks
    // BUT: If we're already in a switch context, eq(x, 0) is likely case 0
    if (stmt.condition.kind == mlil::MlilExprKind::kOp &&
        stmt.condition.args.size() == 2) {
        bool is_ne_zero = (stmt.condition.op == mlil::MlilOp::kNe &&
                          is_zero_imm(stmt.condition.args[1]));
        bool is_zero_ne = (stmt.condition.op == mlil::MlilOp::kNe &&
                          is_zero_imm(stmt.condition.args[0]));
        
        // ne(x, 0) is definitely not a switch case pattern - it's a null check
        if (is_ne_zero || is_zero_ne) {
            return false;
        }
        
        // eq(x, 0) handling depends on context
        if (!in_switch_context) {
            bool is_eq_zero = (stmt.condition.op == mlil::MlilOp::kEq &&
                              is_zero_imm(stmt.condition.args[1]));
            bool is_zero_eq = (stmt.condition.op == mlil::MlilOp::kEq &&
                              is_zero_imm(stmt.condition.args[0]));
            
            if ((is_eq_zero || is_zero_eq)) {
                const mlil::MlilExpr* var_side = is_eq_zero ? &stmt.condition.args[0] : &stmt.condition.args[1];
                // Only accept if the other side is a subtraction (x - c) == 0 pattern
                if (var_side->kind == mlil::MlilExprKind::kVar) {
                    // Simple variable == 0, not in switch context, likely a null check
                    return false;
                }
            }
        }
    }
    
    // Simplify the condition first to normalize patterns like eq(sub(x, c), 0) -> eq(x, c)
    mlil::MlilExpr simplified = simplify_condition_for_switch(stmt.condition);
    
    // Pattern 1: if (x == c) - direct equality (after simplification)
    // But NOT when c == 0 and x is a simple variable (that's a null check)
    if (simplified.kind == mlil::MlilExprKind::kOp &&
        simplified.op == mlil::MlilOp::kEq &&
        simplified.args.size() == 2) {
        std::uint64_t imm = 0;
        if (get_imm_value(simplified.args[1], imm)) {
            if (is_valid_switch_cond(simplified.args[0])) {
                // Reject case 0 if it's a simple variable (null check)
                // BUT: if we're in switch context, allow it as case 0
                if (imm == 0 && simplified.args[0].kind == mlil::MlilExprKind::kVar && !in_switch_context) {
                    // Check if this came from a subtraction pattern
                    // Original condition: eq(sub(x, 0), 0) would simplify to eq(x, 0)
                    // We need to check the original condition
                    if (stmt.condition.kind == mlil::MlilExprKind::kOp &&
                        stmt.condition.op == mlil::MlilOp::kEq) {
                        // Check if original had subtraction
                        bool had_sub = false;
                        for (const auto& arg : stmt.condition.args) {
                            if (arg.kind == mlil::MlilExprKind::kOp &&
                                arg.op == mlil::MlilOp::kSub) {
                                had_sub = true;
                                break;
                            }
                        }
                        if (!had_sub) {
                            return false;  // Simple eq(var, 0), not a switch case
                        }
                    }
                }
                cond_expr = simplified.args[0];
                case_val = imm;
                return true;
            }
        }
        if (get_imm_value(simplified.args[0], imm)) {
            if (is_valid_switch_cond(simplified.args[1])) {
                // Same check for case 0 - allow it in switch context
                if (imm == 0 && simplified.args[1].kind == mlil::MlilExprKind::kVar && !in_switch_context) {
                    if (stmt.condition.kind == mlil::MlilExprKind::kOp &&
                        stmt.condition.op == mlil::MlilOp::kEq) {
                        bool had_sub = false;
                        for (const auto& arg : stmt.condition.args) {
                            if (arg.kind == mlil::MlilExprKind::kOp &&
                                arg.op == mlil::MlilOp::kSub) {
                                had_sub = true;
                                break;
                            }
                        }
                        if (!had_sub) {
                            return false;
                        }
                    }
                }
                cond_expr = simplified.args[1];
                case_val = imm;
                return true;
            }
        }
    }
    
    // Pattern 2: if (!(x - c)) - compiler idiom for equality
    // This is often represented as !(x - c) or (x - c) == 0
    if (simplified.kind == mlil::MlilExprKind::kOp &&
        simplified.op == mlil::MlilOp::kNot &&
        simplified.args.size() == 1) {
        mlil::MlilExpr var;
        std::uint64_t c;
        if (extract_sub_const(simplified.args[0], var, c)) {
            if (is_valid_switch_cond(var)) {
                cond_expr = var;
                case_val = c;
                return true;
            }
        }
        // Pattern 2b: if (!(ne(x, c))) which means eq(x, c)
        // But NOT !(ne(x, 0)) which is just a null check inversion
        const auto& inner = simplified.args[0];
        if (inner.kind == mlil::MlilExprKind::kOp &&
            inner.op == mlil::MlilOp::kNe &&
            inner.args.size() == 2) {
            std::uint64_t imm = 0;
            if (get_imm_value(inner.args[1], imm) && is_valid_switch_cond(inner.args[0])) {
                // Reject !(ne(var, 0)) - this is just checking if var is null
                if (imm == 0 && inner.args[0].kind == mlil::MlilExprKind::kVar) {
                    return false;
                }
                cond_expr = inner.args[0];
                case_val = imm;
                return true;
            }
            if (get_imm_value(inner.args[0], imm) && is_valid_switch_cond(inner.args[1])) {
                if (imm == 0 && inner.args[1].kind == mlil::MlilExprKind::kVar) {
                    return false;
                }
                cond_expr = inner.args[1];
                case_val = imm;
                return true;
            }
        }
        // Pattern 2c: if (!(x)) where x is just a variable - equivalent to x == 0
        // This pattern is REMOVED - !(var) is typically a boolean/null check, not switch case
        // Keep it only for subtraction results
    }
    
    // Pattern 3: if ((x - c) == 0) - explicit equality with subtraction (original form)
    // This is the classic switch case pattern
    if (stmt.condition.kind == mlil::MlilExprKind::kOp &&
        stmt.condition.op == mlil::MlilOp::kEq &&
        stmt.condition.args.size() == 2) {
        std::uint64_t zero = 0;
        const mlil::MlilExpr* sub_expr = nullptr;
        if (get_imm_value(stmt.condition.args[1], zero) && zero == 0) {
            sub_expr = &stmt.condition.args[0];
        } else if (get_imm_value(stmt.condition.args[0], zero) && zero == 0) {
            sub_expr = &stmt.condition.args[1];
        }
        if (sub_expr) {
            mlil::MlilExpr var;
            std::uint64_t c;
            if (extract_sub_const(*sub_expr, var, c)) {
                if (is_valid_switch_cond(var)) {
                    cond_expr = var;
                    case_val = c;
                    return true;
                }
            }
        }
    }
    
    return false;
}

// Helper to check if two variables might be aliases (same value from different representations)
// This handles patterns like: stack.28:i32 and reg.x0 being the same value
bool vars_might_alias(const mlil::MlilExpr& a, const mlil::MlilExpr& b,
                      const std::unordered_set<std::string>& aliases) {
    if (expr_var_name_equal(a, b)) {
        return true;
    }
    // Check if either variable is in the alias set
    std::string name_a, name_b;
    if (a.kind == mlil::MlilExprKind::kVar) {
        name_a = a.var.name;
    }
    if (b.kind == mlil::MlilExprKind::kVar) {
        name_b = b.var.name;
    }
    if (!name_a.empty() && aliases.count(name_a)) {
        return true;
    }
    if (!name_b.empty() && aliases.count(name_b)) {
        return true;
    }
    return false;
}

// Extract alias from assignment statement (x = y)
bool extract_alias(const Stmt& stmt, std::string& name_out) {
    if (stmt.kind != StmtKind::kAssign) {
        return false;
    }
    // Check if RHS is a simple variable
    if (stmt.expr.kind == mlil::MlilExprKind::kVar && !stmt.expr.var.name.empty()) {
        name_out = stmt.expr.var.name;
        return true;
    }
    return false;
}

// Try to collect switch cases from an if-else chain, allowing for comparison-based switches
// Handles interleaved range checks that compilers generate for switch statements
bool collect_switch_cases_from_chain(Stmt& root_if,
                                      mlil::MlilExpr& switch_cond,
                                      std::vector<std::uint64_t>& case_values,
                                      std::vector<std::vector<Stmt>>& case_bodies,
                                      std::vector<Stmt>& default_body) {
    mlil::MlilExpr first_cond;
    std::uint64_t first_val = 0;
    
    if (!extract_switch_case(root_if, first_cond, first_val)) {
        return false;
    }
    
    switch_cond = first_cond;
    case_values.clear();
    case_bodies.clear();
    default_body.clear();
    
    // Track variable aliases for switch condition
    std::unordered_set<std::string> aliases;
    if (first_cond.kind == mlil::MlilExprKind::kVar && !first_cond.var.name.empty()) {
        aliases.insert(first_cond.var.name);
    }
    
    Stmt* current = &root_if;
    int chain_length = 0;
    const int max_iterations = 100;  // Prevent infinite loops
    int iterations = 0;
    
    while (current && current->kind == StmtKind::kIf && iterations++ < max_iterations) {
        mlil::MlilExpr cond;
        std::uint64_t val = 0;
        
        // After finding the first case, we're in switch context - allow case 0
        bool is_in_switch = (chain_length > 0);
        if (extract_switch_case(*current, cond, val, is_in_switch)) {
            // This is a case check
            if (!vars_might_alias(cond, switch_cond, aliases)) {
                // Different switch variable, stop here
                break;
            }
            
            case_values.push_back(val);
            case_bodies.push_back(current->then_body);
            chain_length++;
            
            // Move to else branch
            // Handle cases where else_body has multiple statements (assignments + if)
            Stmt* next_if = nullptr;
            for (auto& s : current->else_body) {
                // Track aliases from assignments like: reg.x0 = stack.28:i32
                if (s.kind == StmtKind::kAssign) {
                    std::string alias;
                    if (extract_alias(s, alias)) {
                        aliases.insert(alias);
                    }
                    // Also track the assigned variable
                    if (!s.var.name.empty()) {
                        aliases.insert(s.var.name);
                    }
                }
                if (s.kind == StmtKind::kIf) {
                    next_if = &s;
                    break;  // Take first if
                }
            }
            
            if (next_if) {
                current = next_if;
            } else if (!current->else_body.empty()) {
                // else_body is the default case (no if found)
                default_body = current->else_body;
                break;
            } else {
                break;
            }
        } else {
            // Not a case check - check if this is a range check
            mlil::MlilExpr range_var;
            std::uint64_t limit;
            if (extract_range_check(current->condition, range_var, limit) &&
                vars_might_alias(range_var, switch_cond, aliases)) {
                // This is a range check (e.g., if (x > 6) goto default)
                // The then_body is the default case (out of range)
                // The else_body continues the switch chain
                
                // Record the default body from then_body
                if (!current->then_body.empty()) {
                    // This is executed when out of range - it's the default case
                    default_body = current->then_body;
                }
                
                // Continue with else_body which has more cases
                // Handle cases where else_body has multiple statements (assignments + if)
                Stmt* next_if_range = nullptr;
                for (auto& s : current->else_body) {
                    // Track aliases from assignments
                    if (s.kind == StmtKind::kAssign) {
                        std::string alias;
                        if (extract_alias(s, alias)) {
                            aliases.insert(alias);
                        }
                        if (!s.var.name.empty()) {
                            aliases.insert(s.var.name);
                        }
                    }
                    if (s.kind == StmtKind::kIf) {
                        next_if_range = &s;
                        break;  // Take first if
                    }
                }
                
                if (next_if_range) {
                    current = next_if_range;
                    continue;
                } else if (!current->else_body.empty()) {
                    // else_body has non-if statements, might be more default code
                    if (chain_length > 0) {
                        for (auto& s : current->else_body) {
                            default_body.push_back(std::move(s));
                        }
                    }
                    break;
                } else {
                    break;
                }
            } else {
                // Non-matching if - treat remaining else_body as default
                if (chain_length > 0 && !current->else_body.empty()) {
                    for (auto& s : current->else_body) {
                        default_body.push_back(std::move(s));
                    }
                }
                break;
            }
        }
    }
    
    return chain_length >= 2;  // Reduced from 3 to 2 for better detection
}

// Check if a statement block ends with a terminator (return, break, continue, goto)
bool block_ends_in_terminator(const std::vector<Stmt>& body) {
    if (body.empty()) return false;
    const auto& last = body.back();
    return last.kind == StmtKind::kReturn ||
           last.kind == StmtKind::kBreak ||
           last.kind == StmtKind::kContinue ||
           last.kind == StmtKind::kGoto;
}

// Collect switch cases from consecutive if statements (flattened form)
// This handles the case where ControlFlowSimplifier has already flattened if-else chains
// into consecutive if statements, each with a terminator in the then-body
bool collect_switch_cases_from_consecutive_ifs(std::vector<Stmt>& stmts,
                                                std::size_t start_idx,
                                                mlil::MlilExpr& switch_cond,
                                                std::vector<std::uint64_t>& case_values,
                                                std::vector<std::vector<Stmt>>& case_bodies,
                                                std::vector<Stmt>& default_body,
                                                std::size_t& end_idx) {
    if (start_idx >= stmts.size() || stmts[start_idx].kind != StmtKind::kIf) {
        return false;
    }
    
    // Extract first case
    mlil::MlilExpr first_cond;
    std::uint64_t first_val = 0;
    
    if (!extract_switch_case(stmts[start_idx], first_cond, first_val)) {
        return false;
    }
    
    // First if must have a terminator in then_body for this pattern
    if (!block_ends_in_terminator(stmts[start_idx].then_body)) {
        return false;
    }
    
    switch_cond = first_cond;
    case_values.clear();
    case_bodies.clear();
    default_body.clear();
    
    case_values.push_back(first_val);
    case_bodies.push_back(stmts[start_idx].then_body);
    
    std::size_t i = start_idx + 1;
    const int max_cases = 100;  // Prevent runaway
    int case_count = 1;
    
    // Look for range checks and more case checks
    while (i < stmts.size() && case_count < max_cases) {
        Stmt& stmt = stmts[i];
        
        if (stmt.kind != StmtKind::kIf) {
            // Non-if statement: this and everything after is default case
            break;
        }
        
        // Check for range check (e.g., if (x > 6) { default_code })
        mlil::MlilExpr range_var;
        std::uint64_t limit;
        if (extract_range_check(stmt.condition, range_var, limit) &&
            expr_var_name_equal(range_var, switch_cond)) {
            // Range check: then_body is what happens when out of range
            // Skip this check but record the default body if we haven't yet
            if (block_ends_in_terminator(stmt.then_body) && default_body.empty()) {
                default_body = stmt.then_body;
            }
            ++i;
            continue;
        }
        
        // Try to extract case
        mlil::MlilExpr cond;
        std::uint64_t val = 0;
        
        // After finding the first case, we're in switch context - allow case 0
        bool is_in_switch = (case_count > 0);
        if (extract_switch_case(stmt, cond, val, is_in_switch)) {
            // Check same switch variable
            if (!expr_var_name_equal(cond, switch_cond)) {
                // Different variable, stop
                break;
            }
            
            // Check if then_body ends with terminator
            if (!block_ends_in_terminator(stmt.then_body)) {
                // If then_body doesn't end with terminator, this might not be a switch case
                // But still collect it if it's a simple case
                if (stmt.then_body.size() > 3) {  // Heuristic: complex body without terminator
                    break;
                }
            }
            
            case_values.push_back(val);
            case_bodies.push_back(stmt.then_body);
            case_count++;
            ++i;
        } else {
            // Not a case check, stop here
            break;
        }
    }
    
    // Collect remaining statements as default body
    if (default_body.empty()) {
        while (i < stmts.size()) {
            // Don't include trailing returns that might be after the switch
            if (stmts[i].kind == StmtKind::kReturn && i == stmts.size() - 1) {
                // Check if this return is part of the function epilogue
                // If so, don't include it in default
                break;
            }
            default_body.push_back(std::move(stmts[i]));
            ++i;
        }
    }
    
    end_idx = i;
    return case_count >= 2;  // Need at least 2 cases
}

void normalize_switch_statements_block(std::vector<Stmt>& stmts) {
    // IMPORTANT: Process switch detection FIRST at this level, BEFORE recursing!
    // This ensures outer if-else chains are detected before inner ones get modified.
    
    // Look for if-else chains OR consecutive ifs that can be converted to switch
    for (std::size_t i = 0; i < stmts.size(); ++i) {
        Stmt& stmt = stmts[i];
        if (stmt.kind != StmtKind::kIf) {
            continue;
        }

        // Try to form a switch using the improved collector
        mlil::MlilExpr switch_cond;
        std::vector<std::uint64_t> case_values;
        std::vector<std::vector<Stmt>> case_bodies;
        std::vector<Stmt> default_body;
        
        bool found_switch = false;
        std::size_t end_idx = i + 1;
        
        // First try the if-else chain pattern (classic nested if-else)
        if (collect_switch_cases_from_chain(stmt, switch_cond, case_values, case_bodies, default_body)) {
            found_switch = true;
        }
        // Then try the consecutive if pattern (flattened by ControlFlowSimplifier)
        else if (collect_switch_cases_from_consecutive_ifs(stmts, i, switch_cond, case_values, case_bodies, default_body, end_idx)) {
            found_switch = true;
        }
        
        if (found_switch) {
            Stmt switch_stmt;
            switch_stmt.kind = StmtKind::kSwitch;
            switch_stmt.condition = switch_cond;
            switch_stmt.case_values = std::move(case_values);
            switch_stmt.case_bodies = std::move(case_bodies);
            switch_stmt.default_body = std::move(default_body);
            
            // Replace the range of statements with the switch
            stmts[i] = std::move(switch_stmt);
            
            // Erase consumed statements (for consecutive if pattern)
            if (end_idx > i + 1) {
                stmts.erase(stmts.begin() + static_cast<std::ptrdiff_t>(i + 1),
                           stmts.begin() + static_cast<std::ptrdiff_t>(end_idx));
                
                // Adjust index if needed, though subsequent ++i will correctly move to the next valid statement
                // (which has shifted down to i+1)
            }
        }
    }
    
    // AFTER switch detection, recurse into all nested structures
    // This includes case bodies from switches we just created, as well as
    // any remaining if/while/for bodies that weren't converted to switches
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

namespace {

// Check if a loop condition is constant false (0)
bool is_dead_loop_condition(const mlil::MlilExpr& cond) {
    if (cond.kind == mlil::MlilExprKind::kImm && cond.imm == 0) return true;
    
    // Handle degenerate operations (e.g. kNe with no args) which can occur from
    // inverted conditions on invalid/empty expressions
    if (cond.kind == mlil::MlilExprKind::kOp && cond.args.empty()) {
        return true;
    }
    
    // Try simplifying
    mlil::MlilExpr temp = cond;
    simplify_expr(temp);
    return (temp.kind == mlil::MlilExprKind::kImm && temp.imm == 0);
}

// Eliminate dead loops: while(0), for(;0;)
void eliminate_dead_loops_block(std::vector<Stmt>& stmts) {
    // First recurse into nested structures
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            eliminate_dead_loops_block(stmt.then_body);
            eliminate_dead_loops_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            eliminate_dead_loops_block(stmt.body);
        } else if (stmt.kind == StmtKind::kSwitch) {
            for (auto& case_body : stmt.case_bodies) {
                eliminate_dead_loops_block(case_body);
            }
            eliminate_dead_loops_block(stmt.default_body);
        }
    }
    
    // Then eliminate dead loops at this level
    auto it = std::remove_if(stmts.begin(), stmts.end(), [](const Stmt& stmt) {
        // while(0) or for(;0;)
        if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kFor) {
            return is_dead_loop_condition(stmt.condition);
        }
        return false;
    });
    stmts.erase(it, stmts.end());
}

} // namespace

void eliminate_dead_loops(Function& function) {
    eliminate_dead_loops_block(function.stmts);
}

} // namespace engine::decompiler