#include "engine/decompiler/transforms.h"

#include <algorithm>
#include <functional>
#include <unordered_set>
#include <unordered_map>

namespace engine::decompiler {

namespace {

bool is_inc_stmt(const Stmt& stmt, std::string& var_name, int& delta) {
    if (stmt.kind != StmtKind::kAssign || stmt.var.name.empty()) {
        return false;
    }
    if (stmt.expr.kind != mlil::MlilExprKind::kOp || stmt.expr.args.size() != 2) {
        return false;
    }
    if (stmt.expr.op != mlil::MlilOp::kAdd && stmt.expr.op != mlil::MlilOp::kSub) {
        return false;
    }
    if (!expr_uses_var(stmt.expr.args[0], stmt.var.name)) {
        // Warning: This check might be too simple if variable name is reused?
        // But logic matches original.
        // Wait, original was: expr_is_var_name(stmt.expr.args[0], stmt.var.name)
        // I need expr_is_var_name?
        // expr_uses_var is recursive. expr_is_var_name checks exact match.
        // I should implement expr_is_var_name locally or use expr.kind check.
        if (stmt.expr.args[0].kind == mlil::MlilExprKind::kVar && stmt.expr.args[0].var.name == stmt.var.name) {
             // ok
        } else {
             return false;
        }
    } else {
         if (stmt.expr.args[0].kind != mlil::MlilExprKind::kVar || stmt.expr.args[0].var.name != stmt.var.name) {
             return false;
         }
    }

    if (!is_one_imm(stmt.expr.args[1])) {
        return false;
    }
    var_name = stmt.var.name;
    delta = (stmt.expr.op == mlil::MlilOp::kAdd) ? 1 : -1;
    return true;
}

bool is_control_or_boundary_stmt(const Stmt& stmt) {
    switch (stmt.kind) {
        case StmtKind::kIf:
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
        case StmtKind::kFor:
        case StmtKind::kLabel:
        case StmtKind::kGoto:
        case StmtKind::kBreak:
        case StmtKind::kContinue:
        case StmtKind::kReturn:
            return true;
        default:
            return false;
    }
}

bool expr_uses_var_only_as_offset(const mlil::MlilExpr& expr,
                                  const std::string& var_name,
                                  int delta,
                                  bool& used_any) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        if (expr.var.name == var_name) {
            return false;
        }
        return true;
    }
    if (expr.kind == mlil::MlilExprKind::kOp && expr.args.size() == 2 &&
        (expr.op == mlil::MlilOp::kAdd || expr.op == mlil::MlilOp::kSub)) {
        const bool add = (expr.op == mlil::MlilOp::kAdd);
        const bool sub = (expr.op == mlil::MlilOp::kSub);
        const bool want_add = (delta > 0);
        const bool want_sub = (delta < 0);
        if ((add && want_add) || (sub && want_sub)) {
            const auto& a = expr.args[0];
            const auto& b = expr.args[1];
            if (a.kind == mlil::MlilExprKind::kVar && a.var.name == var_name && is_one_imm(b)) {
                used_any = true;
                return true;
            }
            if (add && b.kind == mlil::MlilExprKind::kVar && b.var.name == var_name && is_one_imm(a)) {
                used_any = true;
                return true;
            }
        }
    }
    for (const auto& arg : expr.args) {
        if (!expr_uses_var_only_as_offset(arg, var_name, delta, used_any)) {
            return false;
        }
    }
    return true;
}

bool stmt_uses_var_only_as_offset(const Stmt& stmt,
                                  const std::string& var_name,
                                  int delta,
                                  bool& used_any,
                                  bool condition_only = false) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            return expr_uses_var_only_as_offset(stmt.expr, var_name, delta, used_any);
        case StmtKind::kStore:
            return expr_uses_var_only_as_offset(stmt.target, var_name, delta, used_any) &&
                   expr_uses_var_only_as_offset(stmt.expr, var_name, delta, used_any);
        case StmtKind::kCall:
            if (!expr_uses_var_only_as_offset(stmt.target, var_name, delta, used_any)) {
                return false;
            }
            for (const auto& arg : stmt.args) {
                if (!expr_uses_var_only_as_offset(arg, var_name, delta, used_any)) {
                    return false;
                }
            }
            return true;
        case StmtKind::kReturn:
            return expr_uses_var_only_as_offset(stmt.expr, var_name, delta, used_any);
        case StmtKind::kIf:
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
            return expr_uses_var_only_as_offset(stmt.condition, var_name, delta, used_any);
        default:
            return condition_only ? true : true;
    }
}

void rewrite_var_offset_expr(mlil::MlilExpr& expr, const std::string& var_name, int delta) {
    if (expr.kind == mlil::MlilExprKind::kOp && expr.args.size() == 2 &&
        (expr.op == mlil::MlilOp::kAdd || expr.op == mlil::MlilOp::kSub)) {
        const bool add = (expr.op == mlil::MlilOp::kAdd);
        const bool sub = (expr.op == mlil::MlilOp::kSub);
        const bool want_add = (delta > 0);
        const bool want_sub = (delta < 0);
        if ((add && want_add) || (sub && want_sub)) {
            const auto& a = expr.args[0];
            const auto& b = expr.args[1];
            if (a.kind == mlil::MlilExprKind::kVar && a.var.name == var_name && is_one_imm(b)) {
                expr = a;
                return;
            }
            if (add && b.kind == mlil::MlilExprKind::kVar && b.var.name == var_name && is_one_imm(a)) {
                expr = b;
                return;
            }
        }
    }
    for (auto& arg : expr.args) {
        rewrite_var_offset_expr(arg, var_name, delta);
    }
}

void rewrite_stmt_var_offset(Stmt& stmt, const std::string& var_name, int delta, bool condition_only = false) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            rewrite_var_offset_expr(stmt.expr, var_name, delta);
            break;
        case StmtKind::kStore:
            rewrite_var_offset_expr(stmt.target, var_name, delta);
            rewrite_var_offset_expr(stmt.expr, var_name, delta);
            break;
        case StmtKind::kCall:
            rewrite_var_offset_expr(stmt.target, var_name, delta);
            for (auto& arg : stmt.args) {
                rewrite_var_offset_expr(arg, var_name, delta);
            }
            break;
        case StmtKind::kReturn:
            rewrite_var_offset_expr(stmt.expr, var_name, delta);
            break;
        case StmtKind::kIf:
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
            rewrite_var_offset_expr(stmt.condition, var_name, delta);
            break;
        default:
            if (!condition_only) {
                rewrite_var_offset_expr(stmt.expr, var_name, delta);
                rewrite_var_offset_expr(stmt.target, var_name, delta);
            }
            break;
    }
}

void normalize_post_increments_block(std::vector<Stmt>& stmts) {
    for (std::size_t i = 0; i < stmts.size(); ++i) {
        Stmt& stmt = stmts[i];
        if (stmt.kind == StmtKind::kIf) {
            normalize_post_increments_block(stmt.then_body);
            normalize_post_increments_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            normalize_post_increments_block(stmt.body);
            normalize_post_increments_block(stmt.then_body);
            normalize_post_increments_block(stmt.else_body);
        }

        std::string var_name;
        int delta = 0;
        if (!is_inc_stmt(stmt, var_name, delta)) {
            continue;
        }

        bool any_use = false;
        bool has_control = false;
        std::size_t control_index = 0;
        std::size_t j = i + 1;
        for (; j < stmts.size(); ++j) {
            Stmt& next = stmts[j];
            if (is_control_or_boundary_stmt(next)) {
                bool used = false;
                if ((next.kind == StmtKind::kIf || next.kind == StmtKind::kWhile ||
                     next.kind == StmtKind::kDoWhile) &&
                    stmt_uses_var_only_as_offset(next, var_name, delta, used, true)) {
                    if (used) {
                        any_use = true;
                    }
                    has_control = true;
                    control_index = j;
                    ++j;
                }
                break;
            }
            if (stmt_defines_var(next, var_name)) {
                break;
            }
            bool used = false;
            if (!stmt_uses_var_only_as_offset(next, var_name, delta, used)) {
                break;
            }
            if (used) {
                any_use = true;
            }
        }

        if (!any_use) {
            continue;
        }

        const std::size_t end = j;
        for (std::size_t k = i + 1; k < end; ++k) {
            if (has_control && k == control_index) {
                rewrite_stmt_var_offset(stmts[k], var_name, delta, true);
            } else {
                rewrite_stmt_var_offset(stmts[k], var_name, delta);
            }
        }

        Stmt inc = std::move(stmts[i]);
        stmts.erase(stmts.begin() + static_cast<std::ptrdiff_t>(i));
        if (end > i) {
            --j;
        }
        if (has_control) {
            if (control_index > i) {
                --control_index;
            }
            stmts.insert(stmts.begin() + static_cast<std::ptrdiff_t>(control_index), std::move(inc));
            i = control_index;
        } else {
            stmts.insert(stmts.begin() + static_cast<std::ptrdiff_t>(j), std::move(inc));
            i = j;
        }
    }
}

void collect_stmt_uses_all(const Stmt& stmt, std::unordered_set<std::string>& used) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            collect_expr_vars(stmt.expr, used);
            break;
        case StmtKind::kStore:
            collect_expr_vars(stmt.target, used);
            collect_expr_vars(stmt.expr, used);
            break;
        case StmtKind::kCall:
            collect_expr_vars(stmt.target, used);
            for (const auto& arg : stmt.args) {
                collect_expr_vars(arg, used);
            }
            break;
        case StmtKind::kReturn:
            collect_expr_vars(stmt.expr, used);
            break;
        case StmtKind::kIf:
            collect_expr_vars(stmt.condition, used);
            for (const auto& inner : stmt.then_body) {
                collect_stmt_uses_all(inner, used);
            }
            for (const auto& inner : stmt.else_body) {
                collect_stmt_uses_all(inner, used);
            }
            break;
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
        case StmtKind::kFor:
            collect_expr_vars(stmt.condition, used);
            for (const auto& inner : stmt.body) {
                collect_stmt_uses_all(inner, used);
            }
            for (const auto& inner : stmt.then_body) {
                collect_stmt_uses_all(inner, used);
            }
            for (const auto& inner : stmt.else_body) {
                collect_stmt_uses_all(inner, used);
            }
            break;
        default:
            break;
    }
}

void collect_increments_block(const std::vector<Stmt>& stmts,
                              std::unordered_set<std::string>& out,
                              bool top_level_only = false) {
    for (const auto& stmt : stmts) {
        std::string var_name;
        int delta = 0;
        if (is_inc_stmt(stmt, var_name, delta)) {
            if (!var_name.empty()) {
                out.insert(var_name);
            }
        }
        if (top_level_only) {
            continue;
        }
        if (stmt.kind == StmtKind::kIf) {
            collect_increments_block(stmt.then_body, out, top_level_only);
            collect_increments_block(stmt.else_body, out, top_level_only);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            collect_increments_block(stmt.body, out, top_level_only);
            collect_increments_block(stmt.then_body, out, top_level_only);
            collect_increments_block(stmt.else_body, out, top_level_only);
        }
    }
}

std::unordered_set<std::string> intersect_sets(const std::unordered_set<std::string>& a,
                                                const std::unordered_set<std::string>& b) {
    std::unordered_set<std::string> out;
    for (const auto& name : a) {
        if (b.find(name) != b.end()) {
            out.insert(name);
        }
    }
    return out;
}

bool is_temp_like_name(const std::string& name) {
    if (name.empty()) {
        return false;
    }
    if (name.rfind("tmp", 0) == 0) {
        return true;
    }
    char c = name[0];
    return c == 'v' || c == 'i' || c == 'j' || c == 'k' || c == 't' || c == 'n' || c == 'm';
}

void seed_uninit_loop_indices_block(std::vector<Stmt>& stmts,
                                    const std::unordered_set<std::string>& local_names,
                                    const std::unordered_set<std::string>& param_names,
                                    std::unordered_set<std::string> defined) {
    for (std::size_t i = 0; i < stmts.size(); ++i) {
        Stmt& stmt = stmts[i];
        if (stmt.kind == StmtKind::kAssign && !stmt.var.name.empty()) {
            defined.insert(stmt.var.name);
            continue;
        }
        if (stmt.kind == StmtKind::kCall) {
            for (const auto& ret : stmt.returns) {
                if (!ret.name.empty()) {
                    defined.insert(ret.name);
                }
            }
            continue;
        }

        if (stmt.kind == StmtKind::kIf) {
            auto then_defined = defined;
            auto else_defined = defined;
            seed_uninit_loop_indices_block(stmt.then_body, local_names, param_names, then_defined);
            seed_uninit_loop_indices_block(stmt.else_body, local_names, param_names, else_defined);
            defined = intersect_sets(then_defined, else_defined);
            continue;
        }

        if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            std::unordered_set<std::string> inc_vars;
            collect_increments_block(stmt.body, inc_vars, true);

            std::unordered_set<std::string> uses;
            collect_stmt_uses_all(stmt, uses);

            for (const auto& name : inc_vars) {
                if (defined.find(name) != defined.end()) {
                    continue;
                }
                if (param_names.find(name) != param_names.end()) {
                    continue;
                }
                if (!local_names.empty()) {
                    if (local_names.find(name) == local_names.end() && !is_temp_like_name(name)) {
                        continue;
                    }
                } else if (!is_temp_like_name(name)) {
                    continue;
                }
                if (uses.find(name) == uses.end()) {
                    continue;
                }

                Stmt init;
                init.kind = StmtKind::kAssign;
                init.var.name = name;
                init.var.version = -1;
                init.expr = make_imm_expr(8, 0);
                stmts.insert(stmts.begin() + static_cast<std::ptrdiff_t>(i), std::move(init));
                defined.insert(name);
                ++i;
            }

            seed_uninit_loop_indices_block(stmt.body, local_names, param_names, defined);
            seed_uninit_loop_indices_block(stmt.then_body, local_names, param_names, defined);
            seed_uninit_loop_indices_block(stmt.else_body, local_names, param_names, defined);
            continue;
        }
    }
}

bool match_add_var_var(const mlil::MlilExpr& expr, std::string& a, std::string& b) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kAdd || expr.args.size() != 2) {
        return false;
    }
    if (expr.args[0].kind != mlil::MlilExprKind::kVar || expr.args[1].kind != mlil::MlilExprKind::kVar) {
        return false;
    }
    a = expr.args[0].var.name;
    b = expr.args[1].var.name;
    return !a.empty() && !b.empty();
}

bool match_load_base_index(const mlil::MlilExpr& expr, std::string& base, std::string& index) {
    if (expr.kind != mlil::MlilExprKind::kLoad || expr.args.empty()) {
        return false;
    }
    std::string lhs;
    std::string rhs;
    if (!match_add_var_var(expr.args[0], lhs, rhs)) {
        return false;
    }
    base = lhs;
    index = rhs;
    return true;
}

bool is_if_continue_only(const Stmt& stmt, mlil::MlilExpr& cond_out) {
    if (stmt.kind != StmtKind::kIf) {
        return false;
    }
    if (!stmt.else_body.empty()) {
        return false;
    }
    if (stmt.then_body.size() != 1 || stmt.then_body[0].kind != StmtKind::kContinue) {
        return false;
    }
    cond_out = stmt.condition;
    return true;
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

bool rewrite_compare_bound_expr(mlil::MlilExpr& expr, const std::string& index_var) {
    if (index_var.empty()) {
        return false;
    }
    if (expr.kind == mlil::MlilExprKind::kOp &&
        (expr.op == mlil::MlilOp::kAnd || expr.op == mlil::MlilOp::kOr) &&
        expr.args.size() == 2) {
        if (rewrite_compare_bound_expr(expr.args[0], index_var)) {
            return true;
        }
        if (rewrite_compare_bound_expr(expr.args[1], index_var)) {
            return true;
        }
        return false;
    }
    if (expr_uses_var(expr, index_var)) {
        return false;
    }
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() != 2 || !is_compare_op(expr.op)) {
        return false;
    }
    auto& lhs = expr.args[0];
    auto& rhs = expr.args[1];

    std::uint64_t imm = 0;
    bool lhs_one = get_imm_value(lhs, imm) && imm == 1;
    bool rhs_one = get_imm_value(rhs, imm) && imm == 1;
    if (!lhs_one && !rhs_one) {
        return false;
    }

    std::size_t size = 0;
    if (lhs.kind == mlil::MlilExprKind::kVar) {
        size = lhs.size != 0 ? lhs.size : lhs.var.size;
    } else if (rhs.kind == mlil::MlilExprKind::kVar) {
        size = rhs.size != 0 ? rhs.size : rhs.var.size;
    }
    if (size == 0) {
        size = 8;
    }

    mlil::MlilExpr idx = make_var_expr(index_var, size);
    mlil::MlilExpr one = make_imm_expr(size, 1);
    mlil::MlilExpr idx_plus = make_binary_expr(mlil::MlilOp::kAdd, size, std::move(idx), std::move(one));

    if (lhs_one) {
        lhs = std::move(idx_plus);
    } else {
        rhs = std::move(idx_plus);
    }
    return true;
}

bool try_rewrite_loop_bound(Stmt& stmt, const std::string& index_var) {
    return rewrite_compare_bound_expr(stmt.condition, index_var);
}

mlil::MlilExpr make_bool_and(mlil::MlilExpr lhs, mlil::MlilExpr rhs) {
    mlil::MlilExpr expr;
    expr.kind = mlil::MlilExprKind::kOp;
    expr.op = mlil::MlilOp::kAnd;
    expr.size = 1;
    expr.args.push_back(std::move(lhs));
    expr.args.push_back(std::move(rhs));
    return expr;
}

void normalize_string_copy_loops_block(std::vector<Stmt>& stmts) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            normalize_string_copy_loops_block(stmt.then_body);
            normalize_string_copy_loops_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            normalize_string_copy_loops_block(stmt.body);
            normalize_string_copy_loops_block(stmt.then_body);
            normalize_string_copy_loops_block(stmt.else_body);
        }
    }

    for (auto& stmt : stmts) {
        if (stmt.kind != StmtKind::kWhile) {
            continue;
        }
        int store_idx = -1;
        std::string store_src_base;
        std::string store_src_index;
        for (std::size_t i = 0; i < stmt.body.size(); ++i) {
            if (stmt.body[i].kind != StmtKind::kStore) {
                continue;
            }
            std::string src_base;
            std::string src_index;
            if (!match_load_base_index(stmt.body[i].expr, src_base, src_index)) {
                continue;
            }
            store_idx = static_cast<int>(i);
            store_src_base = std::move(src_base);
            store_src_index = std::move(src_index);
            break;
        }
        if (store_idx < 0) {
            continue;
        }

        int cont_idx = -1;
        mlil::MlilExpr cond_expr;
        for (std::size_t i = static_cast<std::size_t>(store_idx + 1); i < stmt.body.size(); ++i) {
            if (stmt.body[i].kind == StmtKind::kStore || stmt.body[i].kind == StmtKind::kCall) {
                break;
            }
            if (is_if_continue_only(stmt.body[i], cond_expr)) {
                std::string cond_base;
                std::string cond_index;
                if (match_load_base_index(cond_expr, cond_base, cond_index) &&
                    cond_base == store_src_base && cond_index == store_src_index) {
                    cont_idx = static_cast<int>(i);
                }
                break;
            }
        }
        if (cont_idx < 0) {
            continue;
        }

        try_rewrite_loop_bound(stmt, store_src_index);
        stmt.condition = make_bool_and(std::move(stmt.condition), stmt.body[static_cast<std::size_t>(store_idx)].expr);
        stmt.body.erase(stmt.body.begin() + cont_idx);
    }
}

bool find_loop_index_from_store(const std::vector<Stmt>& body, std::string& index_out) {
    std::unordered_set<std::string> inc_vars;
    collect_increments_block(body, inc_vars, true);
    if (inc_vars.empty()) {
        return false;
    }
    for (const auto& stmt : body) {
        if (stmt.kind != StmtKind::kStore) {
            continue;
        }
        std::unordered_set<std::string> vars;
        collect_expr_vars(stmt.target, vars);
        for (const auto& name : vars) {
            if (inc_vars.find(name) != inc_vars.end()) {
                index_out = name;
                return true;
            }
        }
    }
    return false;
}

void repair_loop_bounds_block(std::vector<Stmt>& stmts) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            repair_loop_bounds_block(stmt.then_body);
            repair_loop_bounds_block(stmt.else_body);
            continue;
        }
        if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            repair_loop_bounds_block(stmt.body);
            repair_loop_bounds_block(stmt.then_body);
            repair_loop_bounds_block(stmt.else_body);

            std::string index_var;
            if (find_loop_index_from_store(stmt.body, index_var)) {
                if (try_rewrite_loop_bound(stmt, index_var)) {
                    continue;
                }
            }

            // Fallback
            std::unordered_set<std::string> inc_vars;
            collect_increments_block(stmt.body, inc_vars, true);
            if (inc_vars.size() == 1) {
                const std::string& lone = *inc_vars.begin();
                if (!expr_uses_var(stmt.condition, lone)) {
                    try_rewrite_loop_bound(stmt, lone);
                }
            }
        }
    }
}

// Check if condition is a constant true (while(1))
bool is_constant_true_condition(const mlil::MlilExpr& cond) {
    if (cond.kind == mlil::MlilExprKind::kImm) {
        return cond.imm != 0;
    }
    return false;
}

// Invert a comparison operator
mlil::MlilOp invert_compare_op(mlil::MlilOp op) {
    switch (op) {
        case mlil::MlilOp::kLt: return mlil::MlilOp::kGe;
        case mlil::MlilOp::kLe: return mlil::MlilOp::kGt;
        case mlil::MlilOp::kGt: return mlil::MlilOp::kLe;
        case mlil::MlilOp::kGe: return mlil::MlilOp::kLt;
        case mlil::MlilOp::kEq: return mlil::MlilOp::kNe;
        case mlil::MlilOp::kNe: return mlil::MlilOp::kEq;
        default: return op;
    }
}

// Create an inverted condition expression
mlil::MlilExpr invert_loop_condition(const mlil::MlilExpr& cond) {
    mlil::MlilExpr out = cond;
    
    if (out.kind == mlil::MlilExprKind::kOp) {
        // Handle comparison operators directly
        if (is_compare_op(out.op)) {
            out.op = invert_compare_op(out.op);
            return out;
        }
        
        // Handle NOT - double negation elimination
        if (out.op == mlil::MlilOp::kNot && out.args.size() == 1) {
            return out.args[0];
        }
    }
    
    // Wrap in NOT for other cases
    mlil::MlilExpr not_expr;
    not_expr.kind = mlil::MlilExprKind::kOp;
    not_expr.op = mlil::MlilOp::kNot;
    not_expr.size = 1;
    not_expr.args.push_back(std::move(out));
    return not_expr;
}

// Try to extract a loop condition from a guard if-break pattern in the loop body
// Pattern: if (cond) break; -> loop condition is !cond
// Returns true if a guard was found and extracted
bool extract_guard_condition(std::vector<Stmt>& body, mlil::MlilExpr& out_cond) {
    if (body.empty()) {
        return false;
    }
    
    // Check first statement for pattern: if (!cond) break;
    // or: if (i >= limit) break;
    // This is common for for-loops compiled to while(1)
    Stmt& first = body[0];
    if (first.kind != StmtKind::kIf) {
        return false;
    }
    
    // Check if then_body contains only break
    if (first.then_body.size() != 1 || first.then_body[0].kind != StmtKind::kBreak) {
        return false;
    }
    
    // The loop condition is the inverse of the guard condition
    // if (i >= limit) break; -> loop while (i < limit)
    out_cond = invert_loop_condition(first.condition);
    
    // Remove the guard if from the body
    body.erase(body.begin());
    return true;
}

// Try to extract a loop condition from the last if statement that leads to continue/break
// Pattern: if (cond) { body; continue; } else { break; }
// -> while (cond) { body; }
bool extract_trailing_guard_condition(std::vector<Stmt>& body, mlil::MlilExpr& out_cond) {
    if (body.empty()) {
        return false;
    }
    
    // Check last statement
    Stmt& last = body.back();
    if (last.kind != StmtKind::kIf) {
        return false;
    }
    
    // Pattern 1: if (cond) { ... continue; } else { break; }
    bool then_has_continue = !last.then_body.empty() &&
                             last.then_body.back().kind == StmtKind::kContinue;
    bool else_has_break = !last.else_body.empty() &&
                          last.else_body.size() == 1 &&
                          last.else_body[0].kind == StmtKind::kBreak;
    
    if (then_has_continue && else_has_break) {
        out_cond = last.condition;
        // Remove the continue from then_body
        last.then_body.pop_back();
        // Move then_body contents into main body (replacing the if)
        std::vector<Stmt> new_body;
        new_body.reserve(body.size() - 1 + last.then_body.size());
        for (std::size_t i = 0; i + 1 < body.size(); ++i) {
            new_body.push_back(std::move(body[i]));
        }
        for (auto& stmt : last.then_body) {
            new_body.push_back(std::move(stmt));
        }
        body = std::move(new_body);
        return true;
    }
    
    // Pattern 2: if (!cond) break; (at the end, like a do-while check)
    bool then_only_break = last.then_body.size() == 1 &&
                           last.then_body[0].kind == StmtKind::kBreak &&
                           last.else_body.empty();
    
    if (then_only_break) {
        out_cond = invert_loop_condition(last.condition);
        body.pop_back();
        return true;
    }
    
    return false;
}

// Try to recover loop condition from a while(1) loop
// Returns true if a better condition was found
bool try_recover_loop_condition(Stmt& loop) {
    if (loop.kind != StmtKind::kWhile) {
        return false;
    }
    if (!is_constant_true_condition(loop.condition)) {
        return false;
    }
    if (loop.body.empty()) {
        return false;
    }
    
    // Try to extract condition from beginning guard: if (cond) break;
    mlil::MlilExpr guard_cond;
    if (extract_guard_condition(loop.body, guard_cond)) {
        loop.condition = std::move(guard_cond);
        return true;
    }
    
    // Try to extract condition from trailing guard
    if (extract_trailing_guard_condition(loop.body, guard_cond)) {
        loop.condition = std::move(guard_cond);
        return true;
    }
    
    return false;
}

void merge_while_to_for_block(std::vector<Stmt>& stmts) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            merge_while_to_for_block(stmt.then_body);
            merge_while_to_for_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            merge_while_to_for_block(stmt.body);
            merge_while_to_for_block(stmt.then_body);
            merge_while_to_for_block(stmt.else_body);
        }
    }
    
    // First pass: try to recover loop conditions for while(1) loops
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kWhile) {
            try_recover_loop_condition(stmt);
        }
    }

    for (std::size_t i = 0; i + 1 < stmts.size(); ++i) {
        Stmt& init = stmts[i];
        Stmt& loop = stmts[i + 1];
        if (init.kind != StmtKind::kAssign || init.var.name.empty()) {
            continue;
        }
        if (loop.kind != StmtKind::kWhile) {
            continue;
        }
        if (loop.body.empty()) {
            continue;
        }
        std::size_t last = loop.body.size() - 1;
        std::string inc_var;
        int delta = 0;
        if (!is_inc_stmt(loop.body[last], inc_var, delta) || inc_var != init.var.name) {
            continue;
        }
        bool modified = false;
        for (std::size_t k = 0; k < last; ++k) {
            if (stmt_defines_var(loop.body[k], inc_var)) {
                modified = true;
                break;
            }
        }
        if (modified) {
            continue;
        }

        Stmt for_stmt;
        for_stmt.kind = StmtKind::kFor;
        
        // Save init statement before moving
        Stmt init_copy = init;
        std::string inc_name = init.var.name;
        
        // Try to recover loop condition from while(1) loops
        if (is_constant_true_condition(loop.condition)) {
            mlil::MlilExpr guard_cond;
            // Make a copy of body before extracting (without the increment at the end)
            std::vector<Stmt> body_copy;
            body_copy.reserve(loop.body.size() - 1);
            for (std::size_t k = 0; k + 1 < loop.body.size(); ++k) {
                body_copy.push_back(loop.body[k]);
            }
            
            if (extract_guard_condition(body_copy, guard_cond)) {
                for_stmt.condition = std::move(guard_cond);
                // Use modified body (without guard and without increment)
                for_stmt.body = std::move(body_copy);
            } else if (extract_trailing_guard_condition(body_copy, guard_cond)) {
                for_stmt.condition = std::move(guard_cond);
                for_stmt.body = std::move(body_copy);
            } else {
                // Keep the while(1) condition but remove increment from body
                for_stmt.condition = loop.condition;
                for_stmt.body.reserve(loop.body.size() - 1);
                for (std::size_t k = 0; k + 1 < loop.body.size(); ++k) {
                    for_stmt.body.push_back(std::move(loop.body[k]));
                }
            }
        } else {
            // Normal while loop with proper condition
            for_stmt.condition = loop.condition;
            // Remove increment from body
            for_stmt.body.reserve(loop.body.size() - 1);
            for (std::size_t k = 0; k + 1 < loop.body.size(); ++k) {
                for_stmt.body.push_back(std::move(loop.body[k]));
            }
        }
        
        // then_body holds the initialization statement
        for_stmt.then_body.clear();
        for_stmt.then_body.push_back(std::move(init_copy));
        
        // else_body holds the step/increment statement
        // Reconstruct the increment statement
        Stmt inc_stmt;
        inc_stmt.kind = StmtKind::kAssign;
        inc_stmt.var.name = inc_name;
        inc_stmt.var.version = -1;
        mlil::MlilExpr inc_expr;
        inc_expr.kind = mlil::MlilExprKind::kOp;
        inc_expr.op = (delta > 0) ? mlil::MlilOp::kAdd : mlil::MlilOp::kSub;
        inc_expr.size = 8;
        mlil::MlilExpr var_expr;
        var_expr.kind = mlil::MlilExprKind::kVar;
        var_expr.var.name = inc_name;
        var_expr.var.version = -1;
        var_expr.size = 8;
        mlil::MlilExpr one_expr;
        one_expr.kind = mlil::MlilExprKind::kImm;
        one_expr.imm = 1;
        one_expr.size = 8;
        inc_expr.args.push_back(std::move(var_expr));
        inc_expr.args.push_back(std::move(one_expr));
        inc_stmt.expr = std::move(inc_expr);
        
        for_stmt.else_body.clear();
        for_stmt.else_body.push_back(std::move(inc_stmt));

        stmts.erase(stmts.begin() + static_cast<std::ptrdiff_t>(i + 1));
        stmts[i] = std::move(for_stmt);
    }
}

} // namespace

void normalize_post_increments(Function& function) {
    normalize_post_increments_block(function.stmts);
}

void seed_uninit_loop_indices(Function& function) {
    std::unordered_set<std::string> local_names;
    for (const auto& local : function.locals) {
        local_names.insert(local.name);
    }
    std::unordered_set<std::string> param_names;
    for (const auto& param : function.params) {
        param_names.insert(param.name);
    }
    std::unordered_set<std::string> defined;
    for (const auto& param : function.params) {
        defined.insert(param.name);
    }
    seed_uninit_loop_indices_block(function.stmts, local_names, param_names, defined);
}

void normalize_string_copy_loops(Function& function) {
    normalize_string_copy_loops_block(function.stmts);
}

void repair_loop_bounds(Function& function) {
    repair_loop_bounds_block(function.stmts);
}

void merge_while_to_for(Function& function) {
    merge_while_to_for_block(function.stmts);
}

} // namespace engine::decompiler