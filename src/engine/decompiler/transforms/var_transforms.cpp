#include "engine/decompiler/transforms.h"

#include <algorithm>
#include <functional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace engine::decompiler {

namespace {

struct TempState {
    std::unordered_set<std::string> used_names;
    int counter = 0;
};

std::string type_for_size(std::size_t size) {
    switch (size) {
        case 1: return "uint8_t";
        case 2: return "uint16_t";
        case 4: return "uint32_t";
        case 8: return "uint64_t";
        default: return "auto";
    }
}

std::string next_temp_name(TempState& state) {
    while (true) {
        std::string name = "tmp" + std::to_string(state.counter++);
        if (state.used_names.insert(name).second) {
            return name;
        }
    }
}

void collect_exprs(const mlil::MlilExpr& expr,
                   std::unordered_map<std::string, int>& counts,
                   std::unordered_map<std::string, mlil::MlilExpr>& reps,
                   std::unordered_map<std::string, int>& costs) {
    if (is_pure_expr(expr)) {
        const std::string key = expr_key(expr);
        if (!key.empty()) {
            counts[key]++;
            reps.emplace(key, expr);
            costs.emplace(key, expr_cost(expr));
        }
    }
    for (const auto& arg : expr.args) {
        collect_exprs(arg, counts, reps, costs);
    }
}

void collect_stmt_exprs(const Stmt& stmt,
                        std::unordered_map<std::string, int>& counts,
                        std::unordered_map<std::string, mlil::MlilExpr>& reps,
                        std::unordered_map<std::string, int>& costs) {
    collect_exprs(stmt.expr, counts, reps, costs);
    collect_exprs(stmt.target, counts, reps, costs);
    collect_exprs(stmt.condition, counts, reps, costs);
    for (const auto& arg : stmt.args) {
        collect_exprs(arg, counts, reps, costs);
    }
}

void collect_var_names(const mlil::MlilExpr& expr, std::unordered_set<std::string>& out) {
    if (expr.kind == mlil::MlilExprKind::kVar && !expr.var.name.empty()) {
        out.insert(expr.var.name);
        return;
    }
    for (const auto& arg : expr.args) {
        collect_var_names(arg, out);
    }
}

bool is_simple_offset_expr(const mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() != 2) {
        return false;
    }
    if (expr.op != mlil::MlilOp::kAdd && expr.op != mlil::MlilOp::kSub) {
        return false;
    }
    return is_var_or_imm(expr.args[0]) && is_var_or_imm(expr.args[1]);
}

bool is_simple_address_expr(const mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() != 2 || expr.op != mlil::MlilOp::kAdd) {
        return false;
    }
    return (is_var_or_imm(expr.args[0]) && is_simple_offset_expr(expr.args[1])) ||
           (is_var_or_imm(expr.args[1]) && is_simple_offset_expr(expr.args[0]));
}

bool is_simple_cse_expr(const mlil::MlilExpr& expr) {
    if (expr.kind == mlil::MlilExprKind::kImm || expr.kind == mlil::MlilExprKind::kVar) {
        return true;
    }
    return is_simple_offset_expr(expr) || is_simple_address_expr(expr);
}

struct AvailableExpr {
    mlil::MlilExpr temp;
    std::unordered_set<std::string> deps;
};

void materialize_segment(std::vector<Stmt>& segment, Function& function, TempState& state, std::vector<Stmt>& out) {
    if (segment.empty()) {
        return;
    }
    std::unordered_map<std::string, int> counts;
    std::unordered_map<std::string, mlil::MlilExpr> reps;
    std::unordered_map<std::string, int> costs;
    for (const auto& stmt : segment) {
        collect_stmt_exprs(stmt, counts, reps, costs);
    }

    const int kRepeatCost = 3;
    const int kComplexCost = 6;

    auto should_materialize = [&](const std::string& key) -> bool {
        if (key.empty()) {
            return false;
        }
        auto rep_it = reps.find(key);
        if (rep_it != reps.end() && is_simple_cse_expr(rep_it->second)) {
            return false;
        }
        auto count_it = counts.find(key);
        if (count_it == counts.end()) {
            return false;
        }
        const int count = count_it->second;
        const int cost = costs[key];
        return cost >= kComplexCost || (count >= 2 && cost >= kRepeatCost);
    };

    std::unordered_map<std::string, AvailableExpr> available;

    auto invalidate_available = [&](const std::unordered_set<std::string>& names) {
        if (names.empty()) {
            return;
        }
        for (auto it = available.begin(); it != available.end();) {
            bool kill = false;
            for (const auto& name : names) {
                if (it->second.deps.find(name) != it->second.deps.end()) {
                    kill = true;
                    break;
                }
            }
            if (kill) {
                it = available.erase(it);
            } else {
                ++it;
            }
        }
    };

    std::function<void(mlil::MlilExpr&, std::vector<Stmt>&)> materialize_expr;
    materialize_expr = [&](mlil::MlilExpr& expr, std::vector<Stmt>& pre) {
        if (is_pure_expr(expr)) {
            const std::string key = expr_key(expr);
            if (!key.empty()) {
                auto it = available.find(key);
                if (it != available.end()) {
                    expr = it->second.temp;
                    return;
                }
                if (should_materialize(key)) {
                    auto rep_it = reps.find(key);
                    if (rep_it != reps.end()) {
                        const mlil::MlilExpr& rep = rep_it->second;
                        std::string name = next_temp_name(state);
                        VarDecl local;
                        local.name = name;
                        local.type = type_for_size(rep.size);
                        function.locals.push_back(local);

                        Stmt assign;
                        assign.kind = StmtKind::kAssign;
                        assign.var.name = name;
                        assign.var.version = -1;
                        assign.var.size = rep.size;
                        assign.expr = rep;
                        pre.push_back(assign);

                        AvailableExpr entry;
                        entry.temp = make_var_expr(name, rep.size);
                        collect_var_names(rep, entry.deps);
                        available.emplace(key, entry);

                        expr = entry.temp;
                        return;
                    }
                }
            }
        }
        for (auto& arg : expr.args) {
            materialize_expr(arg, pre);
        }
    };

    for (auto& stmt : segment) {
        std::vector<Stmt> pre;

        switch (stmt.kind) {
            case StmtKind::kAssign:
                materialize_expr(stmt.expr, pre);
                break;
            case StmtKind::kStore:
                materialize_expr(stmt.target, pre);
                materialize_expr(stmt.expr, pre);
                break;
            case StmtKind::kCall:
                materialize_expr(stmt.target, pre);
                for (auto& arg : stmt.args) {
                    materialize_expr(arg, pre);
                }
                break;
            case StmtKind::kReturn:
                materialize_expr(stmt.expr, pre);
                break;
            default:
                materialize_expr(stmt.expr, pre);
                materialize_expr(stmt.target, pre);
                break;
        }

        for (auto& add : pre) {
            out.push_back(std::move(add));
        }
        out.push_back(std::move(stmt));

        std::unordered_set<std::string> modified;
        if (out.back().kind == StmtKind::kAssign && !out.back().var.name.empty()) {
            modified.insert(out.back().var.name);
        } else if (out.back().kind == StmtKind::kCall) {
            for (const auto& ret : out.back().returns) {
                if (!ret.name.empty()) {
                    modified.insert(ret.name);
                }
            }
        }
        invalidate_available(modified);
    }
}

void materialize_block(std::vector<Stmt>& stmts, Function& function, TempState& state) {
    std::vector<Stmt> out;
    std::vector<Stmt> segment;

    auto flush_segment = [&]() {
        materialize_segment(segment, function, state, out);
        segment.clear();
    };

    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            materialize_block(stmt.then_body, function, state);
            materialize_block(stmt.else_body, function, state);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            materialize_block(stmt.body, function, state);
            materialize_block(stmt.then_body, function, state);
            materialize_block(stmt.else_body, function, state);
        }

        if (is_control_stmt(stmt)) {
            flush_segment();
            out.push_back(std::move(stmt));
        } else {
            segment.push_back(std::move(stmt));
        }
    }
    flush_segment();
    stmts = std::move(out);
}

bool expr_is_inlineable(const mlil::MlilExpr& expr) {
    if (is_pure_expr(expr)) {
        return true;
    }
    if (expr.kind == mlil::MlilExprKind::kLoad && !expr.args.empty()) {
        return is_pure_expr(expr.args.front());
    }
    if (expr.kind == mlil::MlilExprKind::kCall) {
        // Calls can be inlined if their arguments are inlineable
        // The call itself has side effects, which are handled by the caller checking dependencies
        for (const auto& arg : expr.args) {
            if (!expr_is_inlineable(arg)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool expr_has_load(const mlil::MlilExpr& expr) {
    if (expr.kind == mlil::MlilExprKind::kLoad || expr.kind == mlil::MlilExprKind::kCall) {
        return true;
    }
    for (const auto& arg : expr.args) {
        if (expr_has_load(arg)) {
            return true;
        }
    }
    return false;
}

bool stmt_modifies_any(const Stmt& stmt, const std::unordered_set<std::string>& deps) {
    if (deps.empty()) {
        return false;
    }
    if (stmt.kind == StmtKind::kAssign) {
        return deps.find(stmt.var.name) != deps.end();
    }
    if (stmt.kind == StmtKind::kCall) {
        for (const auto& ret : stmt.returns) {
            if (deps.find(ret.name) != deps.end()) {
                return true;
            }
        }
    }
    return false;
}

bool is_block_boundary(const Stmt& stmt) {
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

bool stmt_uses_var_in_condition(const Stmt& stmt, const std::string& name) {
    switch (stmt.kind) {
        case StmtKind::kIf:
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
        case StmtKind::kFor:
            return expr_uses_var(stmt.condition, name);
        case StmtKind::kReturn:
            return expr_uses_var(stmt.expr, name);
        default:
            return false;
    }
}

bool stmt_uses_var_in_body(const Stmt& stmt, const std::string& name) {
    if (stmt.kind == StmtKind::kIf) {
        for (const auto& inner : stmt.then_body) {
            if (stmt_uses_var(inner, name)) {
                return true;
            }
        }
        for (const auto& inner : stmt.else_body) {
            if (stmt_uses_var(inner, name)) {
                return true;
            }
        }
    } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
        for (const auto& inner : stmt.body) {
            if (stmt_uses_var(inner, name)) {
                return true;
            }
        }
        for (const auto& inner : stmt.then_body) {
            if (stmt_uses_var(inner, name)) {
                return true;
            }
        }
        for (const auto& inner : stmt.else_body) {
            if (stmt_uses_var(inner, name)) {
                return true;
            }
        }
    }
    return false;
}

void replace_var_in_expr(mlil::MlilExpr& expr, const std::string& name, const mlil::MlilExpr& replacement) {
    if (expr.kind == mlil::MlilExprKind::kVar && expr.var.name == name) {
        expr = replacement;
        return;
    }
    for (auto& arg : expr.args) {
        replace_var_in_expr(arg, name, replacement);
    }
}

void replace_var_in_stmt(Stmt& stmt, const std::string& name, const mlil::MlilExpr& replacement) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            replace_var_in_expr(stmt.expr, name, replacement);
            break;
        case StmtKind::kStore:
            replace_var_in_expr(stmt.target, name, replacement);
            replace_var_in_expr(stmt.expr, name, replacement);
            break;
        case StmtKind::kCall:
            replace_var_in_expr(stmt.target, name, replacement);
            for (auto& arg : stmt.args) {
                replace_var_in_expr(arg, name, replacement);
            }
            break;
        case StmtKind::kReturn:
            replace_var_in_expr(stmt.expr, name, replacement);
            break;
        case StmtKind::kIf:
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
        case StmtKind::kFor:
            replace_var_in_expr(stmt.condition, name, replacement);
            break;
        default:
            break;
    }
}

void inline_temps_block(std::vector<Stmt>& stmts) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            inline_temps_block(stmt.then_body);
            inline_temps_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            inline_temps_block(stmt.body);
            inline_temps_block(stmt.then_body);
            inline_temps_block(stmt.else_body);
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::size_t i = 0; i < stmts.size(); ++i) {
            Stmt& stmt = stmts[i];
            std::string var_name;
            mlil::MlilExpr expr_to_inline;

            if (stmt.kind == StmtKind::kAssign) {
                if (stmt.var.name.empty()) continue;
                var_name = stmt.var.name;
                expr_to_inline = stmt.expr;
            } else if (stmt.kind == StmtKind::kCall) {
                if (stmt.returns.size() != 1) continue;
                if (stmt.returns[0].name.empty()) continue;
                var_name = stmt.returns[0].name;
                
                // Construct call expression
                expr_to_inline.kind = mlil::MlilExprKind::kCall;
                expr_to_inline.args.push_back(stmt.target); // First arg is target
                for (const auto& arg : stmt.args) {
                    expr_to_inline.args.push_back(arg);
                }
                // Size of call expr is size of return value
                expr_to_inline.size = stmt.returns[0].size;
            } else {
                continue;
            }

            if (var_name.empty()) {
                continue;
            }
            if (!expr_is_inlineable(expr_to_inline)) {
                continue;
            }
            if (expr_to_inline.kind == mlil::MlilExprKind::kVar && expr_to_inline.var.name == var_name) {
                continue;
            }
            if (expr_uses_var(expr_to_inline, var_name)) {
                continue;
            }

            std::unordered_set<std::string> deps;
            collect_expr_vars(expr_to_inline, deps);
            // Calls have side effects (memory load/store) so treat as load
            const bool has_load = expr_has_load(expr_to_inline);

            int use_index = -1;
            for (std::size_t j = i + 1; j < stmts.size(); ++j) {
                Stmt& next = stmts[j];
                if (stmt_defines_var(next, var_name)) {
                    break;
                }
                if (stmt_modifies_any(next, deps)) {
                    break;
                }
                if (has_load && (next.kind == StmtKind::kStore || next.kind == StmtKind::kCall)) {
                    if (stmt_uses_var(next, var_name) && use_index == -1) {
                        use_index = static_cast<int>(j);
                    }
                    break;
                }
                if (stmt_uses_var(next, var_name)) {
                    if (use_index != -1) {
                        use_index = -2;
                        break;
                    }
                    use_index = static_cast<int>(j);
                }
                if (is_block_boundary(next)) {
                    if (use_index == -1 && stmt_uses_var_in_condition(next, var_name) &&
                        !stmt_uses_var_in_body(next, var_name)) {
                        use_index = static_cast<int>(j);
                    }
                    break;
                }
            }

            if (use_index >= 0) {
                replace_var_in_stmt(stmts[static_cast<std::size_t>(use_index)], var_name, expr_to_inline);
                stmts.erase(stmts.begin() + static_cast<std::ptrdiff_t>(i));
                changed = true;
                break;
            }
        }
    }
}

bool match_assign_var_expr(const Stmt& stmt, std::string& name, mlil::MlilExpr& expr) {
    if (stmt.kind != StmtKind::kAssign) {
        return false;
    }
    if (stmt.var.name.empty()) {
        return false;
    }
    name = stmt.var.name;
    expr = stmt.expr;
    return true;
}

void fold_store_address_temps_block(std::vector<Stmt>& stmts) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            fold_store_address_temps_block(stmt.then_body);
            fold_store_address_temps_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            fold_store_address_temps_block(stmt.body);
            fold_store_address_temps_block(stmt.then_body);
            fold_store_address_temps_block(stmt.else_body);
        }
    }

    for (std::size_t i = 0; i + 1 < stmts.size(); ++i) {
        std::string name;
        mlil::MlilExpr expr;
        if (!match_assign_var_expr(stmts[i], name, expr)) {
            continue;
        }
        if (!expr_is_inlineable(expr)) {
            continue;
        }
        if (expr_uses_var(expr, name)) {
            continue;
        }
        Stmt& next = stmts[i + 1];
        if (next.kind != StmtKind::kStore) {
            continue;
        }
        if (!stmt_uses_var(next, name)) {
            continue;
        }
        replace_var_in_stmt(next, name, expr);
        stmts.erase(stmts.begin() + static_cast<std::ptrdiff_t>(i));
        if (i > 0) {
            --i;
        }
    }
}

void collect_expr_uses(const mlil::MlilExpr& expr, std::unordered_set<std::string>& used) {
    if (expr.kind == mlil::MlilExprKind::kVar && !expr.var.name.empty()) {
        used.insert(expr.var.name);
    }
    for (const auto& arg : expr.args) {
        collect_expr_uses(arg, used);
    }
}

void collect_stmt_def_counts(const Stmt& stmt, std::unordered_map<std::string, int>& counts) {
    if (stmt.kind == StmtKind::kAssign) {
        if (!stmt.var.name.empty()) {
            counts[stmt.var.name]++;
        }
    } else if (stmt.kind == StmtKind::kCall) {
        for (const auto& ret : stmt.returns) {
            if (!ret.name.empty()) {
                counts[ret.name]++;
            }
        }
    }
    if (stmt.kind == StmtKind::kIf || stmt.kind == StmtKind::kWhile ||
        stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
        for (const auto& inner : stmt.then_body) {
            collect_stmt_def_counts(inner, counts);
        }
        for (const auto& inner : stmt.else_body) {
            collect_stmt_def_counts(inner, counts);
        }
        for (const auto& inner : stmt.body) {
            collect_stmt_def_counts(inner, counts);
        }
    }
}

void collect_modified_vars_pseudoc(const std::vector<Stmt>& stmts, std::unordered_set<std::string>& out) {
    for (const auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kAssign && !stmt.var.name.empty()) {
            out.insert(stmt.var.name);
        } else if (stmt.kind == StmtKind::kCall) {
            for (const auto& ret : stmt.returns) {
                if (!ret.name.empty()) {
                    out.insert(ret.name);
                }
            }
        } else if (stmt.kind == StmtKind::kIf) {
            collect_modified_vars_pseudoc(stmt.then_body, out);
            collect_modified_vars_pseudoc(stmt.else_body, out);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            collect_modified_vars_pseudoc(stmt.body, out);
            collect_modified_vars_pseudoc(stmt.then_body, out);
            collect_modified_vars_pseudoc(stmt.else_body, out);
        }
    }
}

struct AvailExprInfo {
    mlil::MlilExpr expr;
    std::unordered_set<std::string> deps;
    std::string key;
};

bool expr_depends_on(const std::unordered_set<std::string>& deps, const std::string& name) {
    return deps.find(name) != deps.end();
}

// Helper to check if expression contains self-reference (would create x^x pattern)
bool expr_contains_self_ref(const mlil::MlilExpr& expr, const std::string& var_name) {
    if (expr.kind == mlil::MlilExprKind::kVar && expr.var.name == var_name) {
        return true;
    }
    for (const auto& arg : expr.args) {
        if (expr_contains_self_ref(arg, var_name)) {
            return true;
        }
    }
    return false;
}

void substitute_expr_with_avail(mlil::MlilExpr& expr,
                                const std::unordered_map<std::string, AvailExprInfo>& avail,
                                const std::unordered_map<std::string, int>& def_counts,
                                int depth = 0) {
    if (depth > 12) {
        return;
    }
    if (expr.kind == mlil::MlilExprKind::kVar && !expr.var.name.empty()) {
        auto def_it = def_counts.find(expr.var.name);
        if (def_it != def_counts.end() && def_it->second > 1) {
            return;
        }
        auto it = avail.find(expr.var.name);
        if (it != avail.end()) {
            // Prevent self-referential substitution that would create x^x patterns
            // E.g., if h = h ^ input, and we try to substitute h with (h ^ input),
            // we'd get (h ^ input) ^ input which still contains h -> infinite loop
            if (expr_contains_self_ref(it->second.expr, expr.var.name)) {
                return;
            }
            expr = it->second.expr;
            substitute_expr_with_avail(expr, avail, def_counts, depth + 1);
            return;
        }
    }
    for (auto& arg : expr.args) {
        substitute_expr_with_avail(arg, avail, def_counts, depth + 1);
    }
}

void substitute_stmt_with_avail(Stmt& stmt,
                                const std::unordered_map<std::string, AvailExprInfo>& avail,
                                const std::unordered_map<std::string, int>& def_counts) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            substitute_expr_with_avail(stmt.expr, avail, def_counts);
            break;
        case StmtKind::kStore:
            substitute_expr_with_avail(stmt.target, avail, def_counts);
            substitute_expr_with_avail(stmt.expr, avail, def_counts);
            break;
        case StmtKind::kCall:
            substitute_expr_with_avail(stmt.target, avail, def_counts);
            for (auto& arg : stmt.args) {
                substitute_expr_with_avail(arg, avail, def_counts);
            }
            break;
        case StmtKind::kReturn:
            substitute_expr_with_avail(stmt.expr, avail, def_counts);
            break;
        case StmtKind::kIf:
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
        case StmtKind::kFor:
            substitute_expr_with_avail(stmt.condition, avail, def_counts);
            break;
        default:
            break;
    }
}

bool avail_entry_equals(const AvailExprInfo& a, const AvailExprInfo& b) {
    if (a.key.empty() || b.key.empty()) {
        return false;
    }
    return a.key == b.key;
}

void avail_kill_on_defs(std::unordered_map<std::string, AvailExprInfo>& avail,
                        const std::unordered_set<std::string>& defs) {
    if (defs.empty()) {
        return;
    }
    for (auto it = avail.begin(); it != avail.end();) {
        bool kill = false;
        for (const auto& name : defs) {
            if (expr_depends_on(it->second.deps, name) || it->first == name) {
                kill = true;
                break;
            }
        }
        if (kill) {
            it = avail.erase(it);
        } else {
            ++it;
        }
    }
}

void propagate_pseudoc_block(std::vector<Stmt>& stmts,
                             std::unordered_map<std::string, AvailExprInfo>& avail,
                             const std::unordered_map<std::string, int>& def_counts) {
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            substitute_stmt_with_avail(stmt, avail, def_counts);
            auto then_avail = avail;
            auto else_avail = avail;
            propagate_pseudoc_block(stmt.then_body, then_avail, def_counts);
            propagate_pseudoc_block(stmt.else_body, else_avail, def_counts);
            std::unordered_map<std::string, AvailExprInfo> merged;
            for (const auto& entry : then_avail) {
                auto it = else_avail.find(entry.first);
                if (it != else_avail.end() && avail_entry_equals(entry.second, it->second)) {
                    merged[entry.first] = entry.second;
                }
            }
            avail = std::move(merged);
            continue;
        }

        if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            std::unordered_set<std::string> loop_mod;
            collect_modified_vars_pseudoc(stmt.body, loop_mod);
            if (stmt.kind == StmtKind::kFor) {
                collect_modified_vars_pseudoc(stmt.then_body, loop_mod);
                collect_modified_vars_pseudoc(stmt.else_body, loop_mod);
            }
            auto cond_avail = avail;
            avail_kill_on_defs(cond_avail, loop_mod);
            simplify_expr(stmt.condition);

            auto body_avail = cond_avail;
            avail_kill_on_defs(body_avail, loop_mod);
            propagate_pseudoc_block(stmt.body, body_avail, def_counts);
            propagate_pseudoc_block(stmt.then_body, body_avail, def_counts);
            propagate_pseudoc_block(stmt.else_body, body_avail, def_counts);

            avail_kill_on_defs(avail, loop_mod);
            continue;
        }

        substitute_stmt_with_avail(stmt, avail, def_counts);

        if (stmt.kind == StmtKind::kAssign && !stmt.var.name.empty()) {
            const std::string name = stmt.var.name;
            std::unordered_set<std::string> defs;
            defs.insert(name);
            avail_kill_on_defs(avail, defs);

            auto def_it = def_counts.find(name);
            if (def_it == def_counts.end() || def_it->second <= 1) {
                if (is_pure_expr(stmt.expr)) {
                    std::unordered_set<std::string> deps;
                    collect_expr_vars(stmt.expr, deps);
                    if (!expr_depends_on(deps, name)) {
                        AvailExprInfo entry;
                        entry.expr = stmt.expr;
                        entry.deps = std::move(deps);
                        entry.key = expr_key(stmt.expr);
                        avail[name] = std::move(entry);
                    }
                }
            }
        } else if (stmt.kind == StmtKind::kCall) {
            std::unordered_set<std::string> defs;
            for (const auto& ret : stmt.returns) {
                if (!ret.name.empty()) {
                    defs.insert(ret.name);
                }
            }
            avail_kill_on_defs(avail, defs);
        }
    }
}

} // namespace

void materialize_temporaries(Function& function) {
    TempState state;
    for (const auto& param : function.params) {
        state.used_names.insert(param.name);
    }
    for (const auto& local : function.locals) {
        state.used_names.insert(local.name);
    }
    materialize_block(function.stmts, function, state);
}

void inline_trivial_temps(Function& function) {
    inline_temps_block(function.stmts);
}

void fold_store_address_temps(Function& function) {
    fold_store_address_temps_block(function.stmts);
}

void propagate_pseudoc_exprs(Function& function) {
    std::unordered_map<std::string, int> def_counts;
    for (const auto& stmt : function.stmts) {
        collect_stmt_def_counts(stmt, def_counts);
    }
    std::unordered_map<std::string, AvailExprInfo> avail;
    propagate_pseudoc_block(function.stmts, avail, def_counts);
}

namespace {

// P2: Decompose complex expressions in return statements
// This helps with cases like xorshift32 where a single return contains
// a massive nested expression that should be broken into steps

int deep_expr_cost(const mlil::MlilExpr& expr) {
    if (expr.kind == mlil::MlilExprKind::kImm || expr.kind == mlil::MlilExprKind::kVar) {
        return 1;
    }
    int cost = 1;
    for (const auto& arg : expr.args) {
        cost += deep_expr_cost(arg);
    }
    return cost;
}

void find_repeated_subexprs(const mlil::MlilExpr& expr,
                             std::unordered_map<std::string, int>& counts,
                             std::unordered_map<std::string, mlil::MlilExpr>& reps,
                             int min_cost = 4) {
    if (expr.kind == mlil::MlilExprKind::kImm || expr.kind == mlil::MlilExprKind::kVar) {
        return;
    }
    
    // First recurse into children
    for (const auto& arg : expr.args) {
        find_repeated_subexprs(arg, counts, reps, min_cost);
    }
    
    // Check this expression
    if (is_pure_expr(expr) && deep_expr_cost(expr) >= min_cost) {
        const std::string key = expr_key(expr);
        if (!key.empty()) {
            counts[key]++;
            reps.emplace(key, expr);
        }
    }
}

void replace_subexpr_with_var(mlil::MlilExpr& expr,
                               const std::string& key,
                               const mlil::MlilExpr& replacement) {
    if (is_pure_expr(expr)) {
        const std::string this_key = expr_key(expr);
        if (this_key == key) {
            expr = replacement;
            return;
        }
    }
    for (auto& arg : expr.args) {
        replace_subexpr_with_var(arg, key, replacement);
    }
}

void decompose_complex_return_block(std::vector<Stmt>& stmts, Function& function, TempState& state) {
    // Process nested structures first
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            decompose_complex_return_block(stmt.then_body, function, state);
            decompose_complex_return_block(stmt.else_body, function, state);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            decompose_complex_return_block(stmt.body, function, state);
        }
    }
    
    std::vector<Stmt> new_stmts;
    const int kComplexThreshold = 15;  // Expression cost threshold for decomposition
    const int kSubexprMinCost = 4;     // Minimum cost for subexpression extraction
    
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kReturn && stmt.expr.kind != mlil::MlilExprKind::kInvalid) {
            int cost = deep_expr_cost(stmt.expr);
            if (cost >= kComplexThreshold) {
                // Find repeated subexpressions
                std::unordered_map<std::string, int> counts;
                std::unordered_map<std::string, mlil::MlilExpr> reps;
                find_repeated_subexprs(stmt.expr, counts, reps, kSubexprMinCost);
                
                // Extract subexpressions that appear more than once
                std::vector<std::pair<std::string, mlil::MlilExpr>> to_extract;
                for (const auto& [key, count] : counts) {
                    if (count >= 2) {
                        auto it = reps.find(key);
                        if (it != reps.end()) {
                            to_extract.push_back({key, it->second});
                        }
                    }
                }
                
                // Sort by cost (extract most complex first)
                std::sort(to_extract.begin(), to_extract.end(),
                    [](const auto& a, const auto& b) {
                        return deep_expr_cost(a.second) > deep_expr_cost(b.second);
                    });
                
                // Extract up to 3 subexpressions to avoid too many temps
                int extracted = 0;
                for (const auto& [key, subexpr] : to_extract) {
                    if (extracted >= 3) break;
                    
                    // Create temporary variable
                    std::string temp_name = next_temp_name(state);
                    VarDecl local;
                    local.name = temp_name;
                    local.type = type_for_size(subexpr.size);
                    function.locals.push_back(local);
                    
                    // Create assignment
                    Stmt assign;
                    assign.kind = StmtKind::kAssign;
                    assign.var.name = temp_name;
                    assign.var.version = -1;
                    assign.var.size = subexpr.size;
                    assign.expr = subexpr;
                    new_stmts.push_back(assign);
                    
                    // Replace in return expression
                    mlil::MlilExpr var_expr = make_var_expr(temp_name, subexpr.size);
                    replace_subexpr_with_var(stmt.expr, key, var_expr);
                    
                    extracted++;
                }
            }
        }
        new_stmts.push_back(std::move(stmt));
    }
    
    stmts = std::move(new_stmts);
}

} // namespace

void decompose_complex_return_exprs(Function& function) {
    TempState state;
    for (const auto& param : function.params) {
        state.used_names.insert(param.name);
    }
    for (const auto& local : function.locals) {
        state.used_names.insert(local.name);
    }
    decompose_complex_return_block(function.stmts, function, state);
}

namespace {

// Get base variable name (strip SSA version suffix like _v0, _v1, etc.)
std::string get_base_var_name(const std::string& name) {
    if (name.empty()) {
        return name;
    }
    // Find pattern like _v followed by digits at the end
    std::size_t pos = name.rfind("_v");
    if (pos != std::string::npos && pos + 2 < name.size()) {
        bool all_digits = true;
        for (std::size_t i = pos + 2; i < name.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(name[i]))) {
                all_digits = false;
                break;
            }
        }
        if (all_digits) {
            return name.substr(0, pos);
        }
    }
    return name;
}

// Check if an assignment is redundant (x = x pattern)
bool is_redundant_assignment(const Stmt& stmt) {
    if (stmt.kind != StmtKind::kAssign) {
        return false;
    }
    if (stmt.var.name.empty()) {
        return false;
    }
    // Check if expr is just the same variable
    if (stmt.expr.kind != mlil::MlilExprKind::kVar) {
        return false;
    }
    if (stmt.expr.var.name.empty()) {
        return false;
    }
    // Compare base names (ignoring SSA version suffixes)
    std::string base_var = get_base_var_name(stmt.var.name);
    std::string base_expr = get_base_var_name(stmt.expr.var.name);
    return base_var == base_expr;
}

// Check if an assignment is effectively a no-op identity operation
// E.g., x = (x + 0), x = (x | 0), x = (x ^ 0), x = (x * 1), x = (x & 0xFFFFFFFF)
bool is_identity_assignment(const Stmt& stmt) {
    if (stmt.kind != StmtKind::kAssign) {
        return false;
    }
    if (stmt.var.name.empty()) {
        return false;
    }
    
    // Check for binary operations that are identity
    if (stmt.expr.kind != mlil::MlilExprKind::kOp || stmt.expr.args.size() != 2) {
        return false;
    }
    
    const auto& lhs = stmt.expr.args[0];
    const auto& rhs = stmt.expr.args[1];
    
    // Check if one side is the variable being assigned to
    bool lhs_is_var = (lhs.kind == mlil::MlilExprKind::kVar && lhs.var.name == stmt.var.name);
    bool rhs_is_var = (rhs.kind == mlil::MlilExprKind::kVar && rhs.var.name == stmt.var.name);
    
    if (!lhs_is_var && !rhs_is_var) {
        return false;
    }
    
    std::uint64_t imm_val = 0;
    bool other_is_imm = false;
    
    if (lhs_is_var) {
        other_is_imm = get_imm_value(rhs, imm_val);
    } else {
        other_is_imm = get_imm_value(lhs, imm_val);
    }
    
    if (!other_is_imm) {
        return false;
    }
    
    switch (stmt.expr.op) {
        case mlil::MlilOp::kAdd:
        case mlil::MlilOp::kSub:
        case mlil::MlilOp::kOr:
        case mlil::MlilOp::kXor:
        case mlil::MlilOp::kShl:
        case mlil::MlilOp::kShr:
        case mlil::MlilOp::kSar:
            // x + 0, x - 0, x | 0, x ^ 0, x << 0, x >> 0 are identity
            return imm_val == 0;
        case mlil::MlilOp::kMul:
            // x * 1 is identity
            return imm_val == 1;
        case mlil::MlilOp::kAnd:
            // x & all_ones is identity (depends on size)
            if (stmt.expr.size <= 8) {
                std::uint64_t all_ones = (stmt.expr.size == 8) ?
                    0xFFFFFFFFFFFFFFFFULL :
                    ((1ULL << (stmt.expr.size * 8)) - 1);
                return imm_val == all_ones;
            }
            return false;
        default:
            return false;
    }
}

// Check if condition is a constant false (0)
bool is_constant_false(const mlil::MlilExpr& cond) {
    if (cond.kind == mlil::MlilExprKind::kImm) {
        return cond.imm == 0;
    }
    return false;
}

// Check if condition is a constant true (non-zero)
bool is_constant_true(const mlil::MlilExpr& cond) {
    if (cond.kind == mlil::MlilExprKind::kImm) {
        return cond.imm != 0;
    }
    return false;
}

// Check if a statement is effectively empty (nop or empty block)
bool is_empty_stmt(const Stmt& stmt) {
    if (stmt.kind == StmtKind::kNop) {
        return true;
    }
    if (stmt.kind == StmtKind::kIf) {
        // if with empty both branches
        return stmt.then_body.empty() && stmt.else_body.empty();
    }
    return false;
}

void remove_redundant_assignments_block(std::vector<Stmt>& stmts) {
    // First recurse into nested structures
    for (auto& stmt : stmts) {
        if (stmt.kind == StmtKind::kIf) {
            remove_redundant_assignments_block(stmt.then_body);
            remove_redundant_assignments_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kWhile || stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor) {
            remove_redundant_assignments_block(stmt.body);
            remove_redundant_assignments_block(stmt.then_body);
            remove_redundant_assignments_block(stmt.else_body);
        } else if (stmt.kind == StmtKind::kSwitch) {
            for (auto& case_body : stmt.case_bodies) {
                remove_redundant_assignments_block(case_body);
            }
            remove_redundant_assignments_block(stmt.default_body);
        }
    }
    
    // Remove redundant statements
    stmts.erase(
        std::remove_if(stmts.begin(), stmts.end(), [](const Stmt& stmt) {
            // Remove redundant assignments: x = x
            if (is_redundant_assignment(stmt) || is_identity_assignment(stmt)) {
                return true;
            }
            // Remove if(0) statements
            if (stmt.kind == StmtKind::kIf && is_constant_false(stmt.condition)) {
                return true;
            }
            // Remove empty if statements (both branches empty)
            if (stmt.kind == StmtKind::kIf && stmt.then_body.empty() && stmt.else_body.empty()) {
                return true;
            }
            return false;
        }),
        stmts.end()
    );
    
    // Simplify if statements with only one non-empty branch when other is empty
    for (auto& stmt : stmts) {
        if (stmt.kind != StmtKind::kIf) {
            continue;
        }
        // If then is empty but else is not, invert condition and swap
        if (stmt.then_body.empty() && !stmt.else_body.empty()) {
            // Invert condition
            if (stmt.condition.kind == mlil::MlilExprKind::kOp) {
                switch (stmt.condition.op) {
                    case mlil::MlilOp::kEq: stmt.condition.op = mlil::MlilOp::kNe; break;
                    case mlil::MlilOp::kNe: stmt.condition.op = mlil::MlilOp::kEq; break;
                    case mlil::MlilOp::kLt: stmt.condition.op = mlil::MlilOp::kGe; break;
                    case mlil::MlilOp::kLe: stmt.condition.op = mlil::MlilOp::kGt; break;
                    case mlil::MlilOp::kGt: stmt.condition.op = mlil::MlilOp::kLe; break;
                    case mlil::MlilOp::kGe: stmt.condition.op = mlil::MlilOp::kLt; break;
                    default: {
                        // Wrap in NOT
                        mlil::MlilExpr not_expr;
                        not_expr.kind = mlil::MlilExprKind::kOp;
                        not_expr.op = mlil::MlilOp::kNot;
                        not_expr.size = 1;
                        not_expr.args.push_back(std::move(stmt.condition));
                        stmt.condition = std::move(not_expr);
                        break;
                    }
                }
            } else {
                // Wrap in NOT
                mlil::MlilExpr not_expr;
                not_expr.kind = mlil::MlilExprKind::kOp;
                not_expr.op = mlil::MlilOp::kNot;
                not_expr.size = 1;
                not_expr.args.push_back(std::move(stmt.condition));
                stmt.condition = std::move(not_expr);
            }
            stmt.then_body = std::move(stmt.else_body);
            stmt.else_body.clear();
        }
    }
}

} // namespace

void remove_redundant_assignments(Function& function) {
    remove_redundant_assignments_block(function.stmts);
}

} // namespace engine::decompiler