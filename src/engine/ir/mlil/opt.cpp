#include "engine/mlil_opt.h"
#include "engine/mlil_opt_internal.h"

#include <cstdint>

#include "engine/mlil_ssa.h"

namespace engine::mlil {

namespace detail {

// ============================================================================
// Helper functions (private to this translation unit)
// ============================================================================

namespace {

bool is_imm(const MlilExpr& expr, std::uint64_t& value) {
    if (expr.kind != MlilExprKind::kImm) {
        return false;
    }
    value = expr.imm;
    return true;
}

bool is_imm_value(const MlilExpr& expr, std::uint64_t expected, std::size_t expected_size = 0) {
    std::uint64_t value = 0;
    if (!is_imm(expr, value)) {
        return false;
    }
    if (expected_size != 0 && expr.size != expected_size) {
        return false;
    }
    return value == expected;
}

bool is_bool_expr(const MlilExpr& expr) {
    return expr.size == 1;
}

bool is_zero_reg_var(const MlilExpr& expr) {
    if (expr.kind != MlilExprKind::kVar) {
        return false;
    }
    return expr.var.name == "reg.xzr";
}

bool is_zero_value(const MlilExpr& expr) {
    return is_zero_reg_var(expr) || is_imm_value(expr, 0);
}

std::uint64_t mask_for_bits(std::size_t bits) {
    if (bits == 0) {
        return 0;
    }
    if (bits >= 64) {
        return ~static_cast<std::uint64_t>(0);
    }
    return (static_cast<std::uint64_t>(1) << bits) - 1;
}

std::uint64_t mask_for_size(std::size_t size) {
    if (size == 0) {
        return ~static_cast<std::uint64_t>(0);
    }
    return mask_for_bits(size * 8);
}

std::int64_t sign_extend(std::uint64_t value, std::size_t bits) {
    if (bits == 0 || bits >= 64) {
        return static_cast<std::int64_t>(value);
    }
    const std::uint64_t shift = 64 - bits;
    return static_cast<std::int64_t>(value << shift) >> shift;
}

MlilExpr with_size(MlilExpr expr, std::size_t size) {
    if (expr.size == 0) {
        expr.size = size;
    }
    return expr;
}

bool invert_predicate(MlilExpr& expr) {
    if (expr.kind != MlilExprKind::kOp || expr.size != 1) {
        return false;
    }
    switch (expr.op) {
        case MlilOp::kEq: expr.op = MlilOp::kNe; return true;
        case MlilOp::kNe: expr.op = MlilOp::kEq; return true;
        case MlilOp::kLt: expr.op = MlilOp::kGe; return true;
        case MlilOp::kLe: expr.op = MlilOp::kGt; return true;
        case MlilOp::kGt: expr.op = MlilOp::kLe; return true;
        case MlilOp::kGe: expr.op = MlilOp::kLt; return true;
        default: return false;
    }
}

bool normalize_compare_direction(MlilExpr& expr) {
    if (expr.kind != MlilExprKind::kOp || expr.size != 1 || expr.args.size() != 2) {
        return false;
    }
    // Prefer "<" / "<=" forms: a > b  ==> b < a
    switch (expr.op) {
        case MlilOp::kGt:
            std::swap(expr.args[0], expr.args[1]);
            expr.op = MlilOp::kLt;
            return true;
        case MlilOp::kGe:
            std::swap(expr.args[0], expr.args[1]);
            expr.op = MlilOp::kLe;
            return true;
        default:
            return false;
    }
}

bool normalize_bool_compare(MlilExpr& expr) {
    if (expr.kind != MlilExprKind::kOp || expr.args.size() != 2) {
        return false;
    }
    if (!(expr.op == MlilOp::kEq || expr.op == MlilOp::kNe)) {
        return false;
    }
    if (expr.size != 1) {
        return false;
    }

    if (expr.args[0].kind == MlilExprKind::kImm && expr.args[1].kind != MlilExprKind::kImm) {
        std::swap(expr.args[0], expr.args[1]);
    }

    if (!is_bool_expr(expr.args[0]) || !is_bool_expr(expr.args[1])) {
        return false;
    }

    std::uint64_t rhs = 0;
    if (!is_imm(expr.args[1], rhs) || (rhs != 0 && rhs != 1)) {
        return false;
    }

    const bool want_eq = (expr.op == MlilOp::kEq);
    const bool compare_to_one = (rhs == 1);
    const bool invert = (want_eq && !compare_to_one) || (!want_eq && compare_to_one);
    const bool passthrough = !invert;

    MlilExpr inner = std::move(expr.args[0]);
    if (passthrough) {
        expr = with_size(std::move(inner), 1);
        return true;
    }

    if (inner.kind == MlilExprKind::kImm) {
        inner.imm = (inner.imm & 1) ? 0 : 1;
        inner.size = 1;
        expr = std::move(inner);
        return true;
    }
    if (invert_predicate(inner)) {
        expr = with_size(std::move(inner), 1);
        return true;
    }

    MlilExpr zero;
    zero.kind = MlilExprKind::kImm;
    zero.size = 1;
    zero.imm = 0;
    expr.args.clear();
    expr.args.push_back(std::move(inner));
    expr.args.push_back(std::move(zero));
    expr.op = MlilOp::kEq;
    expr.size = 1;
    return true;
}

bool expr_equal(const MlilExpr& a, const MlilExpr& b) {
    if (a.kind != b.kind || a.size != b.size) {
        return false;
    }
    switch (a.kind) {
        case MlilExprKind::kVar:
            return a.var.name == b.var.name && a.var.version == b.var.version;
        case MlilExprKind::kImm:
            return a.imm == b.imm;
        case MlilExprKind::kOp:
            if (a.op != b.op || a.args.size() != b.args.size()) {
                return false;
            }
            for (std::size_t i = 0; i < a.args.size(); ++i) {
                if (!expr_equal(a.args[i], b.args[i])) {
                    return false;
                }
            }
            return true;
        case MlilExprKind::kLoad:
            if (a.args.size() != b.args.size()) {
                return false;
            }
            for (std::size_t i = 0; i < a.args.size(); ++i) {
                if (!expr_equal(a.args[i], b.args[i])) {
                    return false;
                }
            }
            return true;
        default:
            return true;
    }
}

bool simplify_and_patterns(MlilExpr& expr) {
    if (expr.kind != MlilExprKind::kOp || expr.op != MlilOp::kAnd || expr.size != 1 || expr.args.size() != 2) {
        return false;
    }

    auto try_fold = [&](MlilExpr& ge_expr, MlilExpr& nz_expr) -> bool {
        if (ge_expr.kind != MlilExprKind::kOp || ge_expr.size != 1 || ge_expr.args.size() != 2) {
            return false;
        }
        if (!(ge_expr.op == MlilOp::kGe || ge_expr.op == MlilOp::kLe)) {
            return false;
        }

        const MlilExpr a = ge_expr.args[0];
        const MlilExpr b = ge_expr.args[1];

        bool matches = false;
        if (nz_expr.kind == MlilExprKind::kOp && nz_expr.size == 1 && nz_expr.args.size() == 2) {
            if (nz_expr.op == MlilOp::kNe &&
                ((expr_equal(nz_expr.args[0], a) && expr_equal(nz_expr.args[1], b)) ||
                 (expr_equal(nz_expr.args[0], b) && expr_equal(nz_expr.args[1], a)))) {
                matches = true;
            } else if (nz_expr.op == MlilOp::kNe && is_imm_value(nz_expr.args[1], 0) &&
                       nz_expr.args[0].kind == MlilExprKind::kOp && nz_expr.args[0].op == MlilOp::kSub &&
                       nz_expr.args[0].args.size() == 2) {
                const MlilExpr sub_lhs = nz_expr.args[0].args[0];
                const MlilExpr sub_rhs = nz_expr.args[0].args[1];
                if (ge_expr.op == MlilOp::kGe) {
                    // ge(a,b) && (a-b)!=0  ==> a>b
                    matches = expr_equal(sub_lhs, a) && expr_equal(sub_rhs, b);
                } else {
                    // le(a,b) && (b-a)!=0  ==> a<b
                    matches = expr_equal(sub_lhs, b) && expr_equal(sub_rhs, a);
                }
            }
        }

        if (!matches) {
            return false;
        }

        MlilExpr folded;
        folded.kind = MlilExprKind::kOp;
        folded.size = 1;
        folded.op = (ge_expr.op == MlilOp::kGe) ? MlilOp::kGt : MlilOp::kLt;
        folded.args.push_back(std::move(ge_expr.args[0]));
        folded.args.push_back(std::move(ge_expr.args[1]));
        expr = std::move(folded);
        return true;
    };

    return try_fold(expr.args[0], expr.args[1]) || try_fold(expr.args[1], expr.args[0]);
}

bool simplify_zero_reg_ops(MlilExpr& expr) {
    if (expr.kind != MlilExprKind::kOp || expr.args.size() != 2) {
        return false;
    }
    // Make zero-reg behave like an immediate 0 for algebraic simplification.
    if (expr.op == MlilOp::kAdd || expr.op == MlilOp::kSub || expr.op == MlilOp::kOr || expr.op == MlilOp::kXor) {
        if (is_zero_value(expr.args[1])) {
            const std::size_t out_size = expr.size;
            expr = with_size(std::move(expr.args[0]), out_size);
            return true;
        }
        if (expr.op == MlilOp::kAdd && is_zero_value(expr.args[0])) {
            const std::size_t out_size = expr.size;
            expr = with_size(std::move(expr.args[1]), out_size);
            return true;
        }
    }
    if (expr.op == MlilOp::kMul && is_zero_value(expr.args[1])) {
        expr.kind = MlilExprKind::kImm;
        expr.imm = 0;
        expr.args.clear();
        return true;
    }
    if (expr.op == MlilOp::kAnd && is_zero_value(expr.args[1])) {
        expr.kind = MlilExprKind::kImm;
        expr.imm = 0;
        expr.args.clear();
        return true;
    }
    return false;
}

bool fold_binary(const MlilExpr& expr, std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out) {
    switch (expr.op) {
        case MlilOp::kAdd:
            out = lhs + rhs;
            return true;
        case MlilOp::kSub:
            out = lhs - rhs;
            return true;
        case MlilOp::kMul:
            out = lhs * rhs;
            return true;
        case MlilOp::kDiv:
            if (rhs == 0) {
                return false;
            }
            out = lhs / rhs;
            return true;
        case MlilOp::kMod:
            if (rhs == 0) {
                return false;
            }
            out = lhs % rhs;
            return true;
        case MlilOp::kAnd:
            out = lhs & rhs;
            return true;
        case MlilOp::kOr:
            out = lhs | rhs;
            return true;
        case MlilOp::kXor:
            out = lhs ^ rhs;
            return true;
        case MlilOp::kShl:
            out = lhs << rhs;
            return true;
        case MlilOp::kShr:
            out = lhs >> rhs;
            return true;
        case MlilOp::kSar:
            out = static_cast<std::uint64_t>(static_cast<std::int64_t>(lhs) >> rhs);
            return true;
        case MlilOp::kRor: {
            if (rhs == 0) {
                out = lhs;
                return true;
            }
            const std::size_t bits = expr.size ? expr.size * 8 : 64;
            const std::size_t rot = bits ? (rhs % bits) : 0;
            if (rot == 0) {
                out = lhs;
                return true;
            }
            out = (lhs >> rot) | (lhs << (bits - rot));
            return true;
        }
        case MlilOp::kEq:
            out = (lhs == rhs) ? 1 : 0;
            return true;
        case MlilOp::kNe:
            out = (lhs != rhs) ? 1 : 0;
            return true;
        case MlilOp::kLt:
            out = (sign_extend(lhs, expr.size * 8) < sign_extend(rhs, expr.size * 8)) ? 1 : 0;
            return true;
        case MlilOp::kLe:
            out = (sign_extend(lhs, expr.size * 8) <= sign_extend(rhs, expr.size * 8)) ? 1 : 0;
            return true;
        case MlilOp::kGt:
            out = (sign_extend(lhs, expr.size * 8) > sign_extend(rhs, expr.size * 8)) ? 1 : 0;
            return true;
        case MlilOp::kGe:
            out = (sign_extend(lhs, expr.size * 8) >= sign_extend(rhs, expr.size * 8)) ? 1 : 0;
            return true;
        default:
            return false;
    }
}

bool fold_unary(const MlilExpr& expr, std::uint64_t value, std::uint64_t& out) {
    switch (expr.op) {
        case MlilOp::kNot:
            out = ~value;
            return true;
        case MlilOp::kNeg:
            out = static_cast<std::uint64_t>(-static_cast<std::int64_t>(value));
            return true;
        case MlilOp::kAbs: {
            const std::int64_t signed_value = static_cast<std::int64_t>(value);
            out = static_cast<std::uint64_t>(signed_value < 0 ? -signed_value : signed_value);
            return true;
        }
        default:
            return false;
    }
}

}  // anonymous namespace

// ============================================================================
// Exported optimization functions (in detail namespace)
// ============================================================================

bool simplify_op(MlilExpr& expr) {
    if (expr.kind != MlilExprKind::kOp || expr.args.empty()) {
        return false;
    }

    bool changed = false;
    for (auto& arg : expr.args) {
        changed |= simplify_op(arg);
    }

    if (expr.args.size() == 2) {
        if (simplify_zero_reg_ops(expr)) {
            return true;
        }
    }

    if (expr.size == 1 && expr.args.size() == 2) {
        if (normalize_bool_compare(expr)) {
            return true;
        }
        changed |= simplify_and_patterns(expr);
        if (expr.kind != MlilExprKind::kOp) {
            return true;
        }
        changed |= normalize_compare_direction(expr);
    }

    const std::size_t size = expr.size;
    const std::uint64_t mask = mask_for_size(size);

    if (expr.args.size() == 1) {
        std::uint64_t value = 0;
        if (is_imm(expr.args[0], value)) {
            std::uint64_t out = 0;
            if (fold_unary(expr, value, out)) {
                MlilExpr folded;
                folded.kind = MlilExprKind::kImm;
                folded.size = size;
                folded.imm = out & mask;
                expr = std::move(folded);
                return true;
            }
        }
        return changed;
    }

    if (expr.args.size() == 2) {
        std::uint64_t lhs = 0;
        std::uint64_t rhs = 0;
        const bool lhs_imm = is_imm(expr.args[0], lhs);
        const bool rhs_imm = is_imm(expr.args[1], rhs);
        if (lhs_imm && rhs_imm && size > 0 && size <= 8) {
            lhs &= mask;
            rhs &= mask;
            std::uint64_t out = 0;
            if (fold_binary(expr, lhs, rhs, out)) {
                MlilExpr folded;
                folded.kind = MlilExprKind::kImm;
                folded.size = size;
                folded.imm = out & mask;
                expr = std::move(folded);
                return true;
            }
        }

        if (rhs_imm) {
            if ((expr.op == MlilOp::kAdd || expr.op == MlilOp::kSub) && rhs == 0) {
                expr = with_size(std::move(expr.args[0]), size);
                return true;
            }
            if ((expr.op == MlilOp::kMul) && rhs == 1) {
                expr = with_size(std::move(expr.args[0]), size);
                return true;
            }
            if ((expr.op == MlilOp::kMul) && rhs == 0) {
                expr.kind = MlilExprKind::kImm;
                expr.imm = 0;
                expr.args.clear();
                expr.size = size;
                return true;
            }
            if ((expr.op == MlilOp::kAnd) && rhs == 0) {
                expr.kind = MlilExprKind::kImm;
                expr.imm = 0;
                expr.args.clear();
                expr.size = size;
                return true;
            }
            if ((expr.op == MlilOp::kOr || expr.op == MlilOp::kXor) && rhs == 0) {
                expr = with_size(std::move(expr.args[0]), size);
                return true;
            }
        }
    }

    if (expr.op == MlilOp::kSelect && expr.args.size() == 3) {
        std::uint64_t cond = 0;
        if (is_imm(expr.args[0], cond)) {
            const std::size_t out_size = expr.size;
            MlilExpr chosen = cond ? expr.args[1] : expr.args[2];
            expr = with_size(std::move(chosen), out_size);
            return true;
        }
    }

    return changed;
}

namespace {

bool replace_var_in_expr(MlilExpr& expr, const VarRef& target, const MlilExpr& replacement) {
    bool changed = false;
    if (expr.kind == MlilExprKind::kVar) {
        if (expr.var.name == target.name && expr.var.version == target.version) {
            const std::size_t size = expr.size;
            expr = replacement;
            if (expr.size == 0) {
                expr.size = size;
            }
            return true;
        }
    }
    for (auto& arg : expr.args) {
        changed |= replace_var_in_expr(arg, target, replacement);
    }
    return changed;
}

bool replace_var_in_stmt(MlilStmt& stmt, const VarRef& target, const MlilExpr& replacement) {
    bool changed = false;
    changed |= replace_var_in_expr(stmt.expr, target, replacement);
    changed |= replace_var_in_expr(stmt.target, target, replacement);
    changed |= replace_var_in_expr(stmt.condition, target, replacement);
    for (auto& arg : stmt.args) {
        changed |= replace_var_in_expr(arg, target, replacement);
    }
    return changed;
}

}  // anonymous namespace

bool propagate_copies(Function& function, const MlilSsaDefUse& defuse) {
    bool changed = false;
    for (const auto& [key, def_site] : defuse.defs) {
        if (key.name.empty() || key.version < 0) {
            continue;
        }
        if (def_site.is_phi) {
            continue;
        }
        if (def_site.block_index >= function.blocks.size()) {
            continue;
        }
        auto& block = function.blocks[def_site.block_index];
        if (def_site.inst_index >= block.instructions.size()) {
            continue;
        }
        auto& inst = block.instructions[def_site.inst_index];
        if (def_site.stmt_index >= inst.stmts.size()) {
            continue;
        }
        const auto& stmt = inst.stmts[def_site.stmt_index];
        if (stmt.kind != MlilStmtKind::kAssign) {
            continue;
        }
        if (stmt.var.name.empty() || stmt.var.version < 0) {
            continue;
        }
        if (!(stmt.expr.kind == MlilExprKind::kImm || stmt.expr.kind == MlilExprKind::kVar)) {
            continue;
        }
        if (stmt.expr.kind == MlilExprKind::kVar &&
            stmt.expr.var.name == stmt.var.name &&
            stmt.expr.var.version == stmt.var.version) {
            continue;
        }
        auto uses_it = defuse.uses.find(key);
        if (uses_it == defuse.uses.end()) {
            continue;
        }
        const MlilExpr replacement = stmt.expr;
        for (const auto& use_site : uses_it->second) {
            if (use_site.block_index >= function.blocks.size()) {
                continue;
            }
            auto& use_block = function.blocks[use_site.block_index];
            if (use_site.is_phi) {
                if (use_site.stmt_index >= use_block.phis.size()) {
                    continue;
                }
                auto& phi = use_block.phis[use_site.stmt_index];
                changed |= replace_var_in_expr(phi.expr, stmt.var, replacement);
                continue;
            }
            if (use_site.inst_index >= use_block.instructions.size()) {
                continue;
            }
            auto& use_inst = use_block.instructions[use_site.inst_index];
            if (use_site.stmt_index >= use_inst.stmts.size()) {
                continue;
            }
            auto& use_stmt = use_inst.stmts[use_site.stmt_index];
            changed |= replace_var_in_stmt(use_stmt, stmt.var, replacement);
        }
    }
    return changed;
}

bool fold_constants(Function& function) {
    bool changed = false;
    for (auto& block : function.blocks) {
        for (auto& phi : block.phis) {
            changed |= simplify_op(phi.expr);
        }
        for (auto& inst : block.instructions) {
            for (auto& stmt : inst.stmts) {
                changed |= simplify_op(stmt.expr);
                changed |= simplify_op(stmt.target);
                changed |= simplify_op(stmt.condition);
                for (auto& arg : stmt.args) {
                    changed |= simplify_op(arg);
                }
            }
        }
    }
    return changed;
}

bool eliminate_dead_defs(Function& function, const MlilSsaDefUse& defuse) {
    bool changed = false;
    for (auto& block : function.blocks) {
        if (!block.phis.empty()) {
            std::vector<MlilStmt> kept;
            kept.reserve(block.phis.size());
            for (auto& phi : block.phis) {
                VarRefKey key{phi.var.name, phi.var.version};
                if (phi.var.name.empty() || phi.var.version < 0 || defuse.uses.find(key) != defuse.uses.end()) {
                    kept.push_back(std::move(phi));
                } else {
                    changed = true;
                }
            }
            block.phis = std::move(kept);
        }
        for (auto& inst : block.instructions) {
            if (inst.stmts.empty()) {
                continue;
            }
            std::vector<MlilStmt> kept;
            kept.reserve(inst.stmts.size());
            for (auto& stmt : inst.stmts) {
                if (stmt.kind == MlilStmtKind::kAssign && !stmt.var.name.empty() && stmt.var.version >= 0) {
                    VarRefKey key{stmt.var.name, stmt.var.version};
                    if (defuse.uses.find(key) == defuse.uses.end()) {
                        changed = true;
                        continue;
                    }
                }
                kept.push_back(std::move(stmt));
            }
            inst.stmts = std::move(kept);
        }
    }
    return changed;
}

bool has_ssa(const Function& function) {
    for (const auto& block : function.blocks) {
        if (!block.phis.empty()) {
            return true;
        }
        for (const auto& inst : block.instructions) {
            if (!inst.stmts.empty()) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace detail

bool optimize_mlil_ssa(Function& function, const MlilOptOptions& options, std::string& error) {
    error.clear();
    if (!detail::has_ssa(function)) {
        error = "mlil is empty; build_ssa must run first";
        return false;
    }

    bool changed = false;
    for (int iter = 0; iter < 3; ++iter) {
        bool iter_changed = false;
        if (options.copy_propagation) {
            MlilSsaDefUse defuse;
            if (!build_ssa_def_use(function, defuse, error)) {
                return false;
            }
            iter_changed |= detail::propagate_copies(function, defuse);
        }
        if (options.fold_constants) {
            iter_changed |= detail::fold_constants(function);
        }
        if (options.dead_code_elim) {
            MlilSsaDefUse defuse;
            if (!build_ssa_def_use(function, defuse, error)) {
                return false;
            }
            iter_changed |= detail::eliminate_dead_defs(function, defuse);
        }
        changed |= iter_changed;
        if (!iter_changed) {
            break;
        }
    }
    return true;
}

}  // namespace engine::mlil
