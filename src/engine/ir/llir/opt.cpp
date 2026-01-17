#include "engine/llir_opt.h"
#include "engine/llir_opt_internal.h"

#include <cstdint>

#include "engine/llir_ssa.h"

namespace engine::llir {

namespace detail {

// ============================================================================
// Helper functions (private to this translation unit)
// ============================================================================

namespace {

bool is_imm(const LlilExpr& expr, std::uint64_t& value) {
    if (expr.kind != LlilExprKind::kImm) {
        return false;
    }
    value = expr.imm;
    return true;
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

LlilExpr with_size(LlilExpr expr, std::size_t size) {
    if (expr.size == 0) {
        expr.size = size;
    }
    return expr;
}

bool fold_binary(const LlilExpr& expr, std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out) {
    switch (expr.op) {
        case LlilOp::kAdd:
            out = lhs + rhs;
            return true;
        case LlilOp::kSub:
            out = lhs - rhs;
            return true;
        case LlilOp::kMul:
            out = lhs * rhs;
            return true;
        case LlilOp::kDiv:
            if (rhs == 0) {
                return false;
            }
            out = lhs / rhs;
            return true;
        case LlilOp::kMod:
            if (rhs == 0) {
                return false;
            }
            out = lhs % rhs;
            return true;
        case LlilOp::kAnd:
            out = lhs & rhs;
            return true;
        case LlilOp::kOr:
            out = lhs | rhs;
            return true;
        case LlilOp::kXor:
            out = lhs ^ rhs;
            return true;
        case LlilOp::kShl:
            out = lhs << rhs;
            return true;
        case LlilOp::kShr:
            out = lhs >> rhs;
            return true;
        case LlilOp::kSar:
            out = static_cast<std::uint64_t>(static_cast<std::int64_t>(lhs) >> rhs);
            return true;
        case LlilOp::kRor: {
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
        case LlilOp::kEq:
            out = (lhs == rhs) ? 1 : 0;
            return true;
        case LlilOp::kNe:
            out = (lhs != rhs) ? 1 : 0;
            return true;
        case LlilOp::kLt:
            out = (sign_extend(lhs, expr.size * 8) < sign_extend(rhs, expr.size * 8)) ? 1 : 0;
            return true;
        case LlilOp::kLe:
            out = (sign_extend(lhs, expr.size * 8) <= sign_extend(rhs, expr.size * 8)) ? 1 : 0;
            return true;
        case LlilOp::kGt:
            out = (sign_extend(lhs, expr.size * 8) > sign_extend(rhs, expr.size * 8)) ? 1 : 0;
            return true;
        case LlilOp::kGe:
            out = (sign_extend(lhs, expr.size * 8) >= sign_extend(rhs, expr.size * 8)) ? 1 : 0;
            return true;
        default:
            return false;
    }
}

bool fold_unary(const LlilExpr& expr, std::uint64_t value, std::uint64_t& out) {
    switch (expr.op) {
        case LlilOp::kNot:
            out = ~value;
            return true;
        case LlilOp::kNeg:
            out = static_cast<std::uint64_t>(-static_cast<std::int64_t>(value));
            return true;
        case LlilOp::kAbs: {
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

bool simplify_op(LlilExpr& expr) {
    if (expr.kind != LlilExprKind::kOp || expr.args.empty()) {
        return false;
    }

    bool changed = false;
    for (auto& arg : expr.args) {
        changed |= simplify_op(arg);
    }

    const std::size_t size = expr.size;
    const std::uint64_t mask = mask_for_size(size);

    if (expr.args.size() == 1) {
        std::uint64_t value = 0;
        if (is_imm(expr.args[0], value)) {
            std::uint64_t out = 0;
            if (fold_unary(expr, value, out)) {
                LlilExpr folded;
                folded.kind = LlilExprKind::kImm;
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
                LlilExpr folded;
                folded.kind = LlilExprKind::kImm;
                folded.size = size;
                folded.imm = out & mask;
                expr = std::move(folded);
                return true;
            }
        }

        if (rhs_imm) {
            if ((expr.op == LlilOp::kAdd || expr.op == LlilOp::kSub) && rhs == 0) {
                expr = with_size(std::move(expr.args[0]), size);
                return true;
            }
            if ((expr.op == LlilOp::kMul) && rhs == 1) {
                expr = with_size(std::move(expr.args[0]), size);
                return true;
            }
            if ((expr.op == LlilOp::kMul) && rhs == 0) {
                expr.kind = LlilExprKind::kImm;
                expr.imm = 0;
                expr.args.clear();
                expr.size = size;
                return true;
            }
            if ((expr.op == LlilOp::kAnd) && rhs == 0) {
                expr.kind = LlilExprKind::kImm;
                expr.imm = 0;
                expr.args.clear();
                expr.size = size;
                return true;
            }
            if ((expr.op == LlilOp::kOr || expr.op == LlilOp::kXor) && rhs == 0) {
                expr = with_size(std::move(expr.args[0]), size);
                return true;
            }
            if ((expr.op == LlilOp::kShl || expr.op == LlilOp::kShr || expr.op == LlilOp::kSar ||
                 expr.op == LlilOp::kRor) &&
                rhs == 0) {
                expr = with_size(std::move(expr.args[0]), size);
                return true;
            }
        }
        if (lhs_imm) {
            if ((expr.op == LlilOp::kAdd) && lhs == 0) {
                expr = with_size(std::move(expr.args[1]), size);
                return true;
            }
            if ((expr.op == LlilOp::kMul) && lhs == 1) {
                expr = with_size(std::move(expr.args[1]), size);
                return true;
            }
            if ((expr.op == LlilOp::kMul) && lhs == 0) {
                expr.kind = LlilExprKind::kImm;
                expr.imm = 0;
                expr.args.clear();
                expr.size = size;
                return true;
            }
        }
        return changed;
    }

    if (expr.op == LlilOp::kSelect && expr.args.size() == 3) {
        std::uint64_t cond = 0;
        if (is_imm(expr.args[0], cond)) {
            const std::size_t out_size = expr.size;
            LlilExpr chosen = cond ? expr.args[1] : expr.args[2];
            expr = with_size(std::move(chosen), out_size);
            return true;
        }
    }

    return changed;
}

namespace {

bool replace_reg_in_expr(LlilExpr& expr, const RegRef& target, const LlilExpr& replacement) {
    bool changed = false;
    if (expr.kind == LlilExprKind::kReg) {
        if (expr.reg.name == target.name && expr.reg.version == target.version) {
            const std::size_t size = expr.size;
            expr = replacement;
            if (expr.size == 0) {
                expr.size = size;
            }
            return true;
        }
    }
    for (auto& arg : expr.args) {
        changed |= replace_reg_in_expr(arg, target, replacement);
    }
    return changed;
}

bool replace_reg_in_stmt(LlilStmt& stmt, const RegRef& target, const LlilExpr& replacement) {
    bool changed = false;
    changed |= replace_reg_in_expr(stmt.expr, target, replacement);
    changed |= replace_reg_in_expr(stmt.target, target, replacement);
    changed |= replace_reg_in_expr(stmt.condition, target, replacement);
    for (auto& arg : stmt.args) {
        changed |= replace_reg_in_expr(arg, target, replacement);
    }
    return changed;
}

}  // anonymous namespace

bool propagate_copies(Function& function, const LlilSsaDefUse& defuse) {
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
        if (def_site.stmt_index >= inst.llil_ssa.size()) {
            continue;
        }
        const auto& stmt = inst.llil_ssa[def_site.stmt_index];
        if (stmt.kind != LlilStmtKind::kSetReg) {
            continue;
        }
        if (stmt.reg.name.empty() || stmt.reg.version < 0) {
            continue;
        }
        if (!(stmt.expr.kind == LlilExprKind::kImm || stmt.expr.kind == LlilExprKind::kReg)) {
            continue;
        }
        if (stmt.expr.kind == LlilExprKind::kReg &&
            stmt.expr.reg.name == stmt.reg.name &&
            stmt.expr.reg.version == stmt.reg.version) {
            continue;
        }
        auto uses_it = defuse.uses.find(key);
        if (uses_it == defuse.uses.end()) {
            continue;
        }
        const LlilExpr replacement = stmt.expr;
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
                changed |= replace_reg_in_expr(phi.expr, stmt.reg, replacement);
                continue;
            }
            if (use_site.inst_index >= use_block.instructions.size()) {
                continue;
            }
            auto& use_inst = use_block.instructions[use_site.inst_index];
            if (use_site.stmt_index >= use_inst.llil_ssa.size()) {
                continue;
            }
            auto& use_stmt = use_inst.llil_ssa[use_site.stmt_index];
            changed |= replace_reg_in_stmt(use_stmt, stmt.reg, replacement);
        }
    }
    return changed;
}

bool is_flag_reg_name(const std::string& name) {
    return name.rfind("flag_", 0) == 0;
}

bool propagate_flag_exprs(Function& function, const LlilSsaDefUse& defuse) {
    bool changed = false;
    for (const auto& [key, def_site] : defuse.defs) {
        if (key.name.empty() || key.version < 0) {
            continue;
        }
        if (!is_flag_reg_name(key.name)) {
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
        if (def_site.stmt_index >= inst.llil_ssa.size()) {
            continue;
        }
        const auto& stmt = inst.llil_ssa[def_site.stmt_index];
        if (stmt.kind != LlilStmtKind::kSetReg) {
            continue;
        }
        if (!(stmt.reg.name == key.name && stmt.reg.version == key.version)) {
            continue;
        }
        auto uses_it = defuse.uses.find(key);
        if (uses_it == defuse.uses.end()) {
            continue;
        }
        const LlilExpr replacement = stmt.expr;
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
                changed |= replace_reg_in_expr(phi.expr, stmt.reg, replacement);
                continue;
            }
            if (use_site.inst_index >= use_block.instructions.size()) {
                continue;
            }
            auto& use_inst = use_block.instructions[use_site.inst_index];
            if (use_site.stmt_index >= use_inst.llil_ssa.size()) {
                continue;
            }
            auto& use_stmt = use_inst.llil_ssa[use_site.stmt_index];
            changed |= replace_reg_in_stmt(use_stmt, stmt.reg, replacement);
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
            for (auto& stmt : inst.llil_ssa) {
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

bool eliminate_dead_defs(Function& function, const LlilSsaDefUse& defuse) {
    bool changed = false;
    for (auto& block : function.blocks) {
        if (!block.phis.empty()) {
            std::vector<LlilStmt> kept;
            kept.reserve(block.phis.size());
            for (auto& phi : block.phis) {
                RegRefKey key{phi.reg.name, phi.reg.version};
                if (phi.reg.name.empty() || phi.reg.version < 0 || defuse.uses.find(key) != defuse.uses.end()) {
                    kept.push_back(std::move(phi));
                } else {
                    changed = true;
                }
            }
            block.phis = std::move(kept);
        }
        for (auto& inst : block.instructions) {
            if (inst.llil_ssa.empty()) {
                continue;
            }
            std::vector<LlilStmt> kept;
            kept.reserve(inst.llil_ssa.size());
            for (auto& stmt : inst.llil_ssa) {
                if (stmt.kind == LlilStmtKind::kSetReg && !stmt.reg.name.empty() && stmt.reg.version >= 0) {
                    RegRefKey key{stmt.reg.name, stmt.reg.version};
                    if (defuse.uses.find(key) == defuse.uses.end()) {
                        changed = true;
                        continue;
                    }
                }
                kept.push_back(std::move(stmt));
            }
            inst.llil_ssa = std::move(kept);
        }
    }
    return changed;
}

bool has_ssa(const Function& function) {
    for (const auto& block : function.blocks) {
        for (const auto& inst : block.instructions) {
            if (!inst.llil_ssa.empty()) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace detail

bool optimize_llil_ssa(Function& function, const LlilOptOptions& options, std::string& error) {
    error.clear();
    if (!detail::has_ssa(function)) {
        error = "llil_ssa is empty; build_ssa must run first";
        return false;
    }

    bool changed = false;
    for (int iter = 0; iter < 3; ++iter) {
        bool iter_changed = false;
        if (options.copy_propagation) {
            LlilSsaDefUse defuse;
            if (!build_ssa_def_use(function, defuse, error)) {
                return false;
            }
            iter_changed |= detail::propagate_copies(function, defuse);
        }
        if (options.fold_constants) {
            iter_changed |= detail::fold_constants(function);
        }
        if (options.inline_flag_exprs) {
            LlilSsaDefUse defuse;
            if (!build_ssa_def_use(function, defuse, error)) {
                return false;
            }
            iter_changed |= detail::propagate_flag_exprs(function, defuse);
        }
        if (options.dead_code_elim) {
            LlilSsaDefUse defuse;
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

}  // namespace engine::llir
