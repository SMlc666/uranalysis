#include "engine/emit/opt/sugar.h"

namespace engine::emit::opt {

bool is_zero(const mlil::MlilExpr& e) {
    if (e.kind == mlil::MlilExprKind::kImm && e.imm == 0) {
        return true;
    }
    return false;
}

bool get_imm_value(const mlil::MlilExpr& e, std::uint64_t& out) {
    if (e.kind == mlil::MlilExprKind::kImm) {
        out = e.imm;
        return true;
    }
    return false;
}

namespace {

bool split_var_offset(const mlil::MlilExpr& expr, mlil::MlilExpr& base, std::int64_t& offset) {
    if (expr.kind == mlil::MlilExprKind::kVar || expr.kind == mlil::MlilExprKind::kImm) {
        base = expr;
        offset = 0;
        return true;
    }
    if (expr.kind == mlil::MlilExprKind::kOp &&
        (expr.op == mlil::MlilOp::kAdd || expr.op == mlil::MlilOp::kSub) &&
        expr.args.size() == 2) {
        std::uint64_t imm = 0;
        if (expr.args[0].kind == mlil::MlilExprKind::kVar && get_imm_value(expr.args[1], imm)) {
            base = expr.args[0];
            offset = (expr.op == mlil::MlilOp::kAdd) ? static_cast<std::int64_t>(imm)
                                                     : -static_cast<std::int64_t>(imm);
            return true;
        }
        if (expr.op == mlil::MlilOp::kAdd && expr.args[1].kind == mlil::MlilExprKind::kVar &&
            get_imm_value(expr.args[0], imm)) {
            base = expr.args[1];
            offset = static_cast<std::int64_t>(imm);
            return true;
        }
    }
    return false;
}

bool is_scaled_index(const mlil::MlilExpr& e, mlil::MlilExpr& idx_out, std::size_t& scale) {
    if (e.kind == mlil::MlilExprKind::kVar) {
        idx_out = e;
        scale = 1;
        return true;
    }
    if (e.kind == mlil::MlilExprKind::kOp && e.args.size() == 2) {
        if (e.op == mlil::MlilOp::kMul) {
            std::uint64_t imm = 0;
            if (e.args[0].kind == mlil::MlilExprKind::kVar && get_imm_value(e.args[1], imm)) {
                idx_out = e.args[0];
                scale = static_cast<std::size_t>(imm);
                return true;
            }
            if (e.args[1].kind == mlil::MlilExprKind::kVar && get_imm_value(e.args[0], imm)) {
                idx_out = e.args[1];
                scale = static_cast<std::size_t>(imm);
                return true;
            }
        }
        if (e.op == mlil::MlilOp::kShl) {
            std::uint64_t imm = 0;
            if (e.args[0].kind == mlil::MlilExprKind::kVar && get_imm_value(e.args[1], imm)) {
                idx_out = e.args[0];
                scale = static_cast<std::size_t>(1) << imm;
                return true;
            }
        }
    }
    return false;
}

}  // namespace

std::optional<ArrayAccess> match_array_access(const mlil::MlilExpr& load) {
    if (load.kind != mlil::MlilExprKind::kLoad || load.args.empty()) {
        return std::nullopt;
    }

    const auto& addr = load.args[0];
    if (addr.kind != mlil::MlilExprKind::kOp || addr.op != mlil::MlilOp::kAdd ||
        addr.args.size() != 2) {
        return std::nullopt;
    }

    mlil::MlilExpr base0, base1;
    std::int64_t off0 = 0, off1 = 0;

    if (split_var_offset(addr.args[0], base0, off0) &&
        split_var_offset(addr.args[1], base1, off1)) {
        
        const bool base0_imm = base0.kind == mlil::MlilExprKind::kImm;
        const bool base1_imm = base1.kind == mlil::MlilExprKind::kImm;

        // Heuristic: choose the non-immediate as base
        bool use0_as_base = !base0_imm || base1_imm;
        
        const mlil::MlilExpr& base = use0_as_base ? base0 : base1;
        const mlil::MlilExpr& index_expr = use0_as_base ? base1 : base0;
        std::int64_t offset = off0 + off1;

        ArrayAccess result;
        result.base = base;
        result.index = index_expr;
        result.offset = offset;
        result.scale = 1;
        return result;
    }

    // Check for scaled index
    mlil::MlilExpr idx;
    std::size_t scale = 1;
    
    if (addr.args[0].kind == mlil::MlilExprKind::kVar && 
        is_scaled_index(addr.args[1], idx, scale)) {
        ArrayAccess result;
        result.base = addr.args[0];
        result.index = idx;
        result.scale = scale;
        return result;
    }
    
    if (addr.args[1].kind == mlil::MlilExprKind::kVar && 
        is_scaled_index(addr.args[0], idx, scale)) {
        ArrayAccess result;
        result.base = addr.args[1];
        result.index = idx;
        result.scale = scale;
        return result;
    }

    return std::nullopt;
}

std::optional<CompoundAssign> match_compound_assign(const mlil::VarRef& var,
                                                     const mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() != 2) {
        return std::nullopt;
    }

    if (expr.op != mlil::MlilOp::kAdd && expr.op != mlil::MlilOp::kSub) {
        return std::nullopt;
    }

    const auto& lhs = expr.args[0];
    const auto& rhs = expr.args[1];

    // Check if lhs is the same variable
    if (lhs.kind != mlil::MlilExprKind::kVar || lhs.var.name != var.name) {
        // For add, check if rhs is the variable (commutative)
        if (expr.op == mlil::MlilOp::kAdd && 
            rhs.kind == mlil::MlilExprKind::kVar && rhs.var.name == var.name) {
            std::uint64_t imm = 0;
            if (get_imm_value(lhs, imm) && imm == 1) {
                return CompoundAssign{CompoundAssign::Kind::Increment, var.name, {}};
            }
            return CompoundAssign{CompoundAssign::Kind::AddAssign, var.name, lhs};
        }
        return std::nullopt;
    }

    std::uint64_t imm = 0;
    if (get_imm_value(rhs, imm)) {
        if (imm == 1) {
            if (expr.op == mlil::MlilOp::kAdd) {
                return CompoundAssign{CompoundAssign::Kind::Increment, var.name, {}};
            } else {
                return CompoundAssign{CompoundAssign::Kind::Decrement, var.name, {}};
            }
        }
    }

    if (expr.op == mlil::MlilOp::kAdd) {
        return CompoundAssign{CompoundAssign::Kind::AddAssign, var.name, rhs};
    } else {
        return CompoundAssign{CompoundAssign::Kind::SubAssign, var.name, rhs};
    }
}

mlil::MlilExpr simplify_condition(const mlil::MlilExpr& cond) {
    // (x == 0) -> !x  (for boolean contexts)
    if (cond.kind == mlil::MlilExprKind::kOp && cond.op == mlil::MlilOp::kEq &&
        cond.args.size() == 2) {
        if (is_zero(cond.args[0])) {
            mlil::MlilExpr result;
            result.kind = mlil::MlilExprKind::kOp;
            result.op = mlil::MlilOp::kNot;
            result.args.push_back(cond.args[1]);
            return result;
        }
        if (is_zero(cond.args[1])) {
            mlil::MlilExpr result;
            result.kind = mlil::MlilExprKind::kOp;
            result.op = mlil::MlilOp::kNot;
            result.args.push_back(cond.args[0]);
            return result;
        }
    }

    // (x != 0) -> x
    if (cond.kind == mlil::MlilExprKind::kOp && cond.op == mlil::MlilOp::kNe &&
        cond.args.size() == 2) {
        if (is_zero(cond.args[0])) {
            return cond.args[1];
        }
        if (is_zero(cond.args[1])) {
            return cond.args[0];
        }
    }

    return cond;
}

}  // namespace engine::emit::opt
