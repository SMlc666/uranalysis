#include "engine/decompiler/transforms.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <sstream>

namespace engine::decompiler {

bool get_imm_value(const mlil::MlilExpr& expr, std::uint64_t& out) {
    if (expr.kind != mlil::MlilExprKind::kImm) {
        return false;
    }
    out = expr.imm;
    return true;
}

bool is_zero_imm(const mlil::MlilExpr& expr) {
    std::uint64_t value = 0;
    return get_imm_value(expr, value) && value == 0;
}

bool is_one_imm(const mlil::MlilExpr& expr) {
    std::uint64_t value = 0;
    return get_imm_value(expr, value) && value == 1;
}

bool is_var_or_imm(const mlil::MlilExpr& expr) {
    return expr.kind == mlil::MlilExprKind::kVar || expr.kind == mlil::MlilExprKind::kImm;
}

bool is_pure_expr(const mlil::MlilExpr& expr) {
    switch (expr.kind) {
        case mlil::MlilExprKind::kImm:
        case mlil::MlilExprKind::kVar:
            return true;
        case mlil::MlilExprKind::kOp:
            for (const auto& arg : expr.args) {
                if (!is_pure_expr(arg)) {
                    return false;
                }
            }
            return true;
        default:
            return false;
    }
}

int expr_cost(const mlil::MlilExpr& expr) {
    switch (expr.kind) {
        case mlil::MlilExprKind::kImm:
        case mlil::MlilExprKind::kVar:
            return 1;
        case mlil::MlilExprKind::kOp: {
            int cost = 1;
            for (const auto& arg : expr.args) {
                cost += expr_cost(arg);
            }
            return cost;
        }
        default:
            return 2;
    }
}

std::string expr_key(const mlil::MlilExpr& expr) {
    if (!is_pure_expr(expr)) {
        return "";
    }
    switch (expr.kind) {
        case mlil::MlilExprKind::kImm:
            return "i:" + std::to_string(expr.imm) + ":" + std::to_string(expr.size);
        case mlil::MlilExprKind::kVar:
            if (expr.var.name.empty()) {
                return "";
            }
            return "v:" + expr.var.name + ":" + std::to_string(expr.size);
        case mlil::MlilExprKind::kOp: {
            std::string key = "o:" + std::to_string(static_cast<int>(expr.op)) + ":" + std::to_string(expr.size) + "(";
            for (std::size_t i = 0; i < expr.args.size(); ++i) {
                if (i > 0) {
                    key += ",";
                }
                const std::string arg_key = expr_key(expr.args[i]);
                if (arg_key.empty()) {
                    return "";
                }
                key += arg_key;
            }
            key += ")";
            return key;
        }
        default:
            return "";
    }
}

bool expr_uses_var(const mlil::MlilExpr& expr, const std::string& name) {
    if (expr.kind == mlil::MlilExprKind::kVar && expr.var.name == name) {
        return true;
    }
    for (const auto& arg : expr.args) {
        if (expr_uses_var(arg, name)) {
            return true;
        }
    }
    return false;
}

void collect_expr_vars(const mlil::MlilExpr& expr, std::unordered_set<std::string>& out) {
    if (expr.kind == mlil::MlilExprKind::kVar && !expr.var.name.empty()) {
        out.insert(expr.var.name);
    }
    for (const auto& arg : expr.args) {
        collect_expr_vars(arg, out);
    }
}

mlil::MlilExpr make_imm_expr(std::size_t size, std::uint64_t value) {
    mlil::MlilExpr expr;
    expr.kind = mlil::MlilExprKind::kImm;
    expr.size = size;
    expr.imm = value;
    return expr;
}

mlil::MlilExpr make_binary_expr(mlil::MlilOp op, std::size_t size, mlil::MlilExpr lhs, mlil::MlilExpr rhs) {
    mlil::MlilExpr expr;
    expr.kind = mlil::MlilExprKind::kOp;
    expr.size = size;
    expr.op = op;
    expr.args.push_back(std::move(lhs));
    expr.args.push_back(std::move(rhs));
    return expr;
}

mlil::MlilExpr make_var_expr(const std::string& name, std::size_t size) {
    mlil::MlilExpr expr;
    expr.kind = mlil::MlilExprKind::kVar;
    expr.size = size;
    expr.var.name = name;
    expr.var.version = -1;
    expr.var.size = size;
    return expr;
}

bool extract_add_offset(const mlil::MlilExpr& expr, mlil::MlilExpr& base, std::int64_t& offset) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() != 2) {
        return false;
    }
    if (expr.op != mlil::MlilOp::kAdd && expr.op != mlil::MlilOp::kSub) {
        return false;
    }
    std::uint64_t imm = 0;
    if (!get_imm_value(expr.args[1], imm)) {
        return false;
    }
    base = expr.args[0];
    offset = (expr.op == mlil::MlilOp::kAdd) ? static_cast<std::int64_t>(imm)
                                             : -static_cast<std::int64_t>(imm);
    return true;
}

mlil::MlilExpr make_add_with_offset(mlil::MlilExpr base, std::size_t size, std::int64_t offset) {
    if (offset == 0) {
        if (base.size == 0) {
            base.size = size;
        }
        return base;
    }
    std::uint64_t imm = static_cast<std::uint64_t>(offset < 0 ? -offset : offset);
    mlil::MlilOp op = (offset < 0) ? mlil::MlilOp::kSub : mlil::MlilOp::kAdd;
    return make_binary_expr(op, size, std::move(base), make_imm_expr(size, imm));
}

bool simplify_add_sub(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() != 2) {
        return false;
    }
    if (expr.op != mlil::MlilOp::kAdd && expr.op != mlil::MlilOp::kSub) {
        return false;
    }

    auto& lhs = expr.args[0];
    auto& rhs = expr.args[1];
    std::uint64_t imm_lhs = 0;
    std::uint64_t imm_rhs = 0;
    const bool lhs_imm = get_imm_value(lhs, imm_lhs);
    const bool rhs_imm = get_imm_value(rhs, imm_rhs);

    if (lhs_imm && rhs_imm) {
        std::uint64_t value = (expr.op == mlil::MlilOp::kAdd) ? (imm_lhs + imm_rhs) : (imm_lhs - imm_rhs);
        expr = make_imm_expr(expr.size, value);
        return true;
    }

    if (expr.op == mlil::MlilOp::kAdd && lhs_imm && !rhs_imm) {
        std::swap(lhs, rhs);
        std::swap(imm_lhs, imm_rhs);
    }

    if (expr.op == mlil::MlilOp::kAdd && rhs_imm && imm_rhs == 0) {
        mlil::MlilExpr tmp = lhs;
        expr = std::move(tmp);
        return true;
    }
    if (expr.op == mlil::MlilOp::kSub && rhs_imm && imm_rhs == 0) {
        mlil::MlilExpr tmp = lhs;
        expr = std::move(tmp);
        return true;
    }
    
    // x - x -> 0
    if (expr.op == mlil::MlilOp::kSub && expr_key(lhs) == expr_key(rhs) && !expr_key(lhs).empty()) {
        expr = make_imm_expr(expr.size, 0);
        return true;
    }

    if (rhs_imm) {
        mlil::MlilExpr base;
        std::int64_t offset = 0;
        if (extract_add_offset(lhs, base, offset)) {
            const std::int64_t delta = (expr.op == mlil::MlilOp::kAdd)
                                           ? static_cast<std::int64_t>(imm_rhs)
                                           : -static_cast<std::int64_t>(imm_rhs);
            expr = make_add_with_offset(std::move(base), expr.size, offset + delta);
            return true;
        }
    }

    return false;
}

// Simplify multiplication patterns
bool simplify_mul(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kMul || expr.args.size() != 2) {
        return false;
    }
    
    auto& lhs = expr.args[0];
    auto& rhs = expr.args[1];
    std::uint64_t imm_lhs = 0;
    std::uint64_t imm_rhs = 0;
    const bool lhs_imm = get_imm_value(lhs, imm_lhs);
    const bool rhs_imm = get_imm_value(rhs, imm_rhs);
    
    // Constant fold
    if (lhs_imm && rhs_imm) {
        expr = make_imm_expr(expr.size, imm_lhs * imm_rhs);
        return true;
    }
    
    // x * 0 -> 0
    if (rhs_imm && imm_rhs == 0) {
        expr = make_imm_expr(expr.size, 0);
        return true;
    }
    if (lhs_imm && imm_lhs == 0) {
        expr = make_imm_expr(expr.size, 0);
        return true;
    }
    
    // x * 1 -> x
    if (rhs_imm && imm_rhs == 1) {
        mlil::MlilExpr tmp = std::move(lhs);
        expr = std::move(tmp);
        return true;
    }
    if (lhs_imm && imm_lhs == 1) {
        mlil::MlilExpr tmp = std::move(rhs);
        expr = std::move(tmp);
        return true;
    }
    
    // Strength reduction: x * 2^n -> x << n (for small powers of 2)
    if (rhs_imm && imm_rhs > 1 && (imm_rhs & (imm_rhs - 1)) == 0) {
        // imm_rhs is a power of 2
        unsigned shift = 0;
        std::uint64_t v = imm_rhs;
        while (v > 1) { v >>= 1; ++shift; }
        expr = make_binary_expr(mlil::MlilOp::kShl, expr.size, std::move(lhs), make_imm_expr(expr.size, shift));
        return true;
    }
    
    return false;
}

// Simplify XOR patterns
bool simplify_xor(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kXor || expr.args.size() != 2) {
        return false;
    }
    
    auto& lhs = expr.args[0];
    auto& rhs = expr.args[1];
    std::uint64_t imm_lhs = 0;
    std::uint64_t imm_rhs = 0;
    const bool lhs_imm = get_imm_value(lhs, imm_lhs);
    const bool rhs_imm = get_imm_value(rhs, imm_rhs);
    
    // Constant fold
    if (lhs_imm && rhs_imm) {
        expr = make_imm_expr(expr.size, imm_lhs ^ imm_rhs);
        return true;
    }
    
    // x ^ 0 -> x
    if (rhs_imm && imm_rhs == 0) {
        mlil::MlilExpr tmp = std::move(lhs);
        expr = std::move(tmp);
        return true;
    }
    if (lhs_imm && imm_lhs == 0) {
        mlil::MlilExpr tmp = std::move(rhs);
        expr = std::move(tmp);
        return true;
    }
    
    // x ^ x -> 0
    if (expr_key(lhs) == expr_key(rhs) && !expr_key(lhs).empty()) {
        expr = make_imm_expr(expr.size, 0);
        return true;
    }
    
    return false;
}

// Simplify AND patterns
bool simplify_and(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kAnd || expr.args.size() != 2) {
        return false;
    }
    
    auto& lhs = expr.args[0];
    auto& rhs = expr.args[1];
    std::uint64_t imm_lhs = 0;
    std::uint64_t imm_rhs = 0;
    const bool lhs_imm = get_imm_value(lhs, imm_lhs);
    const bool rhs_imm = get_imm_value(rhs, imm_rhs);
    
    // Constant fold
    if (lhs_imm && rhs_imm) {
        expr = make_imm_expr(expr.size, imm_lhs & imm_rhs);
        return true;
    }
    
    // x & 0 -> 0
    if (rhs_imm && imm_rhs == 0) {
        expr = make_imm_expr(expr.size, 0);
        return true;
    }
    if (lhs_imm && imm_lhs == 0) {
        expr = make_imm_expr(expr.size, 0);
        return true;
    }
    
    // x & all-ones -> x (based on size)
    std::uint64_t full_mask = (expr.size > 0 && expr.size < 8) 
        ? ((static_cast<std::uint64_t>(1) << (expr.size * 8)) - 1) 
        : ~static_cast<std::uint64_t>(0);
    if (rhs_imm && imm_rhs == full_mask) {
        mlil::MlilExpr tmp = std::move(lhs);
        expr = std::move(tmp);
        return true;
    }
    
    // x & x -> x
    if (expr_key(lhs) == expr_key(rhs) && !expr_key(lhs).empty()) {
        mlil::MlilExpr tmp = std::move(lhs);
        expr = std::move(tmp);
        return true;
    }
    
    return false;
}

// Simplify OR patterns (non-logical)
bool simplify_or(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kOr || expr.args.size() != 2) {
        return false;
    }
    
    // Skip if this looks like a boolean expression (size 1)
    if (expr.size == 1) {
        return false;
    }
    
    auto& lhs = expr.args[0];
    auto& rhs = expr.args[1];
    std::uint64_t imm_lhs = 0;
    std::uint64_t imm_rhs = 0;
    const bool lhs_imm = get_imm_value(lhs, imm_lhs);
    const bool rhs_imm = get_imm_value(rhs, imm_rhs);
    
    // Constant fold
    if (lhs_imm && rhs_imm) {
        expr = make_imm_expr(expr.size, imm_lhs | imm_rhs);
        return true;
    }
    
    // x | 0 -> x
    if (rhs_imm && imm_rhs == 0) {
        mlil::MlilExpr tmp = std::move(lhs);
        expr = std::move(tmp);
        return true;
    }
    if (lhs_imm && imm_lhs == 0) {
        mlil::MlilExpr tmp = std::move(rhs);
        expr = std::move(tmp);
        return true;
    }
    
    // x | x -> x
    if (expr_key(lhs) == expr_key(rhs) && !expr_key(lhs).empty()) {
        mlil::MlilExpr tmp = std::move(lhs);
        expr = std::move(tmp);
        return true;
    }
    
    return false;
}

bool simplify_compare(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() != 2) {
        return false;
    }
    switch (expr.op) {
        case mlil::MlilOp::kLt:
        case mlil::MlilOp::kLe:
        case mlil::MlilOp::kGt:
        case mlil::MlilOp::kGe:
        case mlil::MlilOp::kEq:
        case mlil::MlilOp::kNe:
            break;
        default:
            return false;
    }

    auto& lhs = expr.args[0];
    auto& rhs = expr.args[1];
    if (lhs.kind == mlil::MlilExprKind::kImm && rhs.kind != mlil::MlilExprKind::kImm) {
        switch (expr.op) {
            case mlil::MlilOp::kLt: expr.op = mlil::MlilOp::kGt; break;
            case mlil::MlilOp::kLe: expr.op = mlil::MlilOp::kGe; break;
            case mlil::MlilOp::kGt: expr.op = mlil::MlilOp::kLt; break;
            case mlil::MlilOp::kGe: expr.op = mlil::MlilOp::kLe; break;
            case mlil::MlilOp::kEq:
            case mlil::MlilOp::kNe:
                break;
            default:
                break;
        }
        std::swap(lhs, rhs);
        return true;
    }
    return false;
}

bool simplify_sub_not(mlil::MlilExpr& expr) {
    // Transform !(x - c) -> x == c
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kNot) {
        return false;
    }
    if (expr.args.empty()) {
        return false;
    }
    auto& sub = expr.args[0];
    if (sub.kind != mlil::MlilExprKind::kOp || sub.op != mlil::MlilOp::kSub) {
        return false;
    }
    // sub has 2 args
    if (sub.args.size() != 2) {
        return false;
    }
    
    // Check for constant on RHS
    std::uint64_t imm = 0;
    if (get_imm_value(sub.args[1], imm)) {
        // Transform to x == c
        auto lhs = std::move(sub.args[0]);
        expr = make_binary_expr(mlil::MlilOp::kEq, expr.size, std::move(lhs), make_imm_expr(sub.size, imm));
        return true;
    }
    
    return false;
}

bool simplify_sub_eq_zero(mlil::MlilExpr& expr) {
    // Transform (x - c) == 0 -> x == c
    // This is how !(x - c) is often represented internally
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kEq) {
        return false;
    }
    if (expr.args.size() != 2) {
        return false;
    }
    
    // Check for (sub) == 0 or 0 == (sub)
    const mlil::MlilExpr* sub_expr = nullptr;
    if (is_zero_imm(expr.args[1]) && expr.args[0].kind == mlil::MlilExprKind::kOp &&
        expr.args[0].op == mlil::MlilOp::kSub) {
        sub_expr = &expr.args[0];
    } else if (is_zero_imm(expr.args[0]) && expr.args[1].kind == mlil::MlilExprKind::kOp &&
               expr.args[1].op == mlil::MlilOp::kSub) {
        sub_expr = &expr.args[1];
    }
    
    if (!sub_expr || sub_expr->args.size() != 2) {
        return false;
    }
    
    // Check for constant on RHS of subtraction
    std::uint64_t imm = 0;
    if (get_imm_value(sub_expr->args[1], imm)) {
        // Transform (x - c) == 0 -> x == c
        mlil::MlilExpr lhs = sub_expr->args[0];
        expr = make_binary_expr(mlil::MlilOp::kEq, expr.size, std::move(lhs), make_imm_expr(sub_expr->size, imm));
        return true;
    }
    
    return false;
}

bool simplify_sub_ne_zero(mlil::MlilExpr& expr) {
    // Transform (x - c) != 0 -> x != c
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kNe) {
        return false;
    }
    if (expr.args.size() != 2) {
        return false;
    }
    
    // Check for (sub) != 0 or 0 != (sub)
    const mlil::MlilExpr* sub_expr = nullptr;
    if (is_zero_imm(expr.args[1]) && expr.args[0].kind == mlil::MlilExprKind::kOp &&
        expr.args[0].op == mlil::MlilOp::kSub) {
        sub_expr = &expr.args[0];
    } else if (is_zero_imm(expr.args[0]) && expr.args[1].kind == mlil::MlilExprKind::kOp &&
               expr.args[1].op == mlil::MlilOp::kSub) {
        sub_expr = &expr.args[1];
    }
    
    if (!sub_expr || sub_expr->args.size() != 2) {
        return false;
    }
    
    // Check for constant on RHS of subtraction
    std::uint64_t imm = 0;
    if (get_imm_value(sub_expr->args[1], imm)) {
        // Transform (x - c) != 0 -> x != c
        mlil::MlilExpr lhs = sub_expr->args[0];
        expr = make_binary_expr(mlil::MlilOp::kNe, expr.size, std::move(lhs), make_imm_expr(sub_expr->size, imm));
        return true;
    }
    
    return false;
}

bool normalize_condition_sub(mlil::MlilExpr& expr) {
    // In condition context, (x - c) is equivalent to (x != c)
    // Transform: (x - c) -> (x != c) when used as a boolean test
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kSub) {
        return false;
    }
    if (expr.args.size() != 2) {
        return false;
    }
    
    // Check for constant on RHS
    std::uint64_t imm = 0;
    if (get_imm_value(expr.args[1], imm)) {
        // Transform to x != c
        auto lhs = std::move(expr.args[0]);
        expr = make_binary_expr(mlil::MlilOp::kNe, expr.size, std::move(lhs), make_imm_expr(expr.size, imm));
        return true;
    }
    
    return false;
}

// Helper: Check if expression matches pattern (x >> 31) or (x >> 0x1f)
// This is sign extraction, commonly used for signed comparison emulation
bool is_sign_extraction(const mlil::MlilExpr& expr, mlil::MlilExpr& inner) {
    if (expr.kind != mlil::MlilExprKind::kOp) {
        return false;
    }
    if (expr.op != mlil::MlilOp::kShr && expr.op != mlil::MlilOp::kSar) {
        return false;
    }
    if (expr.args.size() != 2) {
        return false;
    }
    std::uint64_t shift_amt = 0;
    if (!get_imm_value(expr.args[1], shift_amt)) {
        return false;
    }
    // Check for sign bit extraction (31 for 32-bit, 63 for 64-bit)
    if (shift_amt != 31 && shift_amt != 0x1f && shift_amt != 63 && shift_amt != 0x3f) {
        return false;
    }
    inner = expr.args[0];
    return true;
}

// Simplify patterns like:
// ((x - c) >> 31) != ((x >> 31) & (...))
// which is a verbose signed comparison (x < c) or (x > c)
bool simplify_signed_compare_pattern(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp) {
        return false;
    }
    
    // Pattern 1: or(eq(sub(x, c), 0), complex_overflow_check)
    // This is a signed comparison pattern that represents (x <= c)
    // ARM64 compilers generate this for (i < c+1) where i is the loop counter
    if (expr.op == mlil::MlilOp::kOr && expr.args.size() == 2) {
        // Check for pattern: eq(sub(x, c), 0) || complex_expression
        // First argument might be the equality check
        for (int side = 0; side < 2; ++side) {
            const mlil::MlilExpr& eq_side = (side == 0) ? expr.args[0] : expr.args[1];
            const mlil::MlilExpr& other_side = (side == 0) ? expr.args[1] : expr.args[0];
            
            // Check if eq_side is eq(sub(x, c), 0)
            if (eq_side.kind == mlil::MlilExprKind::kOp &&
                eq_side.op == mlil::MlilOp::kEq &&
                eq_side.args.size() == 2) {
                
                const mlil::MlilExpr* sub_expr = nullptr;
                if (is_zero_imm(eq_side.args[1]) &&
                    eq_side.args[0].kind == mlil::MlilExprKind::kOp &&
                    eq_side.args[0].op == mlil::MlilOp::kSub) {
                    sub_expr = &eq_side.args[0];
                } else if (is_zero_imm(eq_side.args[0]) &&
                           eq_side.args[1].kind == mlil::MlilExprKind::kOp &&
                           eq_side.args[1].op == mlil::MlilOp::kSub) {
                    sub_expr = &eq_side.args[1];
                }
                
                if (sub_expr && sub_expr->args.size() == 2) {
                    std::uint64_t c = 0;
                    if (get_imm_value(sub_expr->args[1], c)) {
                        // Check if other_side is complex (likely overflow check)
                        if (expr_cost(other_side) > 5) {
                            // Check for sign extraction pattern in the complex expression
                            mlil::MlilExpr inner;
                            bool has_sign_extract = false;
                            std::function<void(const mlil::MlilExpr&)> find_sign = [&](const mlil::MlilExpr& e) {
                                if (is_sign_extraction(e, inner)) {
                                    has_sign_extract = true;
                                }
                                for (const auto& arg : e.args) {
                                    find_sign(arg);
                                }
                            };
                            find_sign(other_side);
                            
                            if (has_sign_extract) {
                                // This is a signed loop condition: i <= c (which means i < c+1)
                                // Convert to x < c+1 for cleaner loop bounds
                                // Ensure c+1 doesn't overflow
                                if (c < std::numeric_limits<uint64_t>::max()) {
                                    mlil::MlilExpr x = sub_expr->args[0];
                                    expr = make_binary_expr(mlil::MlilOp::kLt, expr.size,
                                                           std::move(x), make_imm_expr(sub_expr->size, c + 1));
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Fallback: Check if one operand is a simple equality and the other is complex
        mlil::MlilExpr* simple = nullptr;
        mlil::MlilExpr* complex = nullptr;
        
        if (expr.args[0].kind == mlil::MlilExprKind::kOp &&
            expr.args[0].op == mlil::MlilOp::kEq &&
            expr_cost(expr.args[0]) < 5) {
            simple = &expr.args[0];
            complex = &expr.args[1];
        } else if (expr.args[1].kind == mlil::MlilExprKind::kOp &&
                   expr.args[1].op == mlil::MlilOp::kEq &&
                   expr_cost(expr.args[1]) < 5) {
            simple = &expr.args[1];
            complex = &expr.args[0];
        }
        
        if (simple && complex && expr_cost(*complex) > 8) {
            // Check if complex part involves sign extraction (likely overflow check)
            mlil::MlilExpr inner;
            bool has_sign_extract = false;
            std::function<void(const mlil::MlilExpr&)> find_sign = [&](const mlil::MlilExpr& e) {
                if (is_sign_extraction(e, inner)) {
                    has_sign_extract = true;
                }
                for (const auto& arg : e.args) {
                    find_sign(arg);
                }
            };
            find_sign(*complex);
            
            if (has_sign_extract) {
                // The complex expression is likely a signed overflow check
                // Simplify (simple_eq) | (overflow_check) -> (simple_le) or keep simple_eq
                // For now, just convert to <= if the comparison was ==
                mlil::MlilExpr result = *simple;
                result.op = mlil::MlilOp::kLe;  // x == c || overflow -> x <= c
                expr = std::move(result);
                return true;
            }
        }
    }
    
    // Pattern 2: ((x - c) >> 31) != ((x >> 31) & ((x - c) >> 31) != (x >> 31)))
    // This is a convoluted way to express (x < c) for signed comparison
    // Simplify based on structure
    if (expr.op == mlil::MlilOp::kNe && expr.args.size() == 2) {
        mlil::MlilExpr inner_left;
        if (is_sign_extraction(expr.args[0], inner_left)) {
            // Check if inner_left is (x - c)
            if (inner_left.kind == mlil::MlilExprKind::kOp &&
                inner_left.op == mlil::MlilOp::kSub &&
                inner_left.args.size() == 2) {
                std::uint64_t c = 0;
                if (get_imm_value(inner_left.args[1], c)) {
                    // ((x - c) >> 31) != ... -> x < c (for signed)
                    mlil::MlilExpr x = inner_left.args[0];
                    expr = make_binary_expr(mlil::MlilOp::kLt, expr.size,
                                           std::move(x), make_imm_expr(inner_left.size, c));
                    return true;
                }
            }
        }
    }
    
    return false;
}

void normalize_condition_expr(mlil::MlilExpr& expr) {
    // CRITICAL: For complex OR expressions that might be signed loop conditions,
    // try signed compare pattern FIRST before any simplification or recursion.
    // This preserves the original structure: or(eq(sub(x, c), 0), overflow_check)
    // If we simplify children first, eq(sub(x, c), 0) becomes eq(x, c), breaking the pattern.
    if (expr.kind == mlil::MlilExprKind::kOp && expr.op == mlil::MlilOp::kOr && expr.args.size() == 2) {
        int total_cost = expr_cost(expr);
        if (total_cost > 10) {
            // Try signed compare pattern before any other transformation
            if (simplify_signed_compare_pattern(expr)) {
                // After successful pattern match, the result is simple (e.g., x < 9)
                // Optionally simplify the result
                simplify_expr(expr);
                return;
            }
        }
    }
    
    // Now recursively process sub-expressions
    for (auto& arg : expr.args) {
        // Don't recurse into comparison operands - only transform top-level conditions
        if (expr.kind == mlil::MlilExprKind::kOp) {
            switch (expr.op) {
                case mlil::MlilOp::kAnd:
                case mlil::MlilOp::kOr:
                    // For logical operators, recurse into operands as they are also conditions
                    normalize_condition_expr(arg);
                    break;
                case mlil::MlilOp::kNot:
                    // Not's operand is also a condition
                    normalize_condition_expr(arg);
                    break;
                default:
                    // For other operators (comparison, arithmetic), don't transform operands
                    break;
            }
        }
    }
    
    // Apply simplifications
    simplify_expr(expr);
    
    // Try to simplify verbose signed comparison patterns (after standard simplification)
    if (simplify_signed_compare_pattern(expr)) {
        return;
    }
    
    // If top-level is still a subtraction, convert to comparison
    if (expr.kind == mlil::MlilExprKind::kOp && expr.op == mlil::MlilOp::kSub) {
        normalize_condition_sub(expr);
    }
}

bool simplify_not(mlil::MlilExpr& expr) {
    // !imm -> 0 or 1
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kNot) {
        return false;
    }
    if (expr.args.empty()) {
        return false;
    }
    std::uint64_t imm = 0;
    if (get_imm_value(expr.args[0], imm)) {
        // !0 -> 1, !non_zero -> 0
        expr = make_imm_expr(expr.size, imm == 0 ? 1 : 0);
        return true;
    }
    // !!x -> x (if x is boolean)
    if (expr.args[0].kind == mlil::MlilExprKind::kOp &&
        expr.args[0].op == mlil::MlilOp::kNot &&
        !expr.args[0].args.empty()) {
        // Must copy to temporary first to avoid use-after-move
        mlil::MlilExpr inner = std::move(expr.args[0].args[0]);
        expr = std::move(inner);
        return true;
    }
    return false;
}

bool simplify_logical_or(mlil::MlilExpr& expr) {
    // false || x -> x
    // x || false -> x
    // true || x -> true (only if x is simple)
    // x || true -> true (only if x is simple)
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kOr) {
        return false;
    }
    if (expr.args.size() != 2) {
        return false;
    }
    std::uint64_t lhs_imm = 0;
    std::uint64_t rhs_imm = 0;
    bool lhs_is_imm = get_imm_value(expr.args[0], lhs_imm);
    bool rhs_is_imm = get_imm_value(expr.args[1], rhs_imm);
    
    if (lhs_is_imm && lhs_imm == 0) {
        // false || x -> x
        mlil::MlilExpr tmp = std::move(expr.args[1]);
        expr = std::move(tmp);
        return true;
    }
    if (rhs_is_imm && rhs_imm == 0) {
        // x || false -> x
        mlil::MlilExpr tmp = std::move(expr.args[0]);
        expr = std::move(tmp);
        return true;
    }
    
    // Only simplify x || true -> true if x is also simple (not a complex condition)
    // This prevents over-simplification of loop conditions like (i <= 8) || overflow_check
    // where the overflow check part gets simplified to true
    if (lhs_is_imm && lhs_imm != 0) {
        // true || x -> true, but only if x is also simple or constant
        if (rhs_is_imm || expr_cost(expr.args[1]) < 3) {
            expr = make_imm_expr(expr.size, 1);
            return true;
        }
        // Keep the OR if the other side is complex (might be a loop condition)
        return false;
    }
    if (rhs_is_imm && rhs_imm != 0) {
        // x || true -> true, but only if x is also simple or constant
        if (lhs_is_imm || expr_cost(expr.args[0]) < 3) {
            expr = make_imm_expr(expr.size, 1);
            return true;
        }
        // Keep the OR if the other side is complex (might be a loop condition)
        return false;
    }
    
    // Pattern: (A == B) | (A < B) -> A <= B
    // Pattern: (A == B) | (A > B) -> A >= B
    if (expr.args[0].kind == mlil::MlilExprKind::kOp && expr.args[1].kind == mlil::MlilExprKind::kOp) {
        const auto& lhs = expr.args[0];
        const auto& rhs = expr.args[1];
        
        mlil::MlilExpr* eq_expr = nullptr;
        mlil::MlilExpr* cmp_expr = nullptr;
        
        if (lhs.op == mlil::MlilOp::kEq) {
            eq_expr = &expr.args[0];
            cmp_expr = &expr.args[1];
        } else if (rhs.op == mlil::MlilOp::kEq) {
            eq_expr = &expr.args[1];
            cmp_expr = &expr.args[0];
        }
        
        if (eq_expr && cmp_expr && eq_expr->args.size() == 2 && cmp_expr->args.size() == 2) {
            // Check if operands match
            std::string eq_lhs = expr_key(eq_expr->args[0]);
            std::string eq_rhs = expr_key(eq_expr->args[1]);
            std::string cmp_lhs = expr_key(cmp_expr->args[0]);
            std::string cmp_rhs = expr_key(cmp_expr->args[1]);
            
            bool match = (!eq_lhs.empty() && !eq_rhs.empty() && eq_lhs == cmp_lhs && eq_rhs == cmp_rhs);
            
            if (match) {
                if (cmp_expr->op == mlil::MlilOp::kLt) {
                    expr = make_binary_expr(mlil::MlilOp::kLe, expr.size, std::move(eq_expr->args[0]), std::move(eq_expr->args[1]));
                    return true;
                }
                if (cmp_expr->op == mlil::MlilOp::kGt) {
                    expr = make_binary_expr(mlil::MlilOp::kGe, expr.size, std::move(eq_expr->args[0]), std::move(eq_expr->args[1]));
                    return true;
                }
            }
        }
    }

    return false;
}

// Simplify redundant cast expressions
// cast(cast(x)) -> cast(x) (nested casts)
// cast(x) where x.size == expr.size -> x (identity cast)
// cast(imm) -> imm with adjusted size
bool simplify_cast(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kCast) {
        return false;
    }
    if (expr.args.empty()) {
        return false;
    }
    
    auto& inner = expr.args[0];
    
    // Fold nested casts: cast(cast(x)) -> cast(x)
    if (inner.kind == mlil::MlilExprKind::kOp && inner.op == mlil::MlilOp::kCast && !inner.args.empty()) {
        // Take the innermost value and apply the outermost size
        mlil::MlilExpr innermost = std::move(inner.args[0]);
        innermost.size = expr.size;
        expr = std::move(innermost);
        return true;
    }
    
    // Identity cast: cast(x) where sizes match or outer is 0
    if (expr.size == 0 || (inner.size > 0 && inner.size == expr.size)) {
        mlil::MlilExpr tmp = std::move(inner);
        expr = std::move(tmp);
        return true;
    }
    
    // Fold constant casts: cast(imm) -> imm with mask
    std::uint64_t imm = 0;
    if (get_imm_value(inner, imm)) {
        std::uint64_t mask = (expr.size > 0 && expr.size < 8) 
            ? ((static_cast<std::uint64_t>(1) << (expr.size * 8)) - 1) 
            : ~static_cast<std::uint64_t>(0);
        expr = make_imm_expr(expr.size, imm & mask);
        return true;
    }
    
    // For variables and other expressions, remove cast ONLY if sizes match
    // This prevents losing narrowing/widening semantics
    if (inner.kind == mlil::MlilExprKind::kVar || 
        inner.kind == mlil::MlilExprKind::kLoad) {
        if (inner.size == expr.size) {
            mlil::MlilExpr tmp = std::move(inner);
            expr = std::move(tmp);
            return true;
        }
    }
    
    // For binary operations, also remove casts (comparison results, arithmetic, etc.)
    if (inner.kind == mlil::MlilExprKind::kOp) {
        switch (inner.op) {
            case mlil::MlilOp::kAdd:
            case mlil::MlilOp::kSub:
            case mlil::MlilOp::kMul:
            case mlil::MlilOp::kDiv:
            case mlil::MlilOp::kMod:
            case mlil::MlilOp::kAnd:
            case mlil::MlilOp::kOr:
            case mlil::MlilOp::kXor:
            case mlil::MlilOp::kShl:
            case mlil::MlilOp::kShr:
            case mlil::MlilOp::kSar:
            case mlil::MlilOp::kEq:
            case mlil::MlilOp::kNe:
            case mlil::MlilOp::kLt:
            case mlil::MlilOp::kLe:
            case mlil::MlilOp::kGt:
            case mlil::MlilOp::kGe: {
                mlil::MlilExpr tmp = std::move(inner);
                if (tmp.size == 0) {
                    tmp.size = expr.size;
                }
                expr = std::move(tmp);
                return true;
            }
            default:
                break;
        }
    }
    
    return false;
}

bool simplify_select(mlil::MlilExpr& expr) {
    // cond ? 1 : 0 -> cond
    // cond ? 0 : 1 -> !cond
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kSelect) {
        return false;
    }
    if (expr.args.size() != 3) {
        return false;
    }
    
    std::uint64_t true_val = 0;
    std::uint64_t false_val = 0;
    bool true_is_imm = get_imm_value(expr.args[1], true_val);
    bool false_is_imm = get_imm_value(expr.args[2], false_val);
    
    if (true_is_imm && false_is_imm) {
        if (true_val == 1 && false_val == 0) {
            // cond ? 1 : 0 -> cond
            // (Assuming cond is boolean, or we cast it)
            mlil::MlilExpr tmp = std::move(expr.args[0]);
            expr = std::move(tmp);
            return true;
        }
        if (true_val == 0 && false_val == 1) {
            // cond ? 0 : 1 -> !cond
            mlil::MlilExpr cond = std::move(expr.args[0]);
            expr = make_binary_expr(mlil::MlilOp::kNot, expr.size, std::move(cond), mlil::MlilExpr{});
            expr.args.pop_back(); // kNot only needs 1 arg
            return true;
        }
    }
    return false;
}

bool simplify_logical_and(mlil::MlilExpr& expr) {
    // true && x -> x
    // x && true -> x
    // false && x -> false
    // x && false -> false
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kAnd) {
        return false;
    }
    if (expr.args.size() != 2) {
        return false;
    }
    std::uint64_t lhs_imm = 0;
    std::uint64_t rhs_imm = 0;
    bool lhs_is_imm = get_imm_value(expr.args[0], lhs_imm);
    bool rhs_is_imm = get_imm_value(expr.args[1], rhs_imm);
    
    if (lhs_is_imm && lhs_imm != 0) {
        // true && x -> x
        mlil::MlilExpr tmp = std::move(expr.args[1]);
        expr = std::move(tmp);
        return true;
    }
    if (rhs_is_imm && rhs_imm != 0) {
        // x && true -> x
        mlil::MlilExpr tmp = std::move(expr.args[0]);
        expr = std::move(tmp);
        return true;
    }
    if (lhs_is_imm && lhs_imm == 0) {
        // false && x -> false
        expr = make_imm_expr(expr.size, 0);
        return true;
    }
    if (rhs_is_imm && rhs_imm == 0) {
        // x && false -> false
        expr = make_imm_expr(expr.size, 0);
        return true;
    }
    return false;
}

bool simplify_bitwise_ops(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() != 2) {
        return false;
    }
    
    std::uint64_t lhs_imm = 0;
    std::uint64_t rhs_imm = 0;
    bool lhs_is_imm = get_imm_value(expr.args[0], lhs_imm);
    bool rhs_is_imm = get_imm_value(expr.args[1], rhs_imm);
    
    // Constant fold bitwise operations
    if (lhs_is_imm && rhs_is_imm) {
        std::uint64_t result = 0;
        switch (expr.op) {
            case mlil::MlilOp::kAnd: result = lhs_imm & rhs_imm; break;
            case mlil::MlilOp::kOr: result = lhs_imm | rhs_imm; break;
            case mlil::MlilOp::kXor: result = lhs_imm ^ rhs_imm; break;
            case mlil::MlilOp::kShl: result = lhs_imm << (rhs_imm & 0x3f); break;
            case mlil::MlilOp::kShr: result = lhs_imm >> (rhs_imm & 0x3f); break;
            case mlil::MlilOp::kSar: {
                // Arithmetic shift right - need to handle sign
                std::int64_t signed_val = static_cast<std::int64_t>(lhs_imm);
                result = static_cast<std::uint64_t>(signed_val >> (rhs_imm & 0x3f));
                break;
            }
            default:
                return false;
        }
        expr = make_imm_expr(expr.size, result);
        return true;
    }
    
    return false;
}

bool simplify_compare_constants(mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() != 2) {
        return false;
    }
    
    std::uint64_t lhs_imm = 0;
    std::uint64_t rhs_imm = 0;
    bool lhs_is_imm = get_imm_value(expr.args[0], lhs_imm);
    bool rhs_is_imm = get_imm_value(expr.args[1], rhs_imm);
    
    if (!lhs_is_imm || !rhs_is_imm) {
        return false;
    }
    
    bool result = false;
    switch (expr.op) {
        case mlil::MlilOp::kEq: result = (lhs_imm == rhs_imm); break;
        case mlil::MlilOp::kNe: result = (lhs_imm != rhs_imm); break;
        case mlil::MlilOp::kLt: result = (static_cast<std::int64_t>(lhs_imm) < static_cast<std::int64_t>(rhs_imm)); break;
        case mlil::MlilOp::kLe: result = (static_cast<std::int64_t>(lhs_imm) <= static_cast<std::int64_t>(rhs_imm)); break;
        case mlil::MlilOp::kGt: result = (static_cast<std::int64_t>(lhs_imm) > static_cast<std::int64_t>(rhs_imm)); break;
        case mlil::MlilOp::kGe: result = (static_cast<std::int64_t>(lhs_imm) >= static_cast<std::int64_t>(rhs_imm)); break;
        default:
            return false;
    }
    expr = make_imm_expr(1, result ? 1 : 0);
    return true;
}

void simplify_expr(mlil::MlilExpr& expr) {
    // For OR expressions with complex operands, try signed compare pattern FIRST
    // before simplifying children, to preserve the original structure
    if (expr.kind == mlil::MlilExprKind::kOp && expr.op == mlil::MlilOp::kOr && expr.args.size() == 2) {
        // Check if this looks like a signed loop condition pattern
        // Pattern: or(eq(sub(x, c), 0), complex_overflow_check)
        int total_cost = expr_cost(expr);
        if (total_cost > 10) {
            // Try to simplify signed compare pattern before any other simplification
            if (simplify_signed_compare_pattern(expr)) {
                // After simplification, continue to simplify the result
                simplify_expr(expr);
                return;
            }
        }
    }
    
    // First simplify children (bottom-up)
    for (std::size_t i = 0; i < expr.args.size(); ++i) {
        simplify_expr(expr.args[i]);
    }
    
    if (expr.kind != mlil::MlilExprKind::kOp) {
        return;
    }

    // Apply simplifications - only one pass, no recursive re-simplify
    // For OR expressions, try signed compare pattern first (after children are simplified)
    if (expr.op == mlil::MlilOp::kOr) {
        if (simplify_signed_compare_pattern(expr)) {
            return;
        }
    }
    
    // Constant folding for NOT
    if (simplify_not(expr)) {
        return;
    }
    
    // Constant folding for logical OR
    if (simplify_logical_or(expr)) {
        return;
    }
    
    // Constant folding for logical AND
    if (simplify_logical_and(expr)) {
        return;
    }
    
    // Constant folding for bitwise operations
    if (simplify_bitwise_ops(expr)) {
        return;
    }
    
    // Constant folding for comparisons
    if (simplify_compare_constants(expr)) {
        return;
    }

    if (simplify_sub_not(expr)) {
        return;
    }
    if (simplify_sub_eq_zero(expr)) {
        return;
    }
    if (simplify_sub_ne_zero(expr)) {
        return;
    }
    
    if (simplify_select(expr)) {
        return;
    }

    // Enhanced cast simplification
    if (simplify_cast(expr)) {
        return;
    }
    
    if (expr.kind == mlil::MlilExprKind::kOp) {
        if (expr.op == mlil::MlilOp::kAdd || expr.op == mlil::MlilOp::kSub) {
            simplify_add_sub(expr);
        } else {
            simplify_compare(expr);
        }
        
        // Try to simplify verbose signed comparison patterns (bottom-up)
        if (expr.op == mlil::MlilOp::kOr || expr.op == mlil::MlilOp::kNe) {
            simplify_signed_compare_pattern(expr);
        }
    }
}

bool is_control_stmt(const Stmt& stmt) {
    return stmt.kind == StmtKind::kIf ||
           stmt.kind == StmtKind::kWhile ||
           stmt.kind == StmtKind::kDoWhile ||
           stmt.kind == StmtKind::kFor;
}

bool stmt_uses_var(const Stmt& stmt, const std::string& name) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            return expr_uses_var(stmt.expr, name);
        case StmtKind::kStore:
            return expr_uses_var(stmt.target, name) || expr_uses_var(stmt.expr, name);
        case StmtKind::kCall:
            if (expr_uses_var(stmt.target, name)) {
                return true;
            }
            for (const auto& arg : stmt.args) {
                if (expr_uses_var(arg, name)) {
                    return true;
                }
            }
            return false;
        case StmtKind::kReturn:
            return expr_uses_var(stmt.expr, name);
        case StmtKind::kIf:
            if (expr_uses_var(stmt.condition, name)) {
                return true;
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
            return false;
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
        case StmtKind::kFor:
            if (expr_uses_var(stmt.condition, name)) {
                return true;
            }
            for (const auto& inner : stmt.body) {
                if (stmt_uses_var(inner, name)) {
                    return true;
                }
            }
            return false;
        default:
            return false;
    }
}

bool stmt_defines_var(const Stmt& stmt, const std::string& name) {
    if (stmt.kind == StmtKind::kAssign && stmt.var.name == name) {
        return true;
    }
    if (stmt.kind == StmtKind::kCall) {
        for (const auto& ret : stmt.returns) {
            if (ret.name == name) {
                return true;
            }
        }
    }
    return false;
}

} // namespace engine::decompiler