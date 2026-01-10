#include "engine/decompiler/transforms.h"

#include <algorithm>
#include <functional>
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
        expr = lhs;
        return true;
    }
    if (expr.op == mlil::MlilOp::kSub && rhs_imm && imm_rhs == 0) {
        expr = lhs;
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

void simplify_expr(mlil::MlilExpr& expr) {
    for (auto& arg : expr.args) {
        simplify_expr(arg);
    }
    if (expr.kind != mlil::MlilExprKind::kOp) {
        return;
    }
    if (expr.op == mlil::MlilOp::kCast && expr.args.size() == 1) {
        expr = expr.args[0];
        return;
    }
    if (expr.op == mlil::MlilOp::kAdd || expr.op == mlil::MlilOp::kSub) {
        simplify_add_sub(expr);
    } else {
        simplify_compare(expr);
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