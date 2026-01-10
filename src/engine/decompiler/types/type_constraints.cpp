#include "engine/decompiler/types/type_constraints.h"

#include <cstddef>
#include <string>

namespace engine::decompiler::types {

namespace {

SsaVarKey key_from_var(const mlil::VarRef& var) {
    SsaVarKey key;
    key.name = var.name;
    key.version = var.version;
    return key;
}

std::uint32_t bits_from_size(std::size_t size) {
    if (size == 0) {
        return 0;
    }
    return static_cast<std::uint32_t>(size * 8);
}

void hint_from_type_name(const mlil::VarRef& var, TypeSolver& solver) {
    if (var.type_name.empty()) {
        return;
    }
    if (var.type_name.size() < 2) {
        return;
    }
    char prefix = var.type_name[0];
    std::string digits = var.type_name.substr(1);
    std::uint32_t bits = 0;
    for (char c : digits) {
        if (c < '0' || c > '9') {
            return;
        }
        bits = bits * 10 + static_cast<std::uint32_t>(c - '0');
    }
    if (bits == 0) {
        return;
    }
    if (prefix == 'i') {
        solver.hint_int(key_from_var(var), bits);
    } else if (prefix == 'u') {
        solver.hint_uint(key_from_var(var), bits);
    }
}

void hint_var(const mlil::VarRef& var, TypeSolver& solver) {
    if (var.name.empty()) {
        return;
    }
    const SsaVarKey key = key_from_var(var);
    solver.add_var(key);
    // Do not force the type to the register width. 
    // Let the operations (loads, stores, calls) drive the type precision.
    // if (var.size != 0) {
    //    solver.hint_uint(key, bits_from_size(var.size));
    // }
    hint_from_type_name(var, solver);
}

void hint_address_expr(const mlil::MlilExpr& expr,
                       std::uint32_t access_bits,
                       TypeSolver& solver);

void hint_expr(const mlil::MlilExpr& expr, TypeSolver& solver) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        hint_var(expr.var, solver);
    }
    if (expr.kind == mlil::MlilExprKind::kLoad) {
        if (!expr.args.empty()) {
            hint_address_expr(expr.args.front(), bits_from_size(expr.size), solver);
        }
    }
    for (const auto& arg : expr.args) {
        hint_expr(arg, solver);
    }
}

void hint_address_expr(const mlil::MlilExpr& expr,
                       std::uint32_t access_bits,
                       TypeSolver& solver) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        hint_var(expr.var, solver);
        solver.hint_ptr(key_from_var(expr.var), access_bits);
        return;
    }
    if (expr.kind == mlil::MlilExprKind::kOp &&
        (expr.op == mlil::MlilOp::kAdd || expr.op == mlil::MlilOp::kSub)) {
        if (expr.args.size() == 2) {
            const auto& lhs = expr.args[0];
            const auto& rhs = expr.args[1];
            if (lhs.kind == mlil::MlilExprKind::kVar) {
                hint_var(lhs.var, solver);
                // Don't force ptr type on operands of arithmetic; one might be an index
            }
            if (rhs.kind == mlil::MlilExprKind::kVar) {
                hint_var(rhs.var, solver);
                // Don't force ptr type on operands of arithmetic; one might be an index
            }
        }
    }
    for (const auto& arg : expr.args) {
        hint_expr(arg, solver);
    }
}

void constrain_assignment(const mlil::VarRef& dst,
                          const mlil::MlilExpr& expr,
                          TypeSolver& solver) {
    hint_var(dst, solver);
    if (expr.kind == mlil::MlilExprKind::kVar) {
        hint_var(expr.var, solver);
        solver.add_equal(key_from_var(dst), key_from_var(expr.var));
        return;
    }
    if (expr.kind == mlil::MlilExprKind::kImm) {
        solver.hint_uint(key_from_var(dst), bits_from_size(dst.size));
        return;
    }
    if (expr.kind == mlil::MlilExprKind::kLoad) {
        solver.hint_uint(key_from_var(dst), bits_from_size(expr.size));
    }
    hint_expr(expr, solver);
}

void constrain_expr_op(const mlil::MlilExpr& expr, TypeSolver& solver) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.args.size() < 2) {
        return;
    }
    const auto& lhs = expr.args[0];
    const auto& rhs = expr.args[1];
    if (lhs.kind == mlil::MlilExprKind::kVar && rhs.kind == mlil::MlilExprKind::kVar) {
        hint_var(lhs.var, solver);
        hint_var(rhs.var, solver);
        if (expr.op == mlil::MlilOp::kEq || expr.op == mlil::MlilOp::kNe ||
            expr.op == mlil::MlilOp::kLt || expr.op == mlil::MlilOp::kLe ||
            expr.op == mlil::MlilOp::kGt || expr.op == mlil::MlilOp::kGe) {
            solver.add_equal(key_from_var(lhs.var), key_from_var(rhs.var));
        }
    }
}

void constrain_stmt(const mlil::MlilStmt& stmt, TypeSolver& solver) {
    switch (stmt.kind) {
        case mlil::MlilStmtKind::kAssign:
            constrain_assignment(stmt.var, stmt.expr, solver);
            break;
        case mlil::MlilStmtKind::kStore:
            // Do not force the pointer type based on the store size.
            // Let the pointer's definition (from arithmetic or params) drive the type.
            hint_address_expr(stmt.target, 0, solver);
            hint_expr(stmt.expr, solver);
            break;
        case mlil::MlilStmtKind::kCall:
            hint_expr(stmt.target, solver);
            if (stmt.target.kind == mlil::MlilExprKind::kVar) {
                solver.hint_ptr(key_from_var(stmt.target.var), 0);
            }
            for (const auto& arg : stmt.args) {
                hint_expr(arg, solver);
            }
            for (const auto& ret : stmt.returns) {
                hint_var(ret, solver);
            }
            break;
        case mlil::MlilStmtKind::kJump:
            hint_expr(stmt.target, solver);
            break;
        case mlil::MlilStmtKind::kCJump:
            hint_expr(stmt.condition, solver);
            hint_expr(stmt.target, solver);
            constrain_expr_op(stmt.condition, solver);
            break;
        case mlil::MlilStmtKind::kRet:
            hint_expr(stmt.expr, solver);
            break;
        case mlil::MlilStmtKind::kPhi:
            hint_var(stmt.var, solver);
            for (const auto& arg : stmt.expr.args) {
                if (arg.kind == mlil::MlilExprKind::kVar) {
                    hint_var(arg.var, solver);
                    solver.add_equal(key_from_var(stmt.var), key_from_var(arg.var));
                } else {
                    hint_expr(arg, solver);
                }
            }
            break;
        default:
            hint_expr(stmt.expr, solver);
            hint_expr(stmt.target, solver);
            hint_expr(stmt.condition, solver);
            break;
    }
}

}  // namespace

void collect_constraints_mlil(const mlil::Function& function, TypeSolver& solver) {
    for (const auto& block : function.blocks) {
        for (const auto& phi : block.phis) {
            constrain_stmt(phi, solver);
        }
        for (const auto& inst : block.instructions) {
            for (const auto& stmt : inst.stmts) {
                constrain_stmt(stmt, solver);
            }
        }
    }
}

}  // namespace engine::decompiler::types
