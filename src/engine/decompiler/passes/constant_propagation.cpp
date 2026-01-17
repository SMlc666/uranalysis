#include "engine/decompiler/passes/constant_propagation.h"
#include "engine/decompiler/transforms.h"
#include <unordered_set>
#include <algorithm>

namespace engine::decompiler::passes {

namespace {

void collect_modified_vars(const std::vector<Stmt>& stmts, std::unordered_set<std::string>& modified) {
    for (const auto& stmt : stmts) {
        switch (stmt.kind) {
            case StmtKind::kAssign:
                modified.insert(stmt.var.name);
                break;
            case StmtKind::kCall:
                for (const auto& ret : stmt.returns) modified.insert(ret.name);
                break;
            case StmtKind::kIf:
                collect_modified_vars(stmt.then_body, modified);
                collect_modified_vars(stmt.else_body, modified);
                break;
            case StmtKind::kWhile:
            case StmtKind::kDoWhile:
                collect_modified_vars(stmt.body, modified);
                break;
            case StmtKind::kFor:
                collect_modified_vars(stmt.then_body, modified);
                collect_modified_vars(stmt.else_body, modified);
                collect_modified_vars(stmt.body, modified);
                break;
            case StmtKind::kSwitch:
                for (const auto& cb : stmt.case_bodies) collect_modified_vars(cb, modified);
                collect_modified_vars(stmt.default_body, modified);
                break;
            default: break;
        }
    }
}

bool evaluate_expr(const mlil::MlilExpr& expr, const std::unordered_map<std::string, std::uint64_t>& constants, std::uint64_t& out_val) {
    if (expr.kind == mlil::MlilExprKind::kImm) {
        out_val = expr.imm;
        return true;
    }
    if (expr.kind == mlil::MlilExprKind::kVar) {
        auto it = constants.find(expr.var.name);
        if (it != constants.end()) {
            out_val = it->second;
            return true;
        }
        return false;
    }
    if (expr.kind == mlil::MlilExprKind::kOp) {
        if (expr.args.size() == 1) {
            std::uint64_t val;
            if (evaluate_expr(expr.args[0], constants, val)) {
                switch (expr.op) {
                    case mlil::MlilOp::kNot: out_val = ~val; return true;
                    case mlil::MlilOp::kNeg: out_val = -val; return true;
                    default: break;
                }
            }
        } else if (expr.args.size() == 2) {
            std::uint64_t lhs, rhs;
            if (evaluate_expr(expr.args[0], constants, lhs) && evaluate_expr(expr.args[1], constants, rhs)) {
                switch (expr.op) {
                    case mlil::MlilOp::kAdd: out_val = lhs + rhs; return true;
                    case mlil::MlilOp::kSub: out_val = lhs - rhs; return true;
                    case mlil::MlilOp::kMul: out_val = lhs * rhs; return true;
                    case mlil::MlilOp::kDiv: if (rhs != 0) { out_val = lhs / rhs; return true; } break;
                    case mlil::MlilOp::kAnd: out_val = lhs & rhs; return true;
                    case mlil::MlilOp::kOr: out_val = lhs | rhs; return true;
                    case mlil::MlilOp::kXor: out_val = lhs ^ rhs; return true;
                    case mlil::MlilOp::kShl: out_val = lhs << rhs; return true;
                    case mlil::MlilOp::kShr: out_val = lhs >> rhs; return true;
                    default: break;
                }
            }
        }
    }
    return false;
}

void replace_constants(mlil::MlilExpr& expr, const std::unordered_map<std::string, std::uint64_t>& constants) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        auto it = constants.find(expr.var.name);
        if (it != constants.end()) {
            expr.kind = mlil::MlilExprKind::kImm;
            expr.imm = it->second;
        }
    } else {
        for (auto& arg : expr.args) replace_constants(arg, constants);
        std::uint64_t val;
        if (evaluate_expr(expr, constants, val)) {
            expr.kind = mlil::MlilExprKind::kImm;
            expr.imm = val;
            expr.args.clear();
        }
    }
}

void process_stmts(std::vector<Stmt>& stmts, std::unordered_map<std::string, std::uint64_t>& constants) {
    for (auto& stmt : stmts) {
        switch (stmt.kind) {
            case StmtKind::kAssign: {
                replace_constants(stmt.expr, constants);
                std::uint64_t val;
                if (evaluate_expr(stmt.expr, constants, val)) {
                    constants[stmt.var.name] = val;
                } else {
                    constants.erase(stmt.var.name);
                }
                break;
            }
            case StmtKind::kStore:
                replace_constants(stmt.target, constants);
                replace_constants(stmt.expr, constants);
                break;
            case StmtKind::kCall:
                for (auto& arg : stmt.args) replace_constants(arg, constants);
                for (const auto& ret : stmt.returns) constants.erase(ret.name);
                break;
            case StmtKind::kReturn:
                replace_constants(stmt.expr, constants);
                break;
            case StmtKind::kIf: {
                replace_constants(stmt.condition, constants);
                auto then_constants = constants;
                process_stmts(stmt.then_body, then_constants);
                auto else_constants = constants;
                process_stmts(stmt.else_body, else_constants);
                
                std::unordered_map<std::string, std::uint64_t> merged;
                for (const auto& [name, val] : constants) {
                    auto it_then = then_constants.find(name);
                    auto it_else = else_constants.find(name);
                    if (it_then != then_constants.end() && it_else != else_constants.end()) {
                        if (it_then->second == it_else->second) merged[name] = it_then->second;
                    }
                }
                for (const auto& [name, val] : then_constants) {
                    if (constants.find(name) == constants.end()) {
                         auto it_else = else_constants.find(name);
                         if (it_else != else_constants.end() && it_else->second == val) merged[name] = val;
                    }
                }
                constants = merged;
                break;
            }
            case StmtKind::kWhile:
            case StmtKind::kDoWhile: {
                std::unordered_set<std::string> modified;
                collect_modified_vars(stmt.body, modified);
                for (const auto& name : modified) constants.erase(name);
                replace_constants(stmt.condition, constants);
                auto body_constants = constants;
                process_stmts(stmt.body, body_constants);
                break;
            }
            case StmtKind::kFor: {
                process_stmts(stmt.then_body, constants);
                std::unordered_set<std::string> modified;
                collect_modified_vars(stmt.body, modified);
                collect_modified_vars(stmt.else_body, modified);
                for (const auto& name : modified) constants.erase(name);
                replace_constants(stmt.condition, constants);
                auto body_constants = constants;
                process_stmts(stmt.body, body_constants);
                auto inc_constants = constants;
                process_stmts(stmt.else_body, inc_constants);
                break;
            }
            case StmtKind::kSwitch: {
                replace_constants(stmt.condition, constants);
                std::unordered_set<std::string> modified;
                for (const auto& cb : stmt.case_bodies) collect_modified_vars(cb, modified);
                collect_modified_vars(stmt.default_body, modified);
                for (const auto& name : modified) constants.erase(name);
                for (auto& cb : stmt.case_bodies) {
                    auto case_consts = constants;
                    process_stmts(cb, case_consts);
                }
                auto def_consts = constants;
                process_stmts(stmt.default_body, def_consts);
                break;
            }
            default: break;
        }
    }
}

} // namespace

void propagate_constants(Function& function) {
    std::unordered_map<std::string, std::uint64_t> constants = function.initial_values;
    process_stmts(function.stmts, constants);
}

} // namespace engine::decompiler::passes
