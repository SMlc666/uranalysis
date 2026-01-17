#include "client/formatters/ir.h"

#include <sstream>

#include "client/formatters/address.h"
#include "engine/debug/ir_dump.h"

namespace client::fmt {

// ============================================================================
// LLIR Formatting - delegate to engine::debug
// ============================================================================

std::string format_reg(const engine::llir::RegRef& reg) {
    return engine::debug::dump(reg);
}

std::string format_var(const engine::llir::VarRef& var) {
    return engine::debug::dump(var);
}

const char* llir_op_name(engine::llir::LlilOp op) {
    return engine::debug::op_name(op);
}

std::string format_llir_expr(const engine::llir::LlilExpr& expr) {
    return engine::debug::dump(expr);
}

std::string format_llir_stmt(const engine::llir::LlilStmt& stmt) {
    return engine::debug::dump(stmt);
}

void format_llir_function(const engine::llir::Function& func, std::vector<std::string>& lines) {
    engine::debug::dump(func, lines);
}

std::uint64_t discovered_size(const engine::llir::Function& function) {
    return engine::debug::discovered_size(function);
}

// ============================================================================
// MLIL Formatting - delegate to engine::debug
// ============================================================================

std::string format_mlil_var(const engine::mlil::VarRef& var) {
    return engine::debug::dump(var);
}

const char* mlil_op_name(engine::mlil::MlilOp op) {
    return engine::debug::op_name(op);
}

std::string format_mlil_expr(const engine::mlil::MlilExpr& expr) {
    return engine::debug::dump(expr);
}

std::string format_mlil_stmt(const engine::mlil::MlilStmt& stmt) {
    return engine::debug::dump(stmt);
}

void format_mlil_function(const engine::mlil::Function& func, std::vector<std::string>& lines) {
    engine::debug::dump(func, lines);
}

// ============================================================================
// HLIL Formatting - delegate to engine::debug with rename support
// ============================================================================

void apply_hlil_var_renames(engine::mlil::MlilExpr& expr, const HlilVarRenameMap& renames) {
    if (expr.kind == engine::mlil::MlilExprKind::kVar) {
        auto it = renames.find(expr.var.name);
        if (it != renames.end()) {
            expr.var.name = it->second;
        }
        // HLIL is displayed as non-SSA for readability.
        expr.var.version = -1;
    }
    for (auto& arg : expr.args) {
        apply_hlil_var_renames(arg, renames);
    }
}

engine::mlil::VarRef apply_hlil_var_renames(engine::mlil::VarRef var, const HlilVarRenameMap& renames) {
    auto it = renames.find(var.name);
    if (it != renames.end()) {
        var.name = it->second;
    }
    // HLIL is displayed as non-SSA for readability.
    var.version = -1;
    return var;
}

std::string format_hlil_expr(const engine::hlil::Expr& expr, const HlilVarRenameMap& renames) {
    engine::mlil::MlilExpr tmp = expr;
    apply_hlil_var_renames(tmp, renames);
    // Use options without SSA versions for HLIL
    engine::debug::DumpOptions opts;
    opts.include_ssa_versions = false;
    return engine::debug::dump(tmp, opts);
}

std::string format_hlil_var(const engine::hlil::VarRef& var, const HlilVarRenameMap& renames) {
    engine::mlil::VarRef renamed = apply_hlil_var_renames(var, renames);
    engine::debug::DumpOptions opts;
    opts.include_ssa_versions = false;
    return engine::debug::dump(renamed, opts);
}

std::string format_hlil_stmt(const engine::hlil::HlilStmt& stmt,
                             const HlilVarRenameMap& renames,
                             int indent) {
    // For individual statement formatting with custom renames,
    // we still need some local logic since engine::debug doesn't expose
    // the rename map parameter in single-statement API.
    // Delegate to the block formatter for consistency.
    const std::string pad(static_cast<std::size_t>(indent) * 4, ' ');
    std::string out;
    
    switch (stmt.kind) {
        case engine::hlil::HlilStmtKind::kNop:
            out = pad + "nop";
            break;
        case engine::hlil::HlilStmtKind::kAssign:
            out = pad + format_hlil_var(stmt.var, renames) + " = " + format_hlil_expr(stmt.expr, renames);
            break;
        case engine::hlil::HlilStmtKind::kStore:
            out = pad + "store " + format_hlil_expr(stmt.target, renames) + " <- " +
                  format_hlil_expr(stmt.expr, renames);
            break;
        case engine::hlil::HlilStmtKind::kCall: {
            std::ostringstream oss;
            oss << pad;
            if (!stmt.returns.empty()) {
                for (std::size_t i = 0; i < stmt.returns.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << format_hlil_var(stmt.returns[i], renames);
                }
                oss << " = ";
            }
            oss << "call " << format_hlil_expr(stmt.target, renames) << "(";
            for (std::size_t i = 0; i < stmt.args.size(); ++i) {
                if (i > 0) {
                    oss << ", ";
                }
                oss << format_hlil_expr(stmt.args[i], renames);
            }
            oss << ")";
            out = oss.str();
            break;
        }
        case engine::hlil::HlilStmtKind::kRet:
            out = pad + "ret";
            if (stmt.expr.kind != engine::mlil::MlilExprKind::kInvalid) {
                out += " " + format_hlil_expr(stmt.expr, renames);
            }
            break;
        case engine::hlil::HlilStmtKind::kLabel:
            out = pad + "label " + hex(stmt.address);
            break;
        case engine::hlil::HlilStmtKind::kGoto:
            out = pad + "goto " + hex(stmt.address);
            break;
        case engine::hlil::HlilStmtKind::kBreak:
            out = pad + "break";
            break;
        case engine::hlil::HlilStmtKind::kContinue:
            out = pad + "continue";
            break;
        case engine::hlil::HlilStmtKind::kIf: {
            out = pad + "if (" + format_hlil_expr(stmt.condition, renames) + ") {";
            break;
        }
        case engine::hlil::HlilStmtKind::kWhile: {
            out = pad + "while (" + format_hlil_expr(stmt.condition, renames) + ") {";
            break;
        }
        case engine::hlil::HlilStmtKind::kDoWhile:
            out = pad + "do {";
            break;
        case engine::hlil::HlilStmtKind::kFor:
            out = pad + "for (...) {";
            break;
    }
    if (!stmt.comment.empty()) {
        out += " ; " + stmt.comment;
    }
    return out;
}

void format_hlil_stmt_block(const std::vector<engine::hlil::HlilStmt>& stmts,
                            int indent,
                            const HlilVarRenameMap& renames,
                            std::vector<std::string>& lines) {
    for (const auto& stmt : stmts) {
        if (stmt.kind == engine::hlil::HlilStmtKind::kIf) {
            lines.push_back(format_hlil_stmt(stmt, renames, indent));
            format_hlil_stmt_block(stmt.then_body, indent + 1, renames, lines);
            if (!stmt.else_body.empty()) {
                lines.push_back(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "} else {");
                format_hlil_stmt_block(stmt.else_body, indent + 1, renames, lines);
            }
            lines.push_back(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "}");
            continue;
        }
        if (stmt.kind == engine::hlil::HlilStmtKind::kWhile) {
            lines.push_back(format_hlil_stmt(stmt, renames, indent));
            format_hlil_stmt_block(stmt.body, indent + 1, renames, lines);
            lines.push_back(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "}");
            continue;
        }
        if (stmt.kind == engine::hlil::HlilStmtKind::kDoWhile) {
            lines.push_back(format_hlil_stmt(stmt, renames, indent));
            format_hlil_stmt_block(stmt.body, indent + 1, renames, lines);
            lines.push_back(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "} while (" + 
                           format_hlil_expr(stmt.condition, renames) + ")");
            continue;
        }
        lines.push_back(format_hlil_stmt(stmt, renames, indent));
    }
}

void format_hlil_function(const engine::hlil::Function& func, std::vector<std::string>& lines) {
    // Delegate to engine::debug which handles var_renames internally
    engine::debug::dump(func, lines);
}

}  // namespace client::fmt
