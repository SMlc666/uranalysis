#include "client/formatters/ir.h"

#include <sstream>

#include "client/formatters/address.h"

namespace client::fmt {

// ============================================================================
// LLIR Formatting
// ============================================================================

std::string format_reg(const engine::llir::RegRef& reg) {
    if (reg.name.empty()) {
        return "<reg>";
    }
    if (reg.version >= 0) {
        return reg.name + "#" + std::to_string(reg.version);
    }
    return reg.name;
}

std::string format_var(const engine::llir::VarRef& var) {
    if (var.name.empty()) {
        return "<var>";
    }
    std::string name = var.name;
    if (!var.type_name.empty()) {
        name += ":" + var.type_name;
    }
    if (var.version >= 0) {
        return name + "#" + std::to_string(var.version);
    }
    return name;
}

const char* llir_op_name(engine::llir::LlilOp op) {
    switch (op) {
        case engine::llir::LlilOp::kAdd:
            return "add";
        case engine::llir::LlilOp::kSub:
            return "sub";
        case engine::llir::LlilOp::kMul:
            return "mul";
        case engine::llir::LlilOp::kDiv:
            return "div";
        case engine::llir::LlilOp::kMod:
            return "mod";
        case engine::llir::LlilOp::kAnd:
            return "and";
        case engine::llir::LlilOp::kOr:
            return "or";
        case engine::llir::LlilOp::kXor:
            return "xor";
        case engine::llir::LlilOp::kShl:
            return "shl";
        case engine::llir::LlilOp::kShr:
            return "shr";
        case engine::llir::LlilOp::kSar:
            return "sar";
        case engine::llir::LlilOp::kRor:
            return "ror";
        case engine::llir::LlilOp::kNot:
            return "not";
        case engine::llir::LlilOp::kNeg:
            return "neg";
        case engine::llir::LlilOp::kAbs:
            return "abs";
        case engine::llir::LlilOp::kMin:
            return "min";
        case engine::llir::LlilOp::kMax:
            return "max";
        case engine::llir::LlilOp::kBswap:
            return "bswap";
        case engine::llir::LlilOp::kClz:
            return "clz";
        case engine::llir::LlilOp::kRbit:
            return "rbit";
        case engine::llir::LlilOp::kSqrt:
            return "sqrt";
        case engine::llir::LlilOp::kCast:
            return "cast";
        case engine::llir::LlilOp::kSelect:
            return "select";
        case engine::llir::LlilOp::kEq:
            return "eq";
        case engine::llir::LlilOp::kNe:
            return "ne";
        case engine::llir::LlilOp::kLt:
            return "lt";
        case engine::llir::LlilOp::kLe:
            return "le";
        case engine::llir::LlilOp::kGt:
            return "gt";
        case engine::llir::LlilOp::kGe:
            return "ge";
    }
    return "op";
}

std::string format_llir_expr(const engine::llir::LlilExpr& expr) {
    switch (expr.kind) {
        case engine::llir::LlilExprKind::kInvalid:
            return "<invalid>";
        case engine::llir::LlilExprKind::kUnknown:
            return "<unknown>";
        case engine::llir::LlilExprKind::kUndef:
            return "<undef>";
        case engine::llir::LlilExprKind::kReg:
            return format_reg(expr.reg);
        case engine::llir::LlilExprKind::kVar:
            return format_var(expr.var);
        case engine::llir::LlilExprKind::kImm:
            return hex(expr.imm);
        case engine::llir::LlilExprKind::kLoad: {
            std::ostringstream oss;
            oss << "load";
            if (expr.size != 0) {
                oss << "<" << expr.size << ">";
            }
            oss << "(";
            if (!expr.args.empty()) {
                oss << format_llir_expr(expr.args.front());
            }
            oss << ")";
            return oss.str();
        }
        case engine::llir::LlilExprKind::kOp: {
            std::ostringstream oss;
            oss << llir_op_name(expr.op) << "(";
            for (std::size_t i = 0; i < expr.args.size(); ++i) {
                if (i > 0) {
                    oss << ", ";
                }
                oss << format_llir_expr(expr.args[i]);
            }
            oss << ")";
            return oss.str();
        }
    }
    return "<expr>";
}

std::string format_llir_stmt(const engine::llir::LlilStmt& stmt) {
    std::string out;
    switch (stmt.kind) {
        case engine::llir::LlilStmtKind::kUnimpl:
            out = "unimpl";
            break;
        case engine::llir::LlilStmtKind::kNop:
            out = "nop";
            break;
        case engine::llir::LlilStmtKind::kSetReg:
            out = format_reg(stmt.reg) + " = " + format_llir_expr(stmt.expr);
            break;
        case engine::llir::LlilStmtKind::kSetVar:
            out = format_var(stmt.var) + " = " + format_llir_expr(stmt.expr);
            break;
        case engine::llir::LlilStmtKind::kStore:
            out = "store " + format_llir_expr(stmt.target) + " <- " + format_llir_expr(stmt.expr);
            break;
        case engine::llir::LlilStmtKind::kCall: {
            std::ostringstream oss;
            if (!stmt.returns.empty()) {
                for (std::size_t i = 0; i < stmt.returns.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << format_reg(stmt.returns[i]);
                }
                oss << " = ";
            }
            oss << "call " << format_llir_expr(stmt.target);
            if (!stmt.args.empty()) {
                oss << "(";
                for (std::size_t i = 0; i < stmt.args.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << format_llir_expr(stmt.args[i]);
                }
                oss << ")";
            }
            out = oss.str();
        } break;
        case engine::llir::LlilStmtKind::kJump:
            out = "jump " + format_llir_expr(stmt.target);
            break;
        case engine::llir::LlilStmtKind::kCJump:
            out = "if " + format_llir_expr(stmt.condition) + " -> " + format_llir_expr(stmt.target);
            break;
        case engine::llir::LlilStmtKind::kRet:
            out = "ret";
            if (stmt.expr.kind != engine::llir::LlilExprKind::kInvalid) {
                out += " " + format_llir_expr(stmt.expr);
            }
            break;
        case engine::llir::LlilStmtKind::kPhi: {
            std::string dest = format_reg(stmt.reg);
            if (stmt.expr.kind == engine::llir::LlilExprKind::kOp &&
                stmt.expr.op == engine::llir::LlilOp::kSelect) {
                std::ostringstream oss;
                oss << dest << " = phi(";
                for (std::size_t i = 0; i < stmt.expr.args.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << format_llir_expr(stmt.expr.args[i]);
                }
                oss << ")";
                out = oss.str();
            } else {
                out = dest + " = " + format_llir_expr(stmt.expr);
            }
            break;
        }
    }
    if (!stmt.comment.empty()) {
        out += " ; " + stmt.comment;
    }
    return out;
}

void format_llir_function(const engine::llir::Function& func, std::vector<std::string>& lines) {
    if (func.blocks.empty()) {
        lines.push_back("no llir blocks");
        return;
    }
    for (const auto& block : func.blocks) {
        lines.push_back("block " + hex(block.start) + " - " + hex(block.end));
        for (const auto& phi : block.phis) {
            lines.push_back("    " + format_llir_stmt(phi));
        }
        for (const auto& inst : block.instructions) {
            std::ostringstream oss;
            oss << "  " << hex(inst.address) << ":";
            if (!inst.mnemonic.empty()) {
                oss << " " << inst.mnemonic;
            }
            if (!inst.operands.empty()) {
                oss << " " << inst.operands;
            }
            lines.push_back(oss.str());
            const auto& stmts = inst.llil_ssa.empty() ? inst.llil : inst.llil_ssa;
            for (const auto& stmt : stmts) {
                lines.push_back("    " + format_llir_stmt(stmt));
            }
        }
    }
}

std::uint64_t discovered_size(const engine::llir::Function& function) {
    if (function.blocks.empty()) {
        return 0;
    }
    std::uint64_t start = function.blocks.front().start;
    std::uint64_t end = function.blocks.front().end;
    for (const auto& block : function.blocks) {
        if (block.start < start) {
            start = block.start;
        }
        if (block.end > end) {
            end = block.end;
        }
    }
    return end >= start ? (end - start) : 0;
}

// ============================================================================
// MLIL Formatting
// ============================================================================

std::string format_mlil_var(const engine::mlil::VarRef& var) {
    if (var.name.empty()) {
        return "<var>";
    }
    std::string name = var.name;
    if (!var.type_name.empty()) {
        name += ":" + var.type_name;
    }
    if (var.version >= 0) {
        return name + "#" + std::to_string(var.version);
    }
    return name;
}

const char* mlil_op_name(engine::mlil::MlilOp op) {
    switch (op) {
        case engine::mlil::MlilOp::kAdd:
            return "add";
        case engine::mlil::MlilOp::kSub:
            return "sub";
        case engine::mlil::MlilOp::kMul:
            return "mul";
        case engine::mlil::MlilOp::kDiv:
            return "div";
        case engine::mlil::MlilOp::kMod:
            return "mod";
        case engine::mlil::MlilOp::kAnd:
            return "and";
        case engine::mlil::MlilOp::kOr:
            return "or";
        case engine::mlil::MlilOp::kXor:
            return "xor";
        case engine::mlil::MlilOp::kShl:
            return "shl";
        case engine::mlil::MlilOp::kShr:
            return "shr";
        case engine::mlil::MlilOp::kSar:
            return "sar";
        case engine::mlil::MlilOp::kRor:
            return "ror";
        case engine::mlil::MlilOp::kNot:
            return "not";
        case engine::mlil::MlilOp::kNeg:
            return "neg";
        case engine::mlil::MlilOp::kAbs:
            return "abs";
        case engine::mlil::MlilOp::kMin:
            return "min";
        case engine::mlil::MlilOp::kMax:
            return "max";
        case engine::mlil::MlilOp::kBswap:
            return "bswap";
        case engine::mlil::MlilOp::kClz:
            return "clz";
        case engine::mlil::MlilOp::kRbit:
            return "rbit";
        case engine::mlil::MlilOp::kSqrt:
            return "sqrt";
        case engine::mlil::MlilOp::kCast:
            return "cast";
        case engine::mlil::MlilOp::kSelect:
            return "select";
        case engine::mlil::MlilOp::kEq:
            return "eq";
        case engine::mlil::MlilOp::kNe:
            return "ne";
        case engine::mlil::MlilOp::kLt:
            return "lt";
        case engine::mlil::MlilOp::kLe:
            return "le";
        case engine::mlil::MlilOp::kGt:
            return "gt";
        case engine::mlil::MlilOp::kGe:
            return "ge";
    }
    return "op";
}

std::string format_mlil_expr(const engine::mlil::MlilExpr& expr) {
    switch (expr.kind) {
        case engine::mlil::MlilExprKind::kInvalid:
            return "<invalid>";
        case engine::mlil::MlilExprKind::kUnknown:
            return "<unknown>";
        case engine::mlil::MlilExprKind::kUndef:
            return "<undef>";
        case engine::mlil::MlilExprKind::kVar:
            return format_mlil_var(expr.var);
        case engine::mlil::MlilExprKind::kImm:
            return hex(expr.imm);
        case engine::mlil::MlilExprKind::kLoad: {
            std::ostringstream oss;
            oss << "load";
            if (expr.size != 0) {
                oss << "<" << expr.size << ">";
            }
            oss << "(";
            if (!expr.args.empty()) {
                oss << format_mlil_expr(expr.args.front());
            }
            oss << ")";
            return oss.str();
        }
        case engine::mlil::MlilExprKind::kOp: {
            std::ostringstream oss;
            oss << mlil_op_name(expr.op) << "(";
            for (std::size_t i = 0; i < expr.args.size(); ++i) {
                if (i > 0) {
                    oss << ", ";
                }
                oss << format_mlil_expr(expr.args[i]);
            }
            oss << ")";
            return oss.str();
        }
        case engine::mlil::MlilExprKind::kCall: {
            std::ostringstream oss;
            oss << "call";
            if (!expr.args.empty()) {
                // First arg is target
                oss << " " << format_mlil_expr(expr.args[0]) << "(";
                for (std::size_t i = 1; i < expr.args.size(); ++i) {
                    if (i > 1) {
                        oss << ", ";
                    }
                    oss << format_mlil_expr(expr.args[i]);
                }
                oss << ")";
            } else {
                oss << " <missing target>";
            }
            return oss.str();
        }
    }
    return "<expr>";
}

std::string format_mlil_stmt(const engine::mlil::MlilStmt& stmt) {
    std::string out;
    switch (stmt.kind) {
        case engine::mlil::MlilStmtKind::kUnimpl:
            out = "unimpl";
            break;
        case engine::mlil::MlilStmtKind::kNop:
            out = "nop";
            break;
        case engine::mlil::MlilStmtKind::kAssign:
            out = format_mlil_var(stmt.var) + " = " + format_mlil_expr(stmt.expr);
            break;
        case engine::mlil::MlilStmtKind::kStore:
            out = "store " + format_mlil_expr(stmt.target) + " <- " + format_mlil_expr(stmt.expr);
            break;
        case engine::mlil::MlilStmtKind::kCall: {
            std::ostringstream oss;
            if (!stmt.returns.empty()) {
                for (std::size_t i = 0; i < stmt.returns.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << format_mlil_var(stmt.returns[i]);
                }
                oss << " = ";
            }
            oss << "call " << format_mlil_expr(stmt.target);
            if (!stmt.args.empty()) {
                oss << "(";
                for (std::size_t i = 0; i < stmt.args.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << format_mlil_expr(stmt.args[i]);
                }
                oss << ")";
            }
            out = oss.str();
        } break;
        case engine::mlil::MlilStmtKind::kJump:
            out = "jump " + format_mlil_expr(stmt.target);
            break;
        case engine::mlil::MlilStmtKind::kCJump:
            out = "if " + format_mlil_expr(stmt.condition) + " -> " + format_mlil_expr(stmt.target);
            break;
        case engine::mlil::MlilStmtKind::kRet:
            out = "ret";
            if (stmt.expr.kind != engine::mlil::MlilExprKind::kInvalid) {
                out += " " + format_mlil_expr(stmt.expr);
            }
            break;
        case engine::mlil::MlilStmtKind::kPhi: {
            std::string dest = format_mlil_var(stmt.var);
            if (stmt.expr.kind == engine::mlil::MlilExprKind::kOp &&
                stmt.expr.op == engine::mlil::MlilOp::kSelect) {
                std::ostringstream oss;
                oss << dest << " = phi(";
                for (std::size_t i = 0; i < stmt.expr.args.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << format_mlil_expr(stmt.expr.args[i]);
                }
                oss << ")";
                out = oss.str();
            } else {
                out = dest + " = " + format_mlil_expr(stmt.expr);
            }
            break;
        }
    }
    if (!stmt.comment.empty()) {
        out += " ; " + stmt.comment;
    }
    return out;
}

void format_mlil_function(const engine::mlil::Function& func, std::vector<std::string>& lines) {
    if (func.blocks.empty()) {
        lines.push_back("no mlil blocks");
        return;
    }
    for (const auto& block : func.blocks) {
        lines.push_back("block " + hex(block.start) + " - " + hex(block.end));
        for (const auto& phi : block.phis) {
            lines.push_back("    " + format_mlil_stmt(phi));
        }
        for (const auto& inst : block.instructions) {
            std::ostringstream oss;
            oss << "  " << hex(inst.address) << ":";
            lines.push_back(oss.str());
            for (const auto& stmt : inst.stmts) {
                lines.push_back("    " + format_mlil_stmt(stmt));
            }
        }
    }
}

// ============================================================================
// HLIL Formatting
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
    return format_mlil_expr(tmp);
}

std::string format_hlil_var(const engine::hlil::VarRef& var, const HlilVarRenameMap& renames) {
    return format_mlil_var(apply_hlil_var_renames(var, renames));
}

std::string format_hlil_stmt(const engine::hlil::HlilStmt& stmt,
                             const HlilVarRenameMap& renames,
                             int indent) {
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
        lines.push_back(format_hlil_stmt(stmt, renames, indent));
    }
}

void format_hlil_function(const engine::hlil::Function& func, std::vector<std::string>& lines) {
    if (func.stmts.empty()) {
        lines.push_back("no hlil statements");
        return;
    }
    format_hlil_stmt_block(func.stmts, 0, func.var_renames, lines);
}

}  // namespace client::fmt
