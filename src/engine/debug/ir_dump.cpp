#include "engine/debug/ir_dump.h"

#include <sstream>

namespace engine::debug {

// ============================================================================
// Global Options
// ============================================================================

namespace {
    DumpOptions g_default_opts;
}

DumpOptions& default_dump_options() {
    return g_default_opts;
}

// ============================================================================
// Address Formatting
// ============================================================================

std::string hex(std::uint64_t addr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << addr;
    return oss.str();
}

// ============================================================================
// LLIR Dump Implementation
// ============================================================================

const char* op_name(llir::LlilOp op) {
    switch (op) {
        case llir::LlilOp::kAdd: return "add";
        case llir::LlilOp::kSub: return "sub";
        case llir::LlilOp::kMul: return "mul";
        case llir::LlilOp::kDiv: return "div";
        case llir::LlilOp::kMod: return "mod";
        case llir::LlilOp::kAnd: return "and";
        case llir::LlilOp::kOr:  return "or";
        case llir::LlilOp::kXor: return "xor";
        case llir::LlilOp::kShl: return "shl";
        case llir::LlilOp::kShr: return "shr";
        case llir::LlilOp::kSar: return "sar";
        case llir::LlilOp::kRor: return "ror";
        case llir::LlilOp::kNot: return "not";
        case llir::LlilOp::kNeg: return "neg";
        case llir::LlilOp::kAbs: return "abs";
        case llir::LlilOp::kMin: return "min";
        case llir::LlilOp::kMax: return "max";
        case llir::LlilOp::kBswap: return "bswap";
        case llir::LlilOp::kClz: return "clz";
        case llir::LlilOp::kRbit: return "rbit";
        case llir::LlilOp::kSqrt: return "sqrt";
        case llir::LlilOp::kCast: return "cast";
        case llir::LlilOp::kSelect: return "select";
        case llir::LlilOp::kEq: return "eq";
        case llir::LlilOp::kNe: return "ne";
        case llir::LlilOp::kLt: return "lt";
        case llir::LlilOp::kLe: return "le";
        case llir::LlilOp::kGt: return "gt";
        case llir::LlilOp::kGe: return "ge";
    }
    return "op";
}

std::string dump(const llir::RegRef& reg, const DumpOptions& opts) {
    if (reg.name.empty()) {
        return "<reg>";
    }
    if (opts.include_ssa_versions && reg.version >= 0) {
        return reg.name + "#" + std::to_string(reg.version);
    }
    return reg.name;
}

std::string dump(const llir::VarRef& var, const DumpOptions& opts) {
    if (var.name.empty()) {
        return "<var>";
    }
    std::string name = var.name;
    if (!var.type_name.empty()) {
        name += ":" + var.type_name;
    }
    if (opts.include_ssa_versions && var.version >= 0) {
        return name + "#" + std::to_string(var.version);
    }
    return name;
}

std::string dump(const llir::LlilExpr& expr, const DumpOptions& opts) {
    switch (expr.kind) {
        case llir::LlilExprKind::kInvalid:
            return "<invalid>";
        case llir::LlilExprKind::kUnknown:
            return "<unknown>";
        case llir::LlilExprKind::kUndef:
            return "<undef>";
        case llir::LlilExprKind::kReg:
            return dump(expr.reg, opts);
        case llir::LlilExprKind::kVar:
            return dump(expr.var, opts);
        case llir::LlilExprKind::kImm:
            return hex(expr.imm);
        case llir::LlilExprKind::kLoad: {
            std::ostringstream oss;
            oss << "load";
            if (expr.size != 0) {
                oss << "<" << expr.size << ">";
            }
            oss << "(";
            if (!expr.args.empty()) {
                oss << dump(expr.args.front(), opts);
            }
            oss << ")";
            return oss.str();
        }
        case llir::LlilExprKind::kOp: {
            std::ostringstream oss;
            oss << op_name(expr.op) << "(";
            for (std::size_t i = 0; i < expr.args.size(); ++i) {
                if (i > 0) {
                    oss << ", ";
                }
                oss << dump(expr.args[i], opts);
            }
            oss << ")";
            return oss.str();
        }
    }
    return "<expr>";
}

std::string dump(const llir::LlilStmt& stmt, const DumpOptions& opts) {
    std::string out;
    switch (stmt.kind) {
        case llir::LlilStmtKind::kUnimpl:
            out = "unimpl";
            break;
        case llir::LlilStmtKind::kNop:
            out = "nop";
            break;
        case llir::LlilStmtKind::kSetReg:
            out = dump(stmt.reg, opts) + " = " + dump(stmt.expr, opts);
            break;
        case llir::LlilStmtKind::kSetVar:
            out = dump(stmt.var, opts) + " = " + dump(stmt.expr, opts);
            break;
        case llir::LlilStmtKind::kStore:
            out = "store " + dump(stmt.target, opts) + " <- " + dump(stmt.expr, opts);
            break;
        case llir::LlilStmtKind::kCall: {
            std::ostringstream oss;
            if (!stmt.returns.empty()) {
                for (std::size_t i = 0; i < stmt.returns.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << dump(stmt.returns[i], opts);
                }
                oss << " = ";
            }
            oss << "call " << dump(stmt.target, opts);
            if (!stmt.args.empty()) {
                oss << "(";
                for (std::size_t i = 0; i < stmt.args.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << dump(stmt.args[i], opts);
                }
                oss << ")";
            }
            out = oss.str();
        } break;
        case llir::LlilStmtKind::kJump:
            out = "jump " + dump(stmt.target, opts);
            break;
        case llir::LlilStmtKind::kCJump:
            out = "if " + dump(stmt.condition, opts) + " -> " + dump(stmt.target, opts);
            break;
        case llir::LlilStmtKind::kRet:
            out = "ret";
            if (stmt.expr.kind != llir::LlilExprKind::kInvalid) {
                out += " " + dump(stmt.expr, opts);
            }
            break;
        case llir::LlilStmtKind::kPhi: {
            std::string dest = dump(stmt.reg, opts);
            if (stmt.expr.kind == llir::LlilExprKind::kOp &&
                stmt.expr.op == llir::LlilOp::kSelect) {
                std::ostringstream oss;
                oss << dest << " = phi(";
                for (std::size_t i = 0; i < stmt.expr.args.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << dump(stmt.expr.args[i], opts);
                }
                oss << ")";
                out = oss.str();
            } else {
                out = dest + " = " + dump(stmt.expr, opts);
            }
            break;
        }
    }
    if (opts.include_comments && !stmt.comment.empty()) {
        out += " ; " + stmt.comment;
    }
    return out;
}

void dump(const llir::Function& func, std::vector<std::string>& lines, const DumpOptions& opts) {
    if (func.blocks.empty()) {
        lines.push_back("no llir blocks");
        return;
    }
    for (const auto& block : func.blocks) {
        if (opts.include_block_ranges) {
            lines.push_back("block " + hex(block.start) + " - " + hex(block.end));
        } else {
            lines.push_back("block " + hex(block.start));
        }
        if (opts.include_phis) {
            for (const auto& phi : block.phis) {
                lines.push_back(opts.indent + dump(phi, opts));
            }
        }
        for (const auto& inst : block.instructions) {
            std::ostringstream oss;
            oss << "  " << hex(inst.address) << ":";
            if (opts.include_asm) {
                if (!inst.mnemonic.empty()) {
                    oss << " " << inst.mnemonic;
                }
                if (!inst.operands.empty()) {
                    oss << " " << inst.operands;
                }
            }
            lines.push_back(oss.str());
            const auto& stmts = inst.llil_ssa.empty() ? inst.llil : inst.llil_ssa;
            for (const auto& stmt : stmts) {
                lines.push_back(opts.indent + dump(stmt, opts));
            }
        }
    }
}

std::string dump(const llir::Function& func, const DumpOptions& opts) {
    std::vector<std::string> lines;
    dump(func, lines, opts);
    std::ostringstream oss;
    for (const auto& line : lines) {
        oss << line << "\n";
    }
    return oss.str();
}

void dump(const llir::Function& func, std::ostream& os, const DumpOptions& opts) {
    std::vector<std::string> lines;
    dump(func, lines, opts);
    for (const auto& line : lines) {
        os << line << "\n";
    }
}

// ============================================================================
// MLIL Dump Implementation
// ============================================================================

const char* op_name(mlil::MlilOp op) {
    switch (op) {
        case mlil::MlilOp::kAdd: return "add";
        case mlil::MlilOp::kSub: return "sub";
        case mlil::MlilOp::kMul: return "mul";
        case mlil::MlilOp::kDiv: return "div";
        case mlil::MlilOp::kMod: return "mod";
        case mlil::MlilOp::kAnd: return "and";
        case mlil::MlilOp::kOr:  return "or";
        case mlil::MlilOp::kXor: return "xor";
        case mlil::MlilOp::kShl: return "shl";
        case mlil::MlilOp::kShr: return "shr";
        case mlil::MlilOp::kSar: return "sar";
        case mlil::MlilOp::kRor: return "ror";
        case mlil::MlilOp::kNot: return "not";
        case mlil::MlilOp::kNeg: return "neg";
        case mlil::MlilOp::kAbs: return "abs";
        case mlil::MlilOp::kMin: return "min";
        case mlil::MlilOp::kMax: return "max";
        case mlil::MlilOp::kBswap: return "bswap";
        case mlil::MlilOp::kClz: return "clz";
        case mlil::MlilOp::kRbit: return "rbit";
        case mlil::MlilOp::kSqrt: return "sqrt";
        case mlil::MlilOp::kCast: return "cast";
        case mlil::MlilOp::kSelect: return "select";
        case mlil::MlilOp::kEq: return "eq";
        case mlil::MlilOp::kNe: return "ne";
        case mlil::MlilOp::kLt: return "lt";
        case mlil::MlilOp::kLe: return "le";
        case mlil::MlilOp::kGt: return "gt";
        case mlil::MlilOp::kGe: return "ge";
    }
    return "op";
}

std::string dump(const mlil::VarRef& var, const DumpOptions& opts) {
    if (var.name.empty()) {
        return "<var>";
    }
    std::string name = var.name;
    if (!var.type_name.empty()) {
        name += ":" + var.type_name;
    }
    if (opts.include_ssa_versions && var.version >= 0) {
        return name + "#" + std::to_string(var.version);
    }
    return name;
}

std::string dump(const mlil::MlilExpr& expr, const DumpOptions& opts) {
    switch (expr.kind) {
        case mlil::MlilExprKind::kInvalid:
            return "<invalid>";
        case mlil::MlilExprKind::kUnknown:
            return "<unknown>";
        case mlil::MlilExprKind::kUndef:
            return "<undef>";
        case mlil::MlilExprKind::kVar:
            return dump(expr.var, opts);
        case mlil::MlilExprKind::kImm:
            return hex(expr.imm);
        case mlil::MlilExprKind::kLoad: {
            std::ostringstream oss;
            oss << "load";
            if (expr.size != 0) {
                oss << "<" << expr.size << ">";
            }
            oss << "(";
            if (!expr.args.empty()) {
                oss << dump(expr.args.front(), opts);
            }
            oss << ")";
            return oss.str();
        }
        case mlil::MlilExprKind::kOp: {
            std::ostringstream oss;
            oss << op_name(expr.op) << "(";
            for (std::size_t i = 0; i < expr.args.size(); ++i) {
                if (i > 0) {
                    oss << ", ";
                }
                oss << dump(expr.args[i], opts);
            }
            oss << ")";
            return oss.str();
        }
        case mlil::MlilExprKind::kCall: {
            std::ostringstream oss;
            oss << "call";
            if (!expr.args.empty()) {
                oss << " " << dump(expr.args[0], opts) << "(";
                for (std::size_t i = 1; i < expr.args.size(); ++i) {
                    if (i > 1) {
                        oss << ", ";
                    }
                    oss << dump(expr.args[i], opts);
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

std::string dump(const mlil::MlilStmt& stmt, const DumpOptions& opts) {
    std::string out;
    switch (stmt.kind) {
        case mlil::MlilStmtKind::kUnimpl:
            out = "unimpl";
            break;
        case mlil::MlilStmtKind::kNop:
            out = "nop";
            break;
        case mlil::MlilStmtKind::kAssign:
            out = dump(stmt.var, opts) + " = " + dump(stmt.expr, opts);
            break;
        case mlil::MlilStmtKind::kStore:
            out = "store " + dump(stmt.target, opts) + " <- " + dump(stmt.expr, opts);
            break;
        case mlil::MlilStmtKind::kCall: {
            std::ostringstream oss;
            if (!stmt.returns.empty()) {
                for (std::size_t i = 0; i < stmt.returns.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << dump(stmt.returns[i], opts);
                }
                oss << " = ";
            }
            oss << "call " << dump(stmt.target, opts);
            if (!stmt.args.empty()) {
                oss << "(";
                for (std::size_t i = 0; i < stmt.args.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << dump(stmt.args[i], opts);
                }
                oss << ")";
            }
            out = oss.str();
        } break;
        case mlil::MlilStmtKind::kJump:
            out = "jump " + dump(stmt.target, opts);
            break;
        case mlil::MlilStmtKind::kCJump:
            out = "if " + dump(stmt.condition, opts) + " -> " + dump(stmt.target, opts);
            break;
        case mlil::MlilStmtKind::kRet:
            out = "ret";
            if (stmt.expr.kind != mlil::MlilExprKind::kInvalid) {
                out += " " + dump(stmt.expr, opts);
            }
            break;
        case mlil::MlilStmtKind::kPhi: {
            std::string dest = dump(stmt.var, opts);
            if (stmt.expr.kind == mlil::MlilExprKind::kOp &&
                stmt.expr.op == mlil::MlilOp::kSelect) {
                std::ostringstream oss;
                oss << dest << " = phi(";
                for (std::size_t i = 0; i < stmt.expr.args.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << dump(stmt.expr.args[i], opts);
                }
                oss << ")";
                out = oss.str();
            } else {
                out = dest + " = " + dump(stmt.expr, opts);
            }
            break;
        }
    }
    if (opts.include_comments && !stmt.comment.empty()) {
        out += " ; " + stmt.comment;
    }
    return out;
}

void dump(const mlil::Function& func, std::vector<std::string>& lines, const DumpOptions& opts) {
    if (func.blocks.empty()) {
        lines.push_back("no mlil blocks");
        return;
    }
    for (const auto& block : func.blocks) {
        if (opts.include_block_ranges) {
            lines.push_back("block " + hex(block.start) + " - " + hex(block.end));
        } else {
            lines.push_back("block " + hex(block.start));
        }
        if (opts.include_phis) {
            for (const auto& phi : block.phis) {
                lines.push_back(opts.indent + dump(phi, opts));
            }
        }
        for (const auto& inst : block.instructions) {
            std::ostringstream oss;
            oss << "  " << hex(inst.address) << ":";
            lines.push_back(oss.str());
            for (const auto& stmt : inst.stmts) {
                lines.push_back(opts.indent + dump(stmt, opts));
            }
        }
    }
}

std::string dump(const mlil::Function& func, const DumpOptions& opts) {
    std::vector<std::string> lines;
    dump(func, lines, opts);
    std::ostringstream oss;
    for (const auto& line : lines) {
        oss << line << "\n";
    }
    return oss.str();
}

void dump(const mlil::Function& func, std::ostream& os, const DumpOptions& opts) {
    std::vector<std::string> lines;
    dump(func, lines, opts);
    for (const auto& line : lines) {
        os << line << "\n";
    }
}

// ============================================================================
// HLIL Dump Implementation
// ============================================================================

namespace {

// Helper to apply variable renames (HLIL uses friendly names).
mlil::VarRef apply_renames(mlil::VarRef var, 
                           const std::unordered_map<std::string, std::string>& renames) {
    auto it = renames.find(var.name);
    if (it != renames.end()) {
        var.name = it->second;
    }
    var.version = -1;  // HLIL doesn't show SSA versions
    return var;
}

void apply_renames_expr(mlil::MlilExpr& expr,
                        const std::unordered_map<std::string, std::string>& renames) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        expr.var = apply_renames(expr.var, renames);
    }
    for (auto& arg : expr.args) {
        apply_renames_expr(arg, renames);
    }
}

std::string dump_hlil_expr(const hlil::Expr& expr,
                           const std::unordered_map<std::string, std::string>& renames,
                           const DumpOptions& opts) {
    mlil::MlilExpr tmp = expr;
    apply_renames_expr(tmp, renames);
    // For HLIL, we don't show SSA versions
    DumpOptions hlil_opts = opts;
    hlil_opts.include_ssa_versions = false;
    return dump(tmp, hlil_opts);
}

std::string dump_hlil_var(const hlil::VarRef& var,
                          const std::unordered_map<std::string, std::string>& renames,
                          const DumpOptions& opts) {
    mlil::VarRef renamed = apply_renames(var, renames);
    DumpOptions hlil_opts = opts;
    hlil_opts.include_ssa_versions = false;
    return dump(renamed, hlil_opts);
}

// Forward declaration for internal use
std::string dump_stmt_impl(const hlil::HlilStmt& stmt, int indent,
                           const std::unordered_map<std::string, std::string>& renames,
                           const DumpOptions& opts);

}  // namespace

std::string dump(const hlil::HlilStmt& stmt, int indent, const DumpOptions& opts) {
    // Use empty renames map - caller should use dump_block for full function
    return dump_stmt_impl(stmt, indent, {}, opts);
}

// Internal version with renames
namespace {

std::string dump_stmt_impl(const hlil::HlilStmt& stmt, int indent,
                           const std::unordered_map<std::string, std::string>& renames,
                           const DumpOptions& opts) {
    const std::string pad(static_cast<std::size_t>(indent) * opts.indent.size(), ' ');
    std::string out;
    
    switch (stmt.kind) {
        case hlil::HlilStmtKind::kNop:
            out = pad + "nop";
            break;
        case hlil::HlilStmtKind::kAssign:
            out = pad + dump_hlil_var(stmt.var, renames, opts) + " = " + 
                  dump_hlil_expr(stmt.expr, renames, opts);
            break;
        case hlil::HlilStmtKind::kStore:
            out = pad + "store " + dump_hlil_expr(stmt.target, renames, opts) + " <- " +
                  dump_hlil_expr(stmt.expr, renames, opts);
            break;
        case hlil::HlilStmtKind::kCall: {
            std::ostringstream oss;
            oss << pad;
            if (!stmt.returns.empty()) {
                for (std::size_t i = 0; i < stmt.returns.size(); ++i) {
                    if (i > 0) {
                        oss << ", ";
                    }
                    oss << dump_hlil_var(stmt.returns[i], renames, opts);
                }
                oss << " = ";
            }
            oss << "call " << dump_hlil_expr(stmt.target, renames, opts) << "(";
            for (std::size_t i = 0; i < stmt.args.size(); ++i) {
                if (i > 0) {
                    oss << ", ";
                }
                oss << dump_hlil_expr(stmt.args[i], renames, opts);
            }
            oss << ")";
            out = oss.str();
            break;
        }
        case hlil::HlilStmtKind::kRet:
            out = pad + "ret";
            if (stmt.expr.kind != mlil::MlilExprKind::kInvalid) {
                out += " " + dump_hlil_expr(stmt.expr, renames, opts);
            }
            break;
        case hlil::HlilStmtKind::kLabel:
            out = pad + "label " + hex(stmt.address);
            break;
        case hlil::HlilStmtKind::kGoto:
            out = pad + "goto " + hex(stmt.address);
            break;
        case hlil::HlilStmtKind::kBreak:
            out = pad + "break";
            break;
        case hlil::HlilStmtKind::kContinue:
            out = pad + "continue";
            break;
        case hlil::HlilStmtKind::kIf:
            out = pad + "if (" + dump_hlil_expr(stmt.condition, renames, opts) + ") {";
            break;
        case hlil::HlilStmtKind::kWhile:
            out = pad + "while (" + dump_hlil_expr(stmt.condition, renames, opts) + ") {";
            break;
        case hlil::HlilStmtKind::kDoWhile:
            out = pad + "do {";
            break;
        case hlil::HlilStmtKind::kFor:
            out = pad + "for (...) {";
            break;
    }
    
    if (opts.include_comments && !stmt.comment.empty()) {
        out += " ; " + stmt.comment;
    }
    return out;
}

void dump_block_impl(const std::vector<hlil::HlilStmt>& stmts, int indent,
                     const std::unordered_map<std::string, std::string>& renames,
                     std::vector<std::string>& lines,
                     const DumpOptions& opts) {
    const std::string pad(static_cast<std::size_t>(indent) * opts.indent.size(), ' ');
    
    for (const auto& stmt : stmts) {
        if (stmt.kind == hlil::HlilStmtKind::kIf) {
            lines.push_back(dump_stmt_impl(stmt, indent, renames, opts));
            dump_block_impl(stmt.then_body, indent + 1, renames, lines, opts);
            if (!stmt.else_body.empty()) {
                lines.push_back(pad + "} else {");
                dump_block_impl(stmt.else_body, indent + 1, renames, lines, opts);
            }
            lines.push_back(pad + "}");
            continue;
        }
        if (stmt.kind == hlil::HlilStmtKind::kWhile) {
            lines.push_back(dump_stmt_impl(stmt, indent, renames, opts));
            dump_block_impl(stmt.body, indent + 1, renames, lines, opts);
            lines.push_back(pad + "}");
            continue;
        }
        if (stmt.kind == hlil::HlilStmtKind::kDoWhile) {
            lines.push_back(dump_stmt_impl(stmt, indent, renames, opts));
            dump_block_impl(stmt.body, indent + 1, renames, lines, opts);
            lines.push_back(pad + "} while (" + dump_hlil_expr(stmt.condition, renames, opts) + ")");
            continue;
        }
        lines.push_back(dump_stmt_impl(stmt, indent, renames, opts));
    }
}

}  // namespace

void dump_block(const std::vector<hlil::HlilStmt>& stmts, int indent,
                std::vector<std::string>& lines, const DumpOptions& opts) {
    dump_block_impl(stmts, indent, {}, lines, opts);
}

void dump(const hlil::Function& func, std::vector<std::string>& lines, const DumpOptions& opts) {
    if (func.stmts.empty()) {
        lines.push_back("no hlil statements");
        return;
    }
    dump_block_impl(func.stmts, 0, func.var_renames, lines, opts);
}

std::string dump(const hlil::Function& func, const DumpOptions& opts) {
    std::vector<std::string> lines;
    dump(func, lines, opts);
    std::ostringstream oss;
    for (const auto& line : lines) {
        oss << line << "\n";
    }
    return oss.str();
}

void dump(const hlil::Function& func, std::ostream& os, const DumpOptions& opts) {
    std::vector<std::string> lines;
    dump(func, lines, opts);
    for (const auto& line : lines) {
        os << line << "\n";
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

std::uint64_t discovered_size(const llir::Function& func) {
    if (func.blocks.empty()) {
        return 0;
    }
    std::uint64_t start = func.blocks.front().start;
    std::uint64_t end = func.blocks.front().end;
    for (const auto& block : func.blocks) {
        if (block.start < start) {
            start = block.start;
        }
        if (block.end > end) {
            end = block.end;
        }
    }
    return end >= start ? (end - start) : 0;
}

std::size_t count_stmts(const llir::Function& func) {
    std::size_t count = 0;
    for (const auto& block : func.blocks) {
        count += block.phis.size();
        for (const auto& inst : block.instructions) {
            const auto& stmts = inst.llil_ssa.empty() ? inst.llil : inst.llil_ssa;
            count += stmts.size();
        }
    }
    return count;
}

std::size_t count_stmts(const mlil::Function& func) {
    std::size_t count = 0;
    for (const auto& block : func.blocks) {
        count += block.phis.size();
        for (const auto& inst : block.instructions) {
            count += inst.stmts.size();
        }
    }
    return count;
}

namespace {
std::size_t count_hlil_stmts_recursive(const std::vector<hlil::HlilStmt>& stmts) {
    std::size_t count = stmts.size();
    for (const auto& stmt : stmts) {
        count += count_hlil_stmts_recursive(stmt.then_body);
        count += count_hlil_stmts_recursive(stmt.else_body);
        count += count_hlil_stmts_recursive(stmt.body);
    }
    return count;
}
}  // namespace

std::size_t count_stmts(const hlil::Function& func) {
    return count_hlil_stmts_recursive(func.stmts);
}

}  // namespace engine::debug
