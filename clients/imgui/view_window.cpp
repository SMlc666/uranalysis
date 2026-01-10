#include "view_window.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>

#include "engine/decompiler.h"
#include "engine/hlil.h"
#include "engine/hlil_lift.h"
#include "engine/hlil_opt.h"
#include "engine/llir.h"
#include "engine/mlil.h"
#include "engine/mlil_lift.h"
#include "imgui.h"

namespace client {

namespace {

bool parse_u64(const char* text, std::uint64_t& value) {
    value = 0;
    if (!text || text[0] == '\0') {
        return false;
    }
    std::string s = text;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
        if (s.empty()) {
            return false;
        }
        std::istringstream iss(s);
        iss >> std::hex >> value;
        return !iss.fail();
    }
    std::istringstream iss(s);
    iss >> value;
    return !iss.fail();
}

std::string format_hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

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
        case engine::llir::LlilOp::kAdd: return "add";
        case engine::llir::LlilOp::kSub: return "sub";
        case engine::llir::LlilOp::kMul: return "mul";
        case engine::llir::LlilOp::kDiv: return "div";
        case engine::llir::LlilOp::kMod: return "mod";
        case engine::llir::LlilOp::kAnd: return "and";
        case engine::llir::LlilOp::kOr: return "or";
        case engine::llir::LlilOp::kXor: return "xor";
        case engine::llir::LlilOp::kShl: return "shl";
        case engine::llir::LlilOp::kShr: return "shr";
        case engine::llir::LlilOp::kSar: return "sar";
        case engine::llir::LlilOp::kRor: return "ror";
        case engine::llir::LlilOp::kNot: return "not";
        case engine::llir::LlilOp::kNeg: return "neg";
        case engine::llir::LlilOp::kAbs: return "abs";
        case engine::llir::LlilOp::kMin: return "min";
        case engine::llir::LlilOp::kMax: return "max";
        case engine::llir::LlilOp::kBswap: return "bswap";
        case engine::llir::LlilOp::kClz: return "clz";
        case engine::llir::LlilOp::kRbit: return "rbit";
        case engine::llir::LlilOp::kSqrt: return "sqrt";
        case engine::llir::LlilOp::kCast: return "cast";
        case engine::llir::LlilOp::kSelect: return "select";
        case engine::llir::LlilOp::kEq: return "eq";
        case engine::llir::LlilOp::kNe: return "ne";
        case engine::llir::LlilOp::kLt: return "lt";
        case engine::llir::LlilOp::kLe: return "le";
        case engine::llir::LlilOp::kGt: return "gt";
        case engine::llir::LlilOp::kGe: return "ge";
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
            return format_hex(expr.imm);
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
        case engine::llir::LlilStmtKind::kCall:
            {
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
            }
            break;
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
        case engine::mlil::MlilOp::kAdd: return "add";
        case engine::mlil::MlilOp::kSub: return "sub";
        case engine::mlil::MlilOp::kMul: return "mul";
        case engine::mlil::MlilOp::kDiv: return "div";
        case engine::mlil::MlilOp::kMod: return "mod";
        case engine::mlil::MlilOp::kAnd: return "and";
        case engine::mlil::MlilOp::kOr: return "or";
        case engine::mlil::MlilOp::kXor: return "xor";
        case engine::mlil::MlilOp::kShl: return "shl";
        case engine::mlil::MlilOp::kShr: return "shr";
        case engine::mlil::MlilOp::kSar: return "sar";
        case engine::mlil::MlilOp::kRor: return "ror";
        case engine::mlil::MlilOp::kNot: return "not";
        case engine::mlil::MlilOp::kNeg: return "neg";
        case engine::mlil::MlilOp::kAbs: return "abs";
        case engine::mlil::MlilOp::kMin: return "min";
        case engine::mlil::MlilOp::kMax: return "max";
        case engine::mlil::MlilOp::kBswap: return "bswap";
        case engine::mlil::MlilOp::kClz: return "clz";
        case engine::mlil::MlilOp::kRbit: return "rbit";
        case engine::mlil::MlilOp::kSqrt: return "sqrt";
        case engine::mlil::MlilOp::kCast: return "cast";
        case engine::mlil::MlilOp::kSelect: return "select";
        case engine::mlil::MlilOp::kEq: return "eq";
        case engine::mlil::MlilOp::kNe: return "ne";
        case engine::mlil::MlilOp::kLt: return "lt";
        case engine::mlil::MlilOp::kLe: return "le";
        case engine::mlil::MlilOp::kGt: return "gt";
        case engine::mlil::MlilOp::kGe: return "ge";
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
            return format_hex(expr.imm);
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
        case engine::mlil::MlilStmtKind::kCall:
            {
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
            }
            break;
        case engine::mlil::MlilStmtKind::kJump:
            out = "jump " + format_mlil_expr(stmt.target);
            break;
        case engine::mlil::MlilStmtKind::kCJump:
            out = "if " + format_mlil_expr(stmt.condition) + " -> " + format_mlil_expr(stmt.target);
            break;
        case engine::mlil::MlilStmtKind::kRet:
            out = "ret";
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

using HlilVarRenameMap = std::unordered_map<std::string, std::string>;

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
                             int indent = 0) {
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
            out = pad + "store " + format_hlil_expr(stmt.target, renames) + " <- " + format_hlil_expr(stmt.expr, renames);
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
            out = pad + "label " + format_hex(stmt.address);
            break;
        case engine::hlil::HlilStmtKind::kGoto:
            out = pad + "goto " + format_hex(stmt.address);
            break;
        case engine::hlil::HlilStmtKind::kBreak:
            out = pad + "break";
            break;
        case engine::hlil::HlilStmtKind::kContinue:
            out = pad + "continue";
            break;
        case engine::hlil::HlilStmtKind::kIf:
            out = pad + "if (" + format_hlil_expr(stmt.condition, renames) + ") {";
            break;
        case engine::hlil::HlilStmtKind::kWhile:
            out = pad + "while (" + format_hlil_expr(stmt.condition, renames) + ") {";
            break;
    }
    if (!stmt.comment.empty()) {
        out += " ; " + stmt.comment;
    }
    return out;
}

void emit_hlil_stmt_block(const std::vector<engine::hlil::HlilStmt>& stmts,
                          int indent,
                          const HlilVarRenameMap& renames,
                          std::vector<std::string>& out) {
    for (const auto& stmt : stmts) {
        if (stmt.kind == engine::hlil::HlilStmtKind::kIf) {
            out.push_back(format_hlil_stmt(stmt, renames, indent));
            emit_hlil_stmt_block(stmt.then_body, indent + 1, renames, out);
            if (!stmt.else_body.empty()) {
                out.push_back(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "} else {");
                emit_hlil_stmt_block(stmt.else_body, indent + 1, renames, out);
            }
            out.push_back(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "}");
            continue;
        }
        if (stmt.kind == engine::hlil::HlilStmtKind::kWhile) {
            out.push_back(format_hlil_stmt(stmt, renames, indent));
            emit_hlil_stmt_block(stmt.body, indent + 1, renames, out);
            out.push_back(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "}");
            continue;
        }
        out.push_back(format_hlil_stmt(stmt, renames, indent));
    }
}

void format_hlil_function(const engine::hlil::Function& function, std::vector<std::string>& out) {
    out.clear();
    if (function.stmts.empty()) {
        out.push_back("no hlil statements");
        return;
    }
    emit_hlil_stmt_block(function.stmts, 0, function.var_renames, out);
}

std::string format_addr_list(const std::vector<std::uint64_t>& addrs) {
    if (addrs.empty()) {
        return "-";
    }
    std::ostringstream oss;
    for (std::size_t i = 0; i < addrs.size(); ++i) {
        if (i > 0) {
            oss << ", ";
        }
        oss << format_hex(addrs[i]);
    }
    return oss.str();
}

std::string join_lines(const std::vector<std::string>& lines) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (i > 0) {
            oss << "\n";
        }
        oss << lines[i];
    }
    return oss.str();
}

std::string build_disasm_text(const std::vector<engine::DisasmLine>& disasm) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < disasm.size(); ++i) {
        const auto& line = disasm[i];
        oss << "0x" << std::hex << line.address << std::dec << ": " << line.text;
        if (i + 1 < disasm.size()) {
            oss << "\n";
        }
    }
    return oss.str();
}

std::uint64_t next_disasm_address(const std::vector<engine::DisasmLine>& disasm, std::uint64_t fallback) {
    if (disasm.empty()) {
        return fallback;
    }
    const auto& last = disasm.back();
    const std::uint64_t advance = last.size != 0 ? last.size : 4;
    return last.address + advance;
}

bool append_disasm(ViewState& state, Session& session, std::uint64_t address, int instruction_count) {
    std::size_t count = instruction_count < 1 ? 1 : static_cast<std::size_t>(instruction_count);
    const auto machine = session.binary_info().machine;
    std::size_t max_bytes = count * ((machine == engine::BinaryMachine::kAarch64) ? 4U : 15U);
    std::vector<engine::DisasmLine> chunk;
    std::string error;
    bool ok = false;
    if (machine == engine::BinaryMachine::kAarch64) {
        ok = session.disasm_arm64(address, max_bytes, count, chunk, error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        ok = session.disasm_x86_64(address, max_bytes, count, chunk, error);
    } else {
        error = "unsupported architecture for disasm";
    }
    if (!ok) {
        state.last_error = error.empty() ? "disasm failed" : error;
        state.disasm_reached_end = true;
        return false;
    }
    if (chunk.empty()) {
        state.disasm_reached_end = true;
        return false;
    }
    if (!state.disasm.empty() && chunk.front().address == state.disasm.back().address) {
        chunk.erase(chunk.begin());
    }
    if (chunk.empty()) {
        state.disasm_reached_end = true;
        return false;
    }
    if (state.disasm_cache_limit > 0 &&
        state.disasm.size() + chunk.size() > static_cast<std::size_t>(state.disasm_cache_limit)) {
        state.last_error = "disasm cache limit reached";
        state.disasm_reached_end = true;
        return false;
    }
    state.disasm.insert(state.disasm.end(), chunk.begin(), chunk.end());
    state.disasm_next_address = next_disasm_address(state.disasm, address);
    return true;
}

std::string build_bytes_text(const std::vector<std::uint8_t>& data, std::uint64_t base) {
    std::ostringstream out;
    const std::size_t per_line = 16;
    for (std::size_t offset = 0; offset < data.size(); offset += per_line) {
        std::ostringstream oss;
        oss << "0x" << std::hex << (base + offset);
        oss << ": ";
        for (std::size_t i = 0; i < per_line; ++i) {
            if (offset + i >= data.size()) {
                oss << "   ";
            } else {
                oss << std::setw(2) << std::setfill('0') << static_cast<int>(data[offset + i]) << " ";
            }
        }
        std::ostringstream ascii;
        ascii << " ";
        for (std::size_t i = 0; i < per_line && offset + i < data.size(); ++i) {
            const unsigned char c = data[offset + i];
            ascii << (std::isprint(c) ? static_cast<char>(c) : '.');
        }
        out << oss.str() << ascii.str();
        if (offset + per_line < data.size()) {
            out << "\n";
        }
    }
    return out.str();
}

void render_readonly_text(const char* label, const std::string& text, const ImVec2& size) {
    std::vector<char> buffer(text.begin(), text.end());
    buffer.push_back('\0');
    ImGui::InputTextMultiline(label, buffer.data(), buffer.size(), size, ImGuiInputTextFlags_ReadOnly);
}

void format_llir_function(const engine::llir::Function& function, std::vector<std::string>& out) {
    out.clear();
    out.reserve(function.blocks.size() * 8);
    for (const auto& block : function.blocks) {
        std::ostringstream header;
        header << "block " << format_hex(block.start) << " - " << format_hex(block.end);
        header << " preds=[" << format_addr_list(block.predecessors) << "]";
        header << " succs=[" << format_addr_list(block.successors) << "]";
        out.push_back(header.str());
        if (!block.phis.empty()) {
            out.push_back("  phis:");
            for (const auto& phi : block.phis) {
                out.push_back("    " + format_llir_stmt(phi));
            }
        }
        for (const auto& inst : block.instructions) {
            std::string asm_text = inst.mnemonic;
            if (!inst.operands.empty()) {
                if (!asm_text.empty()) {
                    asm_text += " ";
                }
                asm_text += inst.operands;
            }
            std::ostringstream line;
            line << "  " << format_hex(inst.address);
            if (!asm_text.empty()) {
                line << ": " << asm_text;
            }
            out.push_back(line.str());
            const auto& stmts = inst.llil_ssa.empty() ? inst.llil : inst.llil_ssa;
            for (const auto& stmt : stmts) {
                out.push_back("    " + format_llir_stmt(stmt));
            }
        }
    }
}

void format_mlil_function(const engine::mlil::Function& function, std::vector<std::string>& out) {
    out.clear();
    out.reserve(function.blocks.size() * 6);
    for (const auto& block : function.blocks) {
        std::ostringstream header;
        header << "block " << format_hex(block.start) << " - " << format_hex(block.end);
        header << " preds=[" << format_addr_list(block.predecessors) << "]";
        header << " succs=[" << format_addr_list(block.successors) << "]";
        out.push_back(header.str());
        if (!block.phis.empty()) {
            out.push_back("  phis:");
            for (const auto& phi : block.phis) {
                out.push_back("    " + format_mlil_stmt(phi));
            }
        }
        for (const auto& inst : block.instructions) {
            std::ostringstream line;
            line << "  " << format_hex(inst.address) << ":";
            out.push_back(line.str());
            for (const auto& stmt : inst.stmts) {
                out.push_back("    " + format_mlil_stmt(stmt));
            }
        }
    }
}

void refresh_disasm(ViewState& state, Session& session, std::uint64_t address) {
    state.disasm.clear();
    state.last_error.clear();
    state.last_address = address;
    if (state.instruction_count < 1) {
        state.instruction_count = 1;
    }
    state.disasm_start_address = address;
    state.disasm_next_address = address;
    state.disasm_reached_end = false;
    state.disasm_loading = false;
    state.disasm_reset_scroll = true;
    append_disasm(state, session, address, state.instruction_count);
    state.bytes.clear();
    if (state.byte_count < 1) {
        state.byte_count = 16;
    }
    session.image().read_bytes(address, static_cast<std::size_t>(state.byte_count), state.bytes);
    state.needs_refresh = false;
}

void refresh_ir(ViewState& state, Session& session, std::uint64_t address) {
    state.llir_lines.clear();
    state.mlil_lines.clear();
    state.hlil_lines.clear();
    state.pseudoc_lines.clear();
    state.pseudoc_mlil_lines.clear();
    state.ir_error.clear();
    state.mlil_error.clear();
    state.hlil_error.clear();
    state.pseudoc_error.clear();
    state.pseudoc_mlil_error.clear();
    state.ir_last_address = address;
    if (state.ir_instruction_count < 1) {
        state.ir_instruction_count = 1;
    }

    engine::llir::Function llir_function;
    std::string error;
    bool ok = false;
    const auto machine = session.binary_info().machine;
    if (machine == engine::BinaryMachine::kAarch64) {
        ok = session.build_llir_ssa_arm64(address,
                                          static_cast<std::size_t>(state.ir_instruction_count),
                                          llir_function,
                                          error);
    } else if (machine == engine::BinaryMachine::kX86_64) {
        ok = session.build_llir_ssa_x86_64(address,
                                           static_cast<std::size_t>(state.ir_instruction_count),
                                           llir_function,
                                           error);
    } else {
        error = "unsupported architecture for llir";
    }
    if (!ok) {
        state.ir_error = error.empty() ? "llir build failed" : error;
        state.ir_needs_refresh = false;
        return;
    }

    format_llir_function(llir_function, state.llir_lines);

    engine::mlil::Function mlil_function;
    if (machine != engine::BinaryMachine::kAarch64) {
        state.mlil_error = "mlil error: only arm64 is supported for now";
        state.hlil_error = "hlil error: only arm64 is supported for now";
        state.pseudoc_error = "pseudoc error: only arm64 is supported for now";
    } else {
        if (!session.build_mlil_ssa_arm64(address,
                                          static_cast<std::size_t>(state.ir_instruction_count),
                                          mlil_function,
                                          error)) {
            const std::string msg = error.empty() ? "mlil build failed" : error;
            state.mlil_error = msg;
            state.hlil_error = "hlil error: " + msg;
            state.pseudoc_error = "pseudoc error: " + msg;
            state.pseudoc_mlil_error = state.pseudoc_error;
        } else {
            format_mlil_function(mlil_function, state.mlil_lines);

            engine::hlil::Function hlil_function;
            if (!engine::hlil::build_hlil_from_mlil(mlil_function, hlil_function, error)) {
                state.hlil_error = error.empty() ? "hlil build failed" : error;
            } else if (state.hlil_use_optimizations) {
                engine::hlil::HlilOptOptions opt_options;
                if (!engine::hlil::optimize_hlil(hlil_function, opt_options, error)) {
                    state.hlil_error = error.empty() ? "hlil opt failed" : error;
                } else {
                    format_hlil_function(hlil_function, state.hlil_lines);
                }
            } else {
                format_hlil_function(hlil_function, state.hlil_lines);
            }
        }

        if (state.mlil_error.empty()) {
            engine::decompiler::FunctionHints hints;
            const auto* dwarf_fn = session.dwarf_catalog().find_function_by_address(address);
            if (dwarf_fn) {
                if (!dwarf_fn->name.empty()) {
                    hints.name = dwarf_fn->name;
                } else if (!dwarf_fn->linkage_name.empty()) {
                    hints.name = dwarf_fn->linkage_name;
                }
            }
            if (hints.name.empty()) {
                auto symbols = session.symbol_table().within_range(address, 1);
                if (!symbols.empty() && symbols.front()) {
                    const auto* sym = symbols.front();
                    if (!sym->demangled_name.empty()) {
                        hints.name = sym->demangled_name;
                    } else if (!sym->name.empty()) {
                        hints.name = sym->name;
                    }
                }
            }

            engine::decompiler::Function pseudoc_function;
            engine::mlil::Function pseudoc_mlil_lowered;
            if (!engine::decompiler::build_pseudoc_from_mlil_ssa_debug(mlil_function,
                                                                       pseudoc_function,
                                                                       error,
                                                                       &hints,
                                                                       &pseudoc_mlil_lowered)) {
                const std::string msg = error.empty() ? "pseudoc build failed" : error;
                state.pseudoc_error = msg;
                state.pseudoc_mlil_error = msg;
                state.pseudoc_mlil_lines.clear();
            } else {
                engine::decompiler::emit_pseudoc(pseudoc_function, state.pseudoc_lines);
                format_mlil_function(pseudoc_mlil_lowered, state.pseudoc_mlil_lines);
                state.pseudoc_mlil_error.clear();
            }
        }
    }

    state.ir_needs_refresh = false;
}

}  // namespace

void render_view_window(ViewState& state, Session& session) {
    ImGui::Begin("IDA View-A");

    ImGui::TextUnformatted("Address");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.0f);
    ImGui::InputText("##Address", state.address, sizeof(state.address));
    ImGui::SameLine();
    ImGui::TextUnformatted("Instr");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    ImGui::InputInt("##Instr", &state.instruction_count);
    ImGui::SameLine();
    ImGui::TextUnformatted("Bytes");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    ImGui::InputInt("##Bytes", &state.byte_count);
    ImGui::SameLine();
    bool refresh = ImGui::Button("Refresh");

    if (!session.loaded()) {
        ImGui::TextDisabled("Load a binary file to populate the view.");
        ImGui::End();
        return;
    }

    if (refresh || state.needs_refresh) {
        std::uint64_t addr = 0;
        if (parse_u64(state.address, addr)) {
            refresh_disasm(state, session, addr);
        } else {
            state.last_error = "invalid address";
            state.disasm.clear();
            state.bytes.clear();
            state.disasm_start_address = 0;
            state.disasm_next_address = 0;
            state.disasm_reached_end = true;
            state.disasm_loading = false;
            state.disasm_reset_scroll = true;
            state.needs_refresh = false;
        }
    }

    if (ImGui::BeginTabBar("ViewTabs")) {
        if (ImGui::BeginTabItem("Disasm")) {
            if (ImGui::Button("Copy Disasm")) {
                const std::string text = build_disasm_text(state.disasm);
                ImGui::SetClipboardText(text.c_str());
            }
            ImGui::SameLine();
            if (ImGui::Button("Copy Bytes")) {
                const std::string text = build_bytes_text(state.bytes, state.last_address);
                ImGui::SetClipboardText(text.c_str());
            }

            if (!state.last_error.empty()) {
                ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s", state.last_error.c_str());
            }

            ImGui::Separator();

            float avail = ImGui::GetContentRegionAvail().y;
            float disasm_height = avail > 140.0f ? avail * 0.6f : 180.0f;
            bool request_more = false;
            if (!state.disasm.empty()) {
                ImGui::BeginChild("DisasmScroll", ImVec2(0, disasm_height), true,
                                  ImGuiWindowFlags_HorizontalScrollbar);
                if (state.disasm_reset_scroll) {
                    ImGui::SetScrollY(0.0f);
                    state.disasm_reset_scroll = false;
                }
                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(state.disasm.size()));
                while (clipper.Step()) {
                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                        const auto& line = state.disasm[static_cast<std::size_t>(i)];
                        ImGui::Text("0x%llx: %s", static_cast<unsigned long long>(line.address),
                                    line.text.c_str());
                    }
                }
                float scroll_y = ImGui::GetScrollY();
                float scroll_max = ImGui::GetScrollMaxY();
                float win_h = ImGui::GetWindowHeight();
                if (!state.disasm_reached_end && scroll_max > 0.0f &&
                    scroll_y + win_h >= scroll_max - 80.0f) {
                    request_more = true;
                }
                ImGui::EndChild();
            } else {
                ImGui::TextDisabled("Disassembly will appear here once you refresh with a valid address.");
            }

            if (state.disasm_reached_end) {
                ImGui::TextDisabled("Reached end of readable bytes.");
            } else if (!state.disasm.empty()) {
                if (ImGui::Button("Load more")) {
                    request_more = true;
                }
            }

            if (request_more && !state.disasm_loading && !state.disasm_reached_end) {
                state.disasm_loading = true;
                append_disasm(state, session, state.disasm_next_address, state.instruction_count);
                state.disasm_loading = false;
            }

            ImGui::Separator();

            if (!state.bytes.empty()) {
                const std::string text = build_bytes_text(state.bytes, state.last_address);
                render_readonly_text("##BytesText", text, ImVec2(0, ImGui::GetContentRegionAvail().y));
            } else {
                ImGui::TextDisabled("Byte preview will appear here after refresh.");
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("IR")) {
            ImGui::SetNextItemWidth(120.0f);
            ImGui::InputInt("IR max instr", &state.ir_instruction_count);
            if (state.ir_instruction_count < 1) {
                state.ir_instruction_count = 1;
            }
            ImGui::SameLine();
            bool refresh_ir_requested = ImGui::Button("Build IR");
            if (refresh_ir_requested) {
                state.ir_needs_refresh = true;
            }

            if (state.ir_needs_refresh) {
                std::uint64_t addr = 0;
                if (parse_u64(state.address, addr)) {
                    refresh_ir(state, session, addr);
                } else {
                    state.ir_error = "invalid address";
                    state.llir_lines.clear();
                    state.mlil_lines.clear();
                    state.hlil_lines.clear();
                    state.pseudoc_lines.clear();
                    state.pseudoc_mlil_lines.clear();
                    state.mlil_error.clear();
                    state.hlil_error.clear();
                    state.pseudoc_error.clear();
                    state.pseudoc_mlil_error.clear();
                    state.ir_needs_refresh = false;
                }
            }

            if (!state.ir_error.empty()) {
                ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s", state.ir_error.c_str());
            }

            if (ImGui::BeginTabBar("IrTabs")) {
                if (ImGui::BeginTabItem("LLIR (SSA)")) {
                    if (ImGui::Button("Copy LLIR")) {
                        const std::string text = join_lines(state.llir_lines);
                        ImGui::SetClipboardText(text.c_str());
                    }
                    if (!state.llir_lines.empty()) {
                        const std::string text = join_lines(state.llir_lines);
                        render_readonly_text("##LlirText", text, ImVec2(0, ImGui::GetContentRegionAvail().y));
                    } else {
                        ImGui::TextDisabled("Build IR to populate LLIR.");
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("MLIL")) {
                    if (ImGui::Button("Copy MLIL")) {
                        const std::string text = join_lines(state.mlil_lines);
                        ImGui::SetClipboardText(text.c_str());
                    }
                    if (!state.mlil_error.empty()) {
                        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s",
                                           state.mlil_error.c_str());
                    }
                    if (!state.mlil_lines.empty()) {
                        const std::string text = join_lines(state.mlil_lines);
                        render_readonly_text("##MlilText", text, ImVec2(0, ImGui::GetContentRegionAvail().y));
                    } else {
                        ImGui::TextDisabled("Build IR to populate MLIL.");
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("HLIL (proto)")) {
                    if (ImGui::Button("Copy HLIL")) {
                        const std::string text = join_lines(state.hlil_lines);
                        ImGui::SetClipboardText(text.c_str());
                    }
                    ImGui::SameLine();
                    if (ImGui::Checkbox("Optimize HLIL", &state.hlil_use_optimizations)) {
                        state.ir_needs_refresh = true;
                    }
                    if (!state.hlil_error.empty()) {
                        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s",
                                           state.hlil_error.c_str());
                    }
                    if (!state.hlil_lines.empty()) {
                        const std::string text = join_lines(state.hlil_lines);
                        render_readonly_text("##HlilText", text, ImVec2(0, ImGui::GetContentRegionAvail().y));
                    } else {
                        ImGui::TextDisabled("Build IR to populate HLIL.");
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Pseudo-C (proto)")) {
                    if (ImGui::Button("Copy Pseudo-C")) {
                        const std::string text = join_lines(state.pseudoc_lines);
                        ImGui::SetClipboardText(text.c_str());
                    }
                    if (!state.pseudoc_error.empty()) {
                        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s",
                                           state.pseudoc_error.c_str());
                    }
                    if (!state.pseudoc_lines.empty()) {
                        const std::string text = join_lines(state.pseudoc_lines);
                        render_readonly_text("##PseudoCText", text, ImVec2(0, ImGui::GetContentRegionAvail().y));
                    } else {
                        ImGui::TextDisabled("Build IR to populate pseudo-C.");
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Pseudo-C MLIL (de-SSA)")) {
                    if (ImGui::Button("Copy Pseudo-C MLIL")) {
                        const std::string text = join_lines(state.pseudoc_mlil_lines);
                        ImGui::SetClipboardText(text.c_str());
                    }
                    if (!state.pseudoc_mlil_error.empty()) {
                        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s",
                                           state.pseudoc_mlil_error.c_str());
                    }
                    if (!state.pseudoc_mlil_lines.empty()) {
                        const std::string text = join_lines(state.pseudoc_mlil_lines);
                        render_readonly_text("##PseudoCMlilText", text, ImVec2(0, ImGui::GetContentRegionAvail().y));
                    } else {
                        ImGui::TextDisabled("Build IR to populate pseudo-C MLIL.");
                    }
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}

}  // namespace client
