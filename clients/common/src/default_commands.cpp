#include "client/command.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <unordered_map>

#include "engine/disasm.h"
#include "engine/dwarf.h"
#include "engine/eh_frame.h"
#include "engine/decompiler.h"
#include "engine/function_boundaries.h"
#include "engine/function_discovery.h"
#include "engine/llir.h"
#include "engine/mlil.h"
#include "engine/mlil_lift.h"
#include "engine/hlil.h"
#include "engine/hlil_lift.h"
#include "engine/rtti.h"
#include "engine/strings.h"
#include "engine/symbols.h"
#include "engine/xrefs.h"

namespace client {

namespace {

std::uint64_t parse_u64(const std::string& text, bool& ok) {
    ok = false;
    if (text.empty()) {
        return 0;
    }
    std::string s = text;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
        if (s.empty()) {
            return 0;
        }
        std::uint64_t value = 0;
        std::istringstream iss(s);
        iss >> std::hex >> value;
        ok = !iss.fail();
        return value;
    }
    std::uint64_t value = 0;
    std::istringstream iss(s);
    iss >> value;
    ok = !iss.fail();
    return value;
}

std::string to_lower(const std::string& input) {
    std::string result;
    result.reserve(input.size());
    for (unsigned char c : input) {
        result.push_back(static_cast<char>(std::tolower(c)));
    }
    return result;
}

bool matches_filter(const std::string& filter, const std::string& text) {
    if (filter.empty()) {
        return true;
    }
    const std::string filter_lower = to_lower(filter);
    const std::string target = to_lower(text);
    return target.find(filter_lower) != std::string::npos;
}

std::string format_hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

std::string symbol_display_name(const engine::symbols::SymbolEntry& entry) {
    if (!entry.demangled_name.empty()) {
        return entry.demangled_name;
    }
    if (!entry.name.empty()) {
        return entry.name;
    }
    return "<anon>";
}

bool symbol_matches_filter(const engine::symbols::SymbolEntry& entry, const std::string& filter) {
    if (filter.empty()) {
        return true;
    }
    if (matches_filter(filter, entry.demangled_name)) {
        return true;
    }
    return matches_filter(filter, entry.name);
}

const char* xref_kind_label(engine::xrefs::XrefKind kind) {
    switch (kind) {
        case engine::xrefs::XrefKind::kDataPointer: return "data";
        case engine::xrefs::XrefKind::kCodeCall: return "call";
        case engine::xrefs::XrefKind::kCodeJump: return "jump";
        case engine::xrefs::XrefKind::kCodeCallIndirect: return "call_indirect";
        case engine::xrefs::XrefKind::kCodeJumpIndirect: return "jump_indirect";
    }
    return "xref";
}

const char* seed_kind_label(engine::analysis::SeedKind kind) {
    switch (kind) {
        case engine::analysis::SeedKind::kEntry: return "entry";
        case engine::analysis::SeedKind::kManual: return "manual";
        case engine::analysis::SeedKind::kSymbol: return "symbol";
        case engine::analysis::SeedKind::kPlt: return "plt";
        case engine::analysis::SeedKind::kInitArray: return "init_array";
        case engine::analysis::SeedKind::kEhFrame: return "eh_frame";
        case engine::analysis::SeedKind::kPrologue: return "prologue";
        case engine::analysis::SeedKind::kDwarf: return "dwarf";
        case engine::analysis::SeedKind::kLinearSweep: return "linear";
    }
    return "seed";
}

const char* range_kind_label(engine::analysis::FunctionRangeKind kind) {
    switch (kind) {
        case engine::analysis::FunctionRangeKind::kDwarf: return "dwarf";
        case engine::analysis::FunctionRangeKind::kEhFrame: return "eh_frame";
        case engine::analysis::FunctionRangeKind::kSymbol: return "symbol";
        case engine::analysis::FunctionRangeKind::kCfg: return "cfg";
    }
    return "range";
}

std::string dwarf_function_name(const engine::dwarf::DwarfFunction& func) {
    if (!func.name.empty()) {
        return func.name;
    }
    if (!func.linkage_name.empty()) {
        return func.linkage_name;
    }
    return "<anon>";
}

std::string dwarf_variable_name(const engine::dwarf::DwarfVariable& var) {
    if (!var.name.empty()) {
        return var.name;
    }
    if (!var.linkage_name.empty()) {
        return var.linkage_name;
    }
    return "<anon>";
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

void emit_hlil_stmt_block(const std::vector<engine::hlil::HlilStmt>& stmts,
                          int indent,
                          const HlilVarRenameMap& renames,
                          Output& output) {
    for (const auto& stmt : stmts) {
        if (stmt.kind == engine::hlil::HlilStmtKind::kIf) {
            output.write_line(format_hlil_stmt(stmt, renames, indent));
            emit_hlil_stmt_block(stmt.then_body, indent + 1, renames, output);
            if (!stmt.else_body.empty()) {
                output.write_line(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "} else {");
                emit_hlil_stmt_block(stmt.else_body, indent + 1, renames, output);
            }
            output.write_line(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "}");
            continue;
        }
        if (stmt.kind == engine::hlil::HlilStmtKind::kWhile) {
            output.write_line(format_hlil_stmt(stmt, renames, indent));
            emit_hlil_stmt_block(stmt.body, indent + 1, renames, output);
            output.write_line(std::string(static_cast<std::size_t>(indent) * 4, ' ') + "}");
            continue;
        }
        output.write_line(format_hlil_stmt(stmt, renames, indent));
    }
}

void emit_hlil_function(const engine::hlil::Function& function, Output& output) {
    if (function.stmts.empty()) {
        output.write_line("no hlil statements");
        return;
    }
    emit_hlil_stmt_block(function.stmts, 0, function.var_renames, output);
}

void emit_llir_function(const engine::llir::Function& function, Output& output) {
    if (function.blocks.empty()) {
        output.write_line("no llir blocks");
        return;
    }
    for (const auto& block : function.blocks) {
        output.write_line("block " + format_hex(block.start) + " - " + format_hex(block.end));
        for (const auto& phi : block.phis) {
            output.write_line("    " + format_llir_stmt(phi));
        }
        for (const auto& inst : block.instructions) {
            std::ostringstream oss;
            oss << "  " << format_hex(inst.address) << ":";
            if (!inst.mnemonic.empty()) {
                oss << " " << inst.mnemonic;
            }
            if (!inst.operands.empty()) {
                oss << " " << inst.operands;
            }
            output.write_line(oss.str());
            const auto& stmts = inst.llil_ssa.empty() ? inst.llil : inst.llil_ssa;
            for (const auto& stmt : stmts) {
                output.write_line("    " + format_llir_stmt(stmt));
            }
        }
    }
}

void emit_mlil_function(const engine::mlil::Function& function, Output& output) {
    if (function.blocks.empty()) {
        output.write_line("no mlil blocks");
        return;
    }
    for (const auto& block : function.blocks) {
        output.write_line("block " + format_hex(block.start) + " - " + format_hex(block.end));
        for (const auto& phi : block.phis) {
            output.write_line("    " + format_mlil_stmt(phi));
        }
        for (const auto& inst : block.instructions) {
            std::ostringstream oss;
            oss << "  " << format_hex(inst.address) << ":";
            output.write_line(oss.str());
            for (const auto& stmt : inst.stmts) {
                output.write_line("    " + format_mlil_stmt(stmt));
            }
        }
    }
}

bool require_loaded(const Session& session, Output& output) {
    if (!session.loaded()) {
        output.write_line("no file loaded, use: open <path>");
        return false;
    }
    return true;
}

}  // namespace

CommandRegistry make_default_registry() {
    CommandRegistry registry;

    registry.register_command(Command{
        "open",
        {},
        "open <path>   load binary file",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (args.size() < 2) {
                output.write_line("usage: open <path>");
                return true;
            }
            std::string error;
            if (!session.open(args[1], error)) {
                output.write_line("load error: " + error);
                return true;
            }
            std::ostringstream oss;
            oss << "loaded: " << session.path();
            output.write_line(oss.str());
            oss.str("");
            oss << "entry: 0x" << std::hex << session.binary_info().entry;
            output.write_line(oss.str());
            return true;
        }});

    registry.register_command(Command{
        "close",
        {},
        "close         unload current file",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!session.loaded()) {
                output.write_line("no file loaded");
                return true;
            }
            session.close();
            output.write_line("closed");
            return true;
        }});

    registry.register_command(Command{
        "info",
        {},
        "info          show binary info",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
            std::ostringstream oss;
            switch (session.binary_info().format) {
                case engine::BinaryFormat::kElf:
                    oss << "Format: ELF";
                    break;
                case engine::BinaryFormat::kPe:
                    oss << "Format: PE";
                    break;
                default:
                    oss << "Format: unknown";
                    break;
            }
            output.write_line(oss.str());
            oss.str("");
            oss << "64-bit: " << (session.binary_info().is_64 ? "yes" : "no");
            output.write_line(oss.str());
            oss.str("");
            oss << "Little endian: " << (session.binary_info().little_endian ? "yes" : "no");
            output.write_line(oss.str());
            oss.str("");
            oss << "Entry: 0x" << std::hex << session.binary_info().entry;
            output.write_line(oss.str());
            oss.str("");
            oss << "Program headers: " << std::dec << session.binary_info().ph_num;
            output.write_line(oss.str());
            oss.str("");
            oss << "Section headers: " << session.binary_info().sh_num;
            output.write_line(oss.str());
            return true;
        }});

    registry.register_command(Command{
        "ph",
        {},
        "ph            list program headers",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
            for (std::size_t i = 0; i < session.segments().size(); ++i) {
                const auto& seg = session.segments()[i];
                std::ostringstream oss;
                oss << "PH[" << i << "] type=" << seg.type << " flags=0x" << std::hex << seg.flags << std::dec
                    << " off=0x" << std::hex << seg.offset << " vaddr=0x" << seg.vaddr << std::dec << " filesz=0x"
                    << std::hex << seg.filesz << " memsz=0x" << seg.memsz << std::dec;
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "sh",
        {},
        "sh            list section headers",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
            for (std::size_t i = 0; i < session.sections().size(); ++i) {
                const auto& sec = session.sections()[i];
                std::ostringstream oss;
                oss << "SH[" << i << "] name=" << (sec.name.empty() ? "<noname>" : sec.name) << " type=" << sec.type
                    << " flags=0x" << std::hex << sec.flags << std::dec << " addr=0x" << std::hex << sec.addr
                    << std::dec << " off=0x" << std::hex << sec.offset << " size=0x" << sec.size << std::dec;
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "relocs",
        {"rl"},
        "relocs        list relocations",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
            const auto& relocs = session.relocations();
            if (relocs.empty()) {
                output.write_line("no relocations");
                return true;
            }
            for (const auto& reloc : relocs) {
                std::ostringstream oss;
                oss << format_hex(reloc.offset) << " type=" << reloc.type;
                oss << " sym=" << reloc.sym;
                oss << " value=" << format_hex(reloc.symbol_value);
                oss << " addend=" << reloc.addend;
                if (!reloc.symbol_name.empty()) {
                    oss << " name=" << reloc.symbol_name;
                }
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "symbols",
        {"sym"},
        "symbols [filter]  list symbols",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 2) {
                output.write_line("usage: symbols [filter]");
                return true;
            }
            std::string filter;
            if (args.size() >= 2) {
                filter = args[1];
            }
            const auto& symbols = session.symbol_table().entries();
            if (symbols.empty()) {
                output.write_line("no symbols");
                return true;
            }
            for (const auto& entry : symbols) {
                if (!symbol_matches_filter(entry, filter)) {
                    continue;
                }
                std::string name = symbol_display_name(entry);
                std::ostringstream oss;
                oss << format_hex(entry.address) << " size=" << format_hex(entry.size) << " "
                    << (entry.is_function() ? "func" : "data") << " " << name;
                if (!entry.demangled_name.empty() && !entry.name.empty() &&
                    entry.demangled_name != entry.name) {
                    oss << " (" << entry.name << ")";
                }
                if (!entry.section_name.empty()) {
                    oss << " [" << entry.section_name << "]";
                }
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "funcs",
        {"af"},
        "funcs [min] [filter]  list function symbols",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            std::uint64_t min_size = 1;
            std::string filter;
            if (args.size() >= 2) {
                bool ok = false;
                auto parsed = parse_u64(args[1], ok);
                if (ok) {
                    min_size = parsed;
                    if (args.size() >= 3) {
                        filter = args[2];
                    }
                    if (args.size() > 3) {
                        output.write_line("usage: funcs [min] [filter]");
                        return true;
                    }
                } else {
                    filter = args[1];
                    if (args.size() > 2) {
                        output.write_line("usage: funcs [min] [filter]");
                        return true;
                    }
                }
            }
            const auto& symbols = session.symbol_table().entries();
            bool any = false;
            for (const auto& entry : symbols) {
                if (!entry.is_function()) {
                    continue;
                }
                if (entry.size < min_size) {
                    continue;
                }
                if (!symbol_matches_filter(entry, filter)) {
                    continue;
                }
                std::ostringstream oss;
                oss << format_hex(entry.address) << " size=" << format_hex(entry.size) << " "
                    << symbol_display_name(entry);
                if (!entry.demangled_name.empty() && !entry.name.empty() &&
                    entry.demangled_name != entry.name) {
                    oss << " (" << entry.name << ")";
                }
                output.write_line(oss.str());
                any = true;
            }
            if (!any) {
                output.write_line("no matching functions");
            }
            return true;
        }});

    registry.register_command(Command{
        "names",
        {},
        "names [filter]  list symbols and RTTI names",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 2) {
                output.write_line("usage: names [filter]");
                return true;
            }
            std::string filter;
            if (args.size() >= 2) {
                filter = args[1];
            }
            bool any = false;
            for (const auto& entry : session.symbol_table().entries()) {
                if (!symbol_matches_filter(entry, filter)) {
                    continue;
                }
                std::ostringstream oss;
                oss << "symbol " << format_hex(entry.address) << " size=" << format_hex(entry.size) << " "
                    << symbol_display_name(entry);
                if (!entry.section_name.empty()) {
                    oss << " [" << entry.section_name << "]";
                }
                output.write_line(oss.str());
                any = true;
            }
            for (const auto& type : session.rtti_catalog().types()) {
                std::string name = type.name.empty() ? "<unnamed type>" : type.name;
                if (!matches_filter(filter, name)) {
                    continue;
                }
                std::ostringstream oss;
                oss << "type " << format_hex(type.address) << " vtable=" << format_hex(type.vtable_address) << " "
                    << name;
                output.write_line(oss.str());
                any = true;
            }
            for (const auto& vtable : session.rtti_catalog().vtables()) {
                std::string name = vtable.type_name.empty() ? "<vtable>" : vtable.type_name;
                if (!matches_filter(filter, name)) {
                    continue;
                }
                std::ostringstream oss;
                oss << "vtable " << format_hex(vtable.address) << " entries=" << vtable.entries.size() << " "
                    << name;
                output.write_line(oss.str());
                any = true;
            }
            if (!any) {
                output.write_line("no matching names");
            }
            return true;
        }});

    registry.register_command(Command{
        "strings",
        {"str"},
        "strings [min] [filter]  list strings",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            std::size_t min_length = 4;
            std::string filter;
            if (args.size() >= 2) {
                bool ok = false;
                auto parsed = parse_u64(args[1], ok);
                if (ok) {
                    min_length = static_cast<std::size_t>(parsed);
                    if (args.size() >= 3) {
                        filter = args[2];
                    }
                    if (args.size() > 3) {
                        output.write_line("usage: strings [min] [filter]");
                        return true;
                    }
                } else {
                    filter = args[1];
                    if (args.size() > 2) {
                        output.write_line("usage: strings [min] [filter]");
                        return true;
                    }
                }
            }
            const auto& entries = session.string_catalog().entries();
            bool any = false;
            for (const auto& entry : entries) {
                if (entry.length < min_length) {
                    continue;
                }
                if (!matches_filter(filter, entry.text)) {
                    continue;
                }
                std::ostringstream oss;
                oss << format_hex(entry.address) << " len=" << entry.length;
                if (!entry.section_name.empty()) {
                    oss << " [" << entry.section_name << "]";
                }
                if (!entry.symbol_name.empty()) {
                    oss << " sym=" << entry.symbol_name;
                }
                if (!entry.text.empty()) {
                    oss << " " << entry.text;
                }
                output.write_line(oss.str());
                any = true;
            }
            if (!any) {
                output.write_line("no matching strings");
            }
            return true;
        }});

    registry.register_command(Command{
        "xrefs",
        {"xr"},
        "xrefs <addr> [max]  find xrefs to address",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() < 2 || args.size() > 3) {
                output.write_line("usage: xrefs <addr> [max]");
                return true;
            }
            bool ok = false;
            std::uint64_t target = parse_u64(args[1], ok);
            if (!ok) {
                output.write_line("invalid address: " + args[1]);
                return true;
            }
            std::size_t max_results = 256;
            if (args.size() == 3) {
                auto parsed = parse_u64(args[2], ok);
                if (!ok) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_results = static_cast<std::size_t>(parsed);
            }
            std::vector<engine::xrefs::XrefEntry> entries;
            if (!session.find_xrefs_to_address(target, max_results, entries)) {
                output.write_line("xrefs search failed");
                return true;
            }
            if (entries.empty()) {
                output.write_line("no xrefs found");
                return true;
            }
            for (const auto& entry : entries) {
                std::ostringstream oss;
                oss << format_hex(entry.source) << " -> " << format_hex(entry.target) << " "
                    << xref_kind_label(entry.kind);
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "seek",
        {"s"},
        "seek <addr>   set current address",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() < 2) {
                output.write_line("usage: seek <addr>");
                return true;
            }
            bool ok = false;
            std::uint64_t addr = parse_u64(args[1], ok);
            if (!ok) {
                output.write_line("invalid address: " + args[1]);
                return true;
            }
            session.set_cursor(addr);
            std::ostringstream oss;
            oss << "cursor = 0x" << std::hex << session.cursor();
            output.write_line(oss.str());
            return true;
        }});

    registry.register_command(Command{
        "pd",
        {},
        "pd [n]        disassemble n instructions (default 20)",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            std::size_t count = 20;
            if (args.size() >= 2) {
                bool ok = false;
                auto parsed = parse_u64(args[1], ok);
                if (!ok) {
                    output.write_line("invalid count: " + args[1]);
                    return true;
                }
                count = static_cast<std::size_t>(parsed);
            }
            std::vector<engine::DisasmLine> disasm;
            std::string error;
            const auto machine = session.binary_info().machine;
            const std::size_t max_bytes = count * ((machine == engine::BinaryMachine::kAarch64) ? 4U : 15U);
            bool ok = false;
            if (machine == engine::BinaryMachine::kAarch64) {
                ok = session.disasm_arm64(session.cursor(), max_bytes, count, disasm, error);
            } else if (machine == engine::BinaryMachine::kX86_64) {
                ok = session.disasm_x86_64(session.cursor(), max_bytes, count, disasm, error);
            } else {
                error = "unsupported architecture for disasm";
            }
            if (ok) {
                for (const auto& line : disasm) {
                    std::ostringstream oss;
                    oss << "  0x" << std::hex << line.address << std::dec << ": " << line.text;
                    output.write_line(oss.str());
                }
                if (!disasm.empty()) {
                    const auto& last = disasm.back();
                    const std::uint64_t advance = last.size != 0 ? last.size : 4;
                    session.set_cursor(last.address + advance);
                }
            } else {
                output.write_line("disasm error: " + error);
            }
            return true;
        }});

    registry.register_command(Command{
        "px",
        {"xd"},
        "px <addr> [len]  hex dump bytes",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() < 2 || args.size() > 3) {
                output.write_line("usage: px <addr> [len]");
                return true;
            }
            bool ok = false;
            std::uint64_t addr = parse_u64(args[1], ok);
            if (!ok) {
                output.write_line("invalid address: " + args[1]);
                return true;
            }
            std::size_t length = 64;
            if (args.size() == 3) {
                auto parsed = parse_u64(args[2], ok);
                if (!ok) {
                    output.write_line("invalid length: " + args[2]);
                    return true;
                }
                length = static_cast<std::size_t>(parsed);
            }
            std::vector<std::uint8_t> bytes;
            if (!session.image().read_bytes(addr, length, bytes)) {
                output.write_line("read error");
                return true;
            }
            if (bytes.empty()) {
                output.write_line("no bytes");
                return true;
            }
            const std::size_t per_line = 16;
            for (std::size_t offset = 0; offset < bytes.size(); offset += per_line) {
                std::ostringstream oss;
                oss << format_hex(addr + offset) << ": ";
                for (std::size_t i = 0; i < per_line; ++i) {
                    if (offset + i < bytes.size()) {
                        oss << std::setw(2) << std::setfill('0') << std::hex
                            << static_cast<int>(bytes[offset + i]);
                    } else {
                        oss << "  ";
                    }
                    if (i + 1 < per_line) {
                        oss << " ";
                    }
                }
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "llir",
        {"il"},
        "llir [addr] [max]  show LLIR SSA",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: llir [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                bool ok = false;
                addr = parse_u64(args[1], ok);
                if (!ok) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                bool ok = false;
                auto parsed = parse_u64(args[2], ok);
                if (!ok) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
            engine::llir::Function function;
            std::string error;
            bool ok = false;
            const auto machine = session.binary_info().machine;
            if (machine == engine::BinaryMachine::kAarch64) {
                ok = session.build_llir_ssa_arm64(addr, max_instructions, function, error);
            } else if (machine == engine::BinaryMachine::kX86_64) {
                ok = session.build_llir_ssa_x86_64(addr, max_instructions, function, error);
            } else {
                error = "unsupported architecture for llir";
            }
            if (!ok) {
                output.write_line("llir error: " + (error.empty() ? "build failed" : error));
                return true;
            }
            emit_llir_function(function, output);
            return true;
        }});

    registry.register_command(Command{
        "mlil",
        {"ml"},
        "mlil [addr] [max]  show MLIL",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: mlil [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                bool ok = false;
                addr = parse_u64(args[1], ok);
                if (!ok) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                bool ok = false;
                auto parsed = parse_u64(args[2], ok);
                if (!ok) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
            engine::llir::Function llir_function;
            std::string error;
            bool ok = false;
            const auto machine = session.binary_info().machine;
            if (machine == engine::BinaryMachine::kAarch64) {
                engine::mlil::Function mlil_function;
                ok = session.build_mlil_ssa_arm64(addr, max_instructions, mlil_function, error);
                if (!ok) {
                    output.write_line("mlil error: " + (error.empty() ? "build failed" : error));
                    return true;
                }
                emit_mlil_function(mlil_function, output);
                return true;
            } else if (machine == engine::BinaryMachine::kX86_64) {
                ok = session.build_llir_ssa_x86_64(addr, max_instructions, llir_function, error);
            } else {
                error = "unsupported architecture for llir";
            }
            if (!ok) {
                output.write_line("llir error: " + (error.empty() ? "build failed" : error));
                return true;
            }
            engine::mlil::Function mlil_function;
            if (!engine::mlil::build_mlil_from_llil_ssa(llir_function, mlil_function, error)) {
                output.write_line("mlil error: " + (error.empty() ? "build failed" : error));
                return true;
            }
            emit_mlil_function(mlil_function, output);
            return true;
        }});

    registry.register_command(Command{
        "hlil",
        {"hl"},
        "hlil [addr] [max]  show HLIL (early prototype)",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: hlil [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                bool ok = false;
                addr = parse_u64(args[1], ok);
                if (!ok) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                bool ok = false;
                auto parsed = parse_u64(args[2], ok);
                if (!ok) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }

            std::string error;
            const auto machine = session.binary_info().machine;
            if (machine != engine::BinaryMachine::kAarch64) {
                output.write_line("hlil error: only arm64 is supported for now");
                return true;
            }

            engine::hlil::Function hlil_function;
            if (!session.build_hlil_arm64(addr, max_instructions, hlil_function, error)) {
                output.write_line("hlil error: " + (error.empty() ? "build failed" : error));
                return true;
            }
            emit_hlil_function(hlil_function, output);
            return true;
        }});

    registry.register_command(Command{
        "hlilraw",
        {"hlil0"},
        "hlilraw [addr] [max]  show HLIL without optimizations",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: hlilraw [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                bool ok = false;
                addr = parse_u64(args[1], ok);
                if (!ok) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                bool ok = false;
                auto parsed = parse_u64(args[2], ok);
                if (!ok) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }

            std::string error;
            const auto machine = session.binary_info().machine;
            if (machine != engine::BinaryMachine::kAarch64) {
                output.write_line("hlilraw error: only arm64 is supported for now");
                return true;
            }

            engine::mlil::Function mlil_function;
            if (!session.build_mlil_ssa_arm64(addr, max_instructions, mlil_function, error)) {
                output.write_line("hlilraw error: " + (error.empty() ? "mlil build failed" : error));
                return true;
            }

            engine::hlil::Function hlil_function;
            if (!engine::hlil::build_hlil_from_mlil(mlil_function, hlil_function, error)) {
                output.write_line("hlilraw error: " + (error.empty() ? "hlil build failed" : error));
                return true;
            }

            emit_hlil_function(hlil_function, output);
            return true;
        }});

    registry.register_command(Command{
        "pseudoc",
        {"pc"},
        "pseudoc [addr] [max]  show pseudo-C (early prototype)",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 3) {
                output.write_line("usage: pseudoc [addr] [max]");
                return true;
            }
            std::uint64_t addr = session.cursor();
            std::size_t max_instructions = 1024;
            if (args.size() >= 2) {
                bool ok = false;
                addr = parse_u64(args[1], ok);
                if (!ok) {
                    output.write_line("invalid address: " + args[1]);
                    return true;
                }
            }
            if (args.size() == 3) {
                bool ok = false;
                auto parsed = parse_u64(args[2], ok);
                if (!ok) {
                    output.write_line("invalid max: " + args[2]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }

            std::string error;
            const auto machine = session.binary_info().machine;
            if (machine != engine::BinaryMachine::kAarch64) {
                output.write_line("pseudoc error: only arm64 is supported for now");
                return true;
            }

            engine::decompiler::Function pseudo_function;
            engine::decompiler::FunctionHints hints;
            const auto* dwarf_fn = session.dwarf_catalog().find_function_by_address(addr);
            if (dwarf_fn) {
                if (!dwarf_fn->name.empty()) {
                    hints.name = dwarf_fn->name;
                } else if (!dwarf_fn->linkage_name.empty()) {
                    hints.name = dwarf_fn->linkage_name;
                }
            }
            if (hints.name.empty()) {
                auto symbols = session.symbol_table().within_range(addr, 1);
                if (!symbols.empty() && symbols.front()) {
                    const auto* sym = symbols.front();
                    if (!sym->demangled_name.empty()) {
                        hints.name = sym->demangled_name;
                    } else if (!sym->name.empty()) {
                        hints.name = sym->name;
                    }
                }
            }
            engine::mlil::Function mlil_function;
            if (!session.build_mlil_ssa_arm64(addr, max_instructions, mlil_function, error)) {
                output.write_line("pseudoc error: " + (error.empty() ? "build failed" : error));
                return true;
            }
            if (!engine::decompiler::build_pseudoc_from_mlil_ssa(mlil_function, pseudo_function, error, &hints)) {
                output.write_line("pseudoc error: " + (error.empty() ? "build failed" : error));
                return true;
            }

            std::vector<std::string> lines;
            engine::decompiler::emit_pseudoc(pseudo_function, lines);
            for (const auto& line : lines) {
                output.write_line(line);
            }
            return true;
        }});

    registry.register_command(Command{
        "fdisc",
        {"fd"},
        "fdisc [max]   discover functions",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 2) {
                output.write_line("usage: fdisc [max]");
                return true;
            }
            std::size_t max_instructions = 2048;
            if (args.size() == 2) {
                bool ok = false;
                auto parsed = parse_u64(args[1], ok);
                if (!ok) {
                    output.write_line("invalid max: " + args[1]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
            engine::analysis::FunctionDiscoveryOptions options;
            std::vector<engine::llir::Function> functions;
            std::string error;
            bool ok = false;
            const auto machine = session.binary_info().machine;
            if (machine == engine::BinaryMachine::kAarch64) {
                ok = session.discover_llir_functions_arm64(session.binary_info().entry,
                                                          max_instructions,
                                                          options,
                                                          functions,
                                                          error);
            } else if (machine == engine::BinaryMachine::kX86_64) {
                ok = session.discover_llir_functions_x86_64(session.binary_info().entry,
                                                           max_instructions,
                                                           options,
                                                           functions,
                                                           error);
            } else {
                error = "unsupported architecture for discovery";
            }
            if (!ok) {
                output.write_line("discovery error: " + (error.empty() ? "failed" : error));
                return true;
            }
            if (functions.empty()) {
                output.write_line("no functions discovered");
                return true;
            }
            std::sort(functions.begin(),
                      functions.end(),
                      [](const engine::llir::Function& a, const engine::llir::Function& b) {
                          return a.entry < b.entry;
                      });
            for (const auto& func : functions) {
                std::string name;
                auto matches = session.symbol_table().within_range(func.entry, 1);
                if (!matches.empty() && matches.front()) {
                    name = symbol_display_name(*matches.front());
                } else {
                    name = "sub_" + format_hex(func.entry);
                }
                std::ostringstream oss;
                oss << format_hex(func.entry) << " size=" << format_hex(discovered_size(func))
                    << " blocks=" << func.blocks.size() << " " << name;
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "franges",
        {"fr"},
        "franges [max]  discover function ranges",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() > 2) {
                output.write_line("usage: franges [max]");
                return true;
            }
            std::size_t max_instructions = 2048;
            if (args.size() == 2) {
                bool ok = false;
                auto parsed = parse_u64(args[1], ok);
                if (!ok) {
                    output.write_line("invalid max: " + args[1]);
                    return true;
                }
                max_instructions = static_cast<std::size_t>(parsed);
            }
            engine::analysis::FunctionDiscoveryOptions options;
            std::vector<engine::analysis::FunctionRange> ranges;
            std::string error;
            bool ok = false;
            const auto machine = session.binary_info().machine;
            if (machine == engine::BinaryMachine::kAarch64) {
                ok = session.discover_function_ranges_arm64(session.binary_info().entry,
                                                           max_instructions,
                                                           options,
                                                           ranges,
                                                           error);
            } else if (machine == engine::BinaryMachine::kX86_64) {
                ok = session.discover_function_ranges_x86_64(session.binary_info().entry,
                                                            max_instructions,
                                                            options,
                                                            ranges,
                                                            error);
            } else {
                error = "unsupported architecture for discovery";
            }
            if (!ok) {
                output.write_line("range error: " + (error.empty() ? "failed" : error));
                return true;
            }
            if (ranges.empty()) {
                output.write_line("no ranges discovered");
                return true;
            }
            std::sort(ranges.begin(),
                      ranges.end(),
                      [](const engine::analysis::FunctionRange& a, const engine::analysis::FunctionRange& b) {
                          return a.start < b.start;
                      });
            for (const auto& range : ranges) {
                std::ostringstream oss;
                oss << format_hex(range.start) << " - " << format_hex(range.end) << " kind="
                    << range_kind_label(range.kind) << " seed=" << seed_kind_label(range.seed_kind)
                    << " hard=" << (range.hard ? "yes" : "no");
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "dwarf",
        {},
        "dwarf <funcs|vars|line>  show DWARF data",
        [](Session& session, Output& output, const std::vector<std::string>& args) {
            if (!require_loaded(session, output)) {
                return true;
            }
            if (args.size() < 2) {
                output.write_line("usage: dwarf <funcs|vars|line>");
                output.write_line("  dwarf funcs [filter]");
                output.write_line("  dwarf vars [filter]");
                output.write_line("  dwarf line <addr>");
                return true;
            }
            const auto& catalog = session.dwarf_catalog();
            const std::string& sub = args[1];
            if (sub == "funcs") {
                if (args.size() > 3) {
                    output.write_line("usage: dwarf funcs [filter]");
                    return true;
                }
                std::string filter;
                if (args.size() == 3) {
                    filter = args[2];
                }
                const auto& funcs = catalog.functions();
                if (funcs.empty()) {
                    output.write_line("no dwarf functions");
                    return true;
                }
                bool any = false;
                for (const auto& func : funcs) {
                    std::string name = dwarf_function_name(func);
                    if (!matches_filter(filter, name) && !matches_filter(filter, func.linkage_name)) {
                        continue;
                    }
                    std::ostringstream oss;
                    oss << format_hex(func.low_pc) << " - " << format_hex(func.high_pc) << " " << name;
                    if (!func.linkage_name.empty() && func.linkage_name != name) {
                        oss << " (" << func.linkage_name << ")";
                    }
                    if (func.decl_line != 0) {
                        oss << " line=" << func.decl_line;
                    }
                    if (!func.ranges.empty()) {
                        oss << " ranges=" << func.ranges.size();
                    }
                    output.write_line(oss.str());
                    any = true;
                }
                if (!any) {
                    output.write_line("no matching dwarf functions");
                }
                return true;
            }
            if (sub == "vars") {
                if (args.size() > 3) {
                    output.write_line("usage: dwarf vars [filter]");
                    return true;
                }
                std::string filter;
                if (args.size() == 3) {
                    filter = args[2];
                }
                const auto& vars = catalog.variables();
                if (vars.empty()) {
                    output.write_line("no dwarf variables");
                    return true;
                }
                bool any = false;
                for (const auto& var : vars) {
                    std::string name = dwarf_variable_name(var);
                    if (!matches_filter(filter, name) && !matches_filter(filter, var.linkage_name)) {
                        continue;
                    }
                    std::ostringstream oss;
                    oss << name;
                    if (!var.linkage_name.empty() && var.linkage_name != name) {
                        oss << " (" << var.linkage_name << ")";
                    }
                    if (!var.location_list.empty()) {
                        oss << " locs=" << var.location_list.size();
                    }
                    if (!var.location_expr.empty()) {
                        oss << " expr=" << var.location_expr.size();
                    }
                    output.write_line(oss.str());
                    any = true;
                }
                if (!any) {
                    output.write_line("no matching dwarf variables");
                }
                return true;
            }
            if (sub == "line") {
                if (args.size() != 3) {
                    output.write_line("usage: dwarf line <addr>");
                    return true;
                }
                bool ok = false;
                std::uint64_t addr = parse_u64(args[2], ok);
                if (!ok) {
                    output.write_line("invalid address: " + args[2]);
                    return true;
                }
                const auto* row = catalog.find_line_for_address(addr);
                if (!row) {
                    output.write_line("no line info for address");
                    return true;
                }
                std::ostringstream oss;
                oss << format_hex(addr) << " ";
                if (!row->file.empty()) {
                    oss << row->file << ":";
                }
                oss << row->line;
                output.write_line(oss.str());
                return true;
            }
            output.write_line("unknown dwarf command: " + sub);
            return true;
        }});

    registry.register_command(Command{
        "ehframe",
        {},
        "ehframe       list .eh_frame entries",
        [](Session& session, Output& output, const std::vector<std::string>&) {
            if (!require_loaded(session, output)) {
                return true;
            }
            const auto& entries = session.eh_frame_catalog().entries();
            if (entries.empty()) {
                output.write_line("no eh_frame entries");
                return true;
            }
            for (const auto& entry : entries) {
                std::ostringstream oss;
                oss << format_hex(entry.start) << " size=" << format_hex(entry.size);
                oss << " rows=" << entry.rows.size();
                oss << " cie=" << format_hex(entry.cie);
                output.write_line(oss.str());
            }
            return true;
        }});

    registry.register_command(Command{
        "help",
        {"h", "?"},
        "help          show commands",
        [](Session&, Output& output, const std::vector<std::string>&) {
            output.write_line("Commands:");
            output.write_line("  open   close  info   ph      sh      relocs");
            output.write_line("  symbols funcs  names  strings xrefs");
            output.write_line("  seek   s      pd     px      llir    mlil");
            output.write_line("  fdisc  franges dwarf  ehframe");
            output.write_line("  help   quit   q      exit");
            return true;
        }});

    registry.register_command(Command{
        "quit",
        {"q", "exit"},
        "quit          exit",
        [](Session&, Output&, const std::vector<std::string>&) { return false; }});

    return registry;
}

}  // namespace client
