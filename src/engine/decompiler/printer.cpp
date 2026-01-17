#include "printer.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <unordered_map>

#include "engine/decompiler/transforms.h"

namespace engine::decompiler {

namespace {

const std::unordered_map<std::string, std::string>* g_name_remap = nullptr;

} // namespace

std::string format_hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

std::string normalize_function_name(std::string name) {
    auto pos = name.find('(');
    if (pos != std::string::npos) {
        name = name.substr(0, pos);
    }
    while (!name.empty() && std::isspace(static_cast<unsigned char>(name.back()))) {
        name.pop_back();
    }
    return name;
}

std::string op_name(mlil::MlilOp op) {
    switch (op) {
        case mlil::MlilOp::kAdd: return "+";
        case mlil::MlilOp::kSub: return "-";
        case mlil::MlilOp::kMul: return "*";
        case mlil::MlilOp::kDiv: return "/";
        case mlil::MlilOp::kMod: return "%";
        case mlil::MlilOp::kAnd: return "&";
        case mlil::MlilOp::kOr: return "|";
        case mlil::MlilOp::kXor: return "^";
        case mlil::MlilOp::kShl: return "<<";
        case mlil::MlilOp::kShr: return ">>";
        case mlil::MlilOp::kSar: return ">>";
        case mlil::MlilOp::kRor: return "ror";
        case mlil::MlilOp::kNot: return "~";
        case mlil::MlilOp::kNeg: return "-";
        case mlil::MlilOp::kAbs: return "abs";
        case mlil::MlilOp::kMin: return "min";
        case mlil::MlilOp::kMax: return "max";
        case mlil::MlilOp::kBswap: return "bswap";
        case mlil::MlilOp::kClz: return "clz";
        case mlil::MlilOp::kRbit: return "rbit";
        case mlil::MlilOp::kSqrt: return "sqrt";
        case mlil::MlilOp::kCast: return "cast";
        case mlil::MlilOp::kSelect: return "select";
        case mlil::MlilOp::kEq: return "==";
        case mlil::MlilOp::kNe: return "!=";
        case mlil::MlilOp::kLt: return "<";
        case mlil::MlilOp::kLe: return "<=";
        case mlil::MlilOp::kGt: return ">";
        case mlil::MlilOp::kGe: return ">=";
    }
    return "op";
}

bool is_unary_symbol(mlil::MlilOp op) {
    return op == mlil::MlilOp::kNot || op == mlil::MlilOp::kNeg;
}

bool is_binary_symbol(mlil::MlilOp op) {
    switch (op) {
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
        case mlil::MlilOp::kGe:
            return true;
        default:
            return false;
    }
}

// Check if a string segment looks like a version suffix (e.g., "v0", "v123")
bool is_version_suffix(const std::string& s, std::size_t pos) {
    if (pos >= s.size()) return false;
    if (s[pos] != 'v' && s[pos] != 'V') return false;
    if (pos + 1 >= s.size()) return false;
    // Must be followed by digits
    for (std::size_t i = pos + 1; i < s.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
            return false;
        }
    }
    return true;
}

// Clean up SSA version suffixes from variable names
// e.g., "arg0_v0" -> "arg0", "v28_2_v32" -> "v28_2", "sp_v2421" -> "sp"
std::string clean_ssa_suffix(const std::string& name) {
    if (name.empty()) return name;
    
    // Look for patterns like "_v<digits>" at the end
    std::size_t last_underscore = name.rfind('_');
    if (last_underscore != std::string::npos && last_underscore + 1 < name.size()) {
        if (is_version_suffix(name, last_underscore + 1)) {
            std::string cleaned = name.substr(0, last_underscore);
            // Recursively clean in case of multiple suffixes (e.g., "v28_2_v32")
            return clean_ssa_suffix(cleaned);
        }
    }
    
    return name;
}

std::string display_name(const std::string& name) {
    if (name.empty()) {
        return name;
    }
    
    // First check if there's a remap
    if (g_name_remap) {
        auto it = g_name_remap->find(name);
        if (it != g_name_remap->end()) {
            return it->second;
        }
    }
    
    // Clean up SSA version suffixes
    std::string cleaned = clean_ssa_suffix(name);
    
    // Check if cleaned name has a remap
    if (g_name_remap && cleaned != name) {
        auto it = g_name_remap->find(cleaned);
        if (it != g_name_remap->end()) {
            return it->second;
        }
    }
    
    // Normalize stack variable names: "stack.28" -> "v28"
    if (cleaned.rfind("stack.", 0) == 0 && cleaned.size() > 6) {
        return "v" + cleaned.substr(6);
    }
    
    // Normalize arg slot names: "arg.0" -> "a0"
    if (cleaned.rfind("arg.", 0) == 0 && cleaned.size() > 4) {
        return "a" + cleaned.substr(4);
    }
    
    return cleaned;
}

bool is_boolish_expr(const mlil::MlilExpr& expr) {
    if (expr.size == 1) {
        return true;
    }
    if (expr.kind != mlil::MlilExprKind::kOp) {
        return false;
    }
    switch (expr.op) {
        case mlil::MlilOp::kEq:
        case mlil::MlilOp::kNe:
        case mlil::MlilOp::kLt:
        case mlil::MlilOp::kLe:
        case mlil::MlilOp::kGt:
        case mlil::MlilOp::kGe:
        case mlil::MlilOp::kNot:
        case mlil::MlilOp::kAnd:
        case mlil::MlilOp::kOr:
            return true;
        default:
            return false;
    }
}

std::string format_bool_term(const mlil::MlilExpr& expr) {
    if (expr.kind == mlil::MlilExprKind::kOp &&
        (expr.op == mlil::MlilOp::kAnd || expr.op == mlil::MlilOp::kOr)) {
        return "(" + format_bool_expr(expr) + ")";
    }
    return format_bool_expr(expr);
}

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

std::string format_index_with_offset(const std::string& index, std::int64_t offset, bool index_simple) {
    if (offset == 0) {
        return index;
    }
    std::uint64_t mag = static_cast<std::uint64_t>(offset < 0 ? -offset : offset);
    std::string suffix = format_hex(mag);
    if (offset < 0) {
        if (index_simple) {
            return index + " - " + suffix;
        }
        return "(" + index + " - " + suffix + ")";
    }
    if (index_simple) {
        return index + " + " + suffix;
    }
    return "(" + index + " + " + suffix + ")";
}

std::string try_format_array_access(const mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kLoad || expr.args.empty()) {
        return "";
    }
    const auto& addr = expr.args[0];
    if (addr.kind != mlil::MlilExprKind::kOp || addr.op != mlil::MlilOp::kAdd || addr.args.size() != 2) {
        return "";
    }
    
    auto is_scaled_index = [](const mlil::MlilExpr& e, std::string& idx_out) -> bool {
        if (e.kind == mlil::MlilExprKind::kVar) {
            // Simple index without scale (size 1)
            idx_out = format_expr_raw(e);
            return true;
        }
        if (e.kind == mlil::MlilExprKind::kOp && (e.op == mlil::MlilOp::kMul || e.op == mlil::MlilOp::kShl) && e.args.size() == 2) {
            // Check for index * scale
            if (e.args[0].kind == mlil::MlilExprKind::kVar && e.args[1].kind == mlil::MlilExprKind::kImm) {
                idx_out = format_expr_raw(e.args[0]);
                return true;
            }
            if (e.args[1].kind == mlil::MlilExprKind::kVar && e.args[0].kind == mlil::MlilExprKind::kImm) {
                idx_out = format_expr_raw(e.args[1]);
                return true;
            }
        }
        return false;
    };

    auto is_likely_index = [&](const mlil::MlilExpr& e) -> bool {
        if (e.kind == mlil::MlilExprKind::kImm) return true;
        if (e.kind == mlil::MlilExprKind::kVar) {
             // Heuristic: names starting with 'v' or 'i' are often indices/temporaries
             if (!e.var.name.empty() && (e.var.name[0] == 'v' || e.var.name[0] == 'i')) return true;
        }
        if (e.kind == mlil::MlilExprKind::kOp) {
             if (e.op == mlil::MlilOp::kMul || e.op == mlil::MlilOp::kShl) return true;
        }
        return false;
    };

    std::string index_str;
    
    mlil::MlilExpr base0;
    mlil::MlilExpr base1;
    std::int64_t off0 = 0;
    std::int64_t off1 = 0;
    if (split_var_offset(addr.args[0], base0, off0) && split_var_offset(addr.args[1], base1, off1)) {
        const bool base0_imm = base0.kind == mlil::MlilExprKind::kImm;
        const bool base1_imm = base1.kind == mlil::MlilExprKind::kImm;
        const bool base0_idx = is_likely_index(base0);
        const bool base1_idx = is_likely_index(base1);

        bool use0_as_base = false;
        if (!base0_imm && (base1_imm || base1_idx || !base0_idx)) {
            use0_as_base = true;
        } else if (!base1_imm && (base0_imm || base0_idx || !base1_idx)) {
            use0_as_base = false;
        } else {
            use0_as_base = true;
        }

        const mlil::MlilExpr& base = use0_as_base ? base0 : base1;
        const mlil::MlilExpr& index = use0_as_base ? base1 : base0;
        std::int64_t offset = off0 + off1;

        std::string index_str = format_expr_raw(index);
        const bool index_simple = (index.kind == mlil::MlilExprKind::kVar || index.kind == mlil::MlilExprKind::kImm);
        if (index.kind == mlil::MlilExprKind::kImm) {
            std::uint64_t imm = 0;
            get_imm_value(index, imm);
            std::int64_t idx = static_cast<std::int64_t>(imm) + offset;
            if (idx < 0) {
                index_str = "-" + format_hex(static_cast<std::uint64_t>(-idx));
            } else {
                index_str = format_hex(static_cast<std::uint64_t>(idx));
            }
        } else if (offset != 0) {
            index_str = format_index_with_offset(index_str, offset, index_simple);
        }

        return format_expr_raw(base) + "[" + index_str + "]";
    }

    if (addr.args[0].kind == mlil::MlilExprKind::kVar && is_scaled_index(addr.args[1], index_str)) {
        return format_expr_raw(addr.args[0]) + "[" + index_str + "]";
    }
    if (addr.args[1].kind == mlil::MlilExprKind::kVar && is_scaled_index(addr.args[0], index_str)) {
        return format_expr_raw(addr.args[1]) + "[" + index_str + "]";
    }
    
    return "";
}

std::string format_expr_raw(const mlil::MlilExpr& expr) {
    switch (expr.kind) {
        case mlil::MlilExprKind::kInvalid:
            return "/*invalid*/0";
        case mlil::MlilExprKind::kUnknown:
            return "/*unknown*/0";
        case mlil::MlilExprKind::kUndef:
            return "/*undef*/0";
        case mlil::MlilExprKind::kVar:
            return expr.var.name.empty() ? "var" : display_name(expr.var.name);
        case mlil::MlilExprKind::kImm:
            return format_hex(expr.imm);
        case mlil::MlilExprKind::kLoad: {
            std::string arr = try_format_array_access(expr);
            if (!arr.empty()) {
                return arr;
            }
            const mlil::MlilExpr& addr_expr = expr.args.empty() ? expr : expr.args.front();
            if (addr_expr.kind == mlil::MlilExprKind::kVar) {
                return "*" + format_expr_raw(addr_expr);
            }
            std::string addr = expr.args.empty() ? "0" : format_expr_raw(expr.args.front());
            return "*(" + addr + ")";
        }
        case mlil::MlilExprKind::kOp: {
            // Guard against malformed expressions with missing operands
            if (expr.args.empty()) {
                // Binary/comparison ops with no args - try to provide meaningful output
                if (is_binary_symbol(expr.op)) {
                    // For comparison operators with no args, this is likely a boolean result
                    // Return a constant that makes sense in context
                    switch (expr.op) {
                        case mlil::MlilOp::kEq:
                        case mlil::MlilOp::kNe:
                        case mlil::MlilOp::kLt:
                        case mlil::MlilOp::kLe:
                        case mlil::MlilOp::kGt:
                        case mlil::MlilOp::kGe:
                            // Boolean result - return false as default
                            return "0";
                        default:
                            // For arithmetic ops, return 0
                            return "0";
                    }
                }
                // For unary ops with no args, return 0
                return "0";
            }
            if (expr.op == mlil::MlilOp::kSelect && expr.args.size() == 3) {
                return "(" + format_expr_raw(expr.args[0]) + " ? " + format_expr_raw(expr.args[1]) + " : " +
                       format_expr_raw(expr.args[2]) + ")";
            }
            if (expr.op == mlil::MlilOp::kCast && !expr.args.empty()) {
                // Skip explicit cast printing for cleaner C code if it's just a width change
                return format_expr_raw(expr.args.front());
            }
            if (is_unary_symbol(expr.op) && expr.args.size() == 1) {
                return "(" + op_name(expr.op) + format_expr_raw(expr.args[0]) + ")";
            }
            if (is_binary_symbol(expr.op)) {
                if (expr.args.size() == 2) {
                    return "(" + format_expr_raw(expr.args[0]) + " " + op_name(expr.op) + " " +
                           format_expr_raw(expr.args[1]) + ")";
                } else if (expr.args.size() == 1) {
                    // Binary op with only one arg - treat as comparison with 0
                    return "(" + format_expr_raw(expr.args[0]) + " " + op_name(expr.op) + " 0)";
                }
            }
            std::ostringstream oss;
            oss << op_name(expr.op) << "(";
            for (std::size_t i = 0; i < expr.args.size(); ++i) {
                if (i > 0) {
                    oss << ", ";
                }
                oss << format_expr_raw(expr.args[i]);
            }
            oss << ")";
            return oss.str();
        }
        case mlil::MlilExprKind::kCall: {
            std::ostringstream oss;
            std::string call_target = format_expr_raw(expr.args.empty() ? mlil::MlilExpr{} : expr.args[0]);
            oss << call_target << "(";
            for (std::size_t i = 1; i < expr.args.size(); ++i) {
                if (i > 1) {
                    oss << ", ";
                }
                oss << format_expr_raw(expr.args[i]);
            }
            oss << ")";
            return oss.str();
        }
    }
    return "expr";
}

std::string format_expr(const mlil::MlilExpr& expr) {
    mlil::MlilExpr simplified = expr;
    simplify_expr(simplified);
    return format_expr_raw(simplified);
}

std::string format_bool_expr(const mlil::MlilExpr& expr) {
    if (expr.kind == mlil::MlilExprKind::kOp && expr.args.size() == 2) {
        const auto& lhs = expr.args[0];
        const auto& rhs = expr.args[1];
        if ((expr.op == mlil::MlilOp::kAnd || expr.op == mlil::MlilOp::kOr) &&
            is_boolish_expr(lhs) && is_boolish_expr(rhs)) {
            const char* op = (expr.op == mlil::MlilOp::kAnd) ? " && " : " || ";
            return format_bool_term(lhs) + op + format_bool_term(rhs);
        }
        if (expr.op == mlil::MlilOp::kEq || expr.op == mlil::MlilOp::kNe) {
            if (is_zero_imm(lhs)) {
                return (expr.op == mlil::MlilOp::kEq ? "!" : "") + format_bool_term(rhs);
            }
            if (is_zero_imm(rhs)) {
                return (expr.op == mlil::MlilOp::kEq ? "!" : "") + format_bool_term(lhs);
            }
        }
    }
    if (expr.kind == mlil::MlilExprKind::kOp && expr.op == mlil::MlilOp::kNot && expr.args.size() == 1) {
        return "!" + format_bool_term(expr.args[0]);
    }
    return format_expr_raw(expr);
}

std::string format_condition(const mlil::MlilExpr& expr) {
    mlil::MlilExpr simplified = expr;
    normalize_condition_expr(simplified);
    return format_bool_expr(simplified);
}

namespace {

bool expr_is_var_name(const mlil::MlilExpr& expr, const std::string& name) {
    return expr.kind == mlil::MlilExprKind::kVar && expr.var.name == name;
}

bool expr_is_imm_value(const mlil::MlilExpr& expr, std::uint64_t value) {
    std::uint64_t imm = 0;
    return get_imm_value(expr, imm) && imm == value;
}

} // namespace

void emit_stmt_to_lines(const Stmt& stmt,
                        int indent,
                        const std::unordered_set<std::string>& used,
                        const std::string& return_type,
                        std::vector<std::string>& out_lines) {
    const std::string pad(static_cast<std::size_t>(indent) * 4, ' ');
    switch (stmt.kind) {
        case StmtKind::kFor: {
            std::string init = " ";
            if (!stmt.then_body.empty() && stmt.then_body[0].kind == StmtKind::kAssign) {
                const auto& is = stmt.then_body[0];
                init = display_name(is.var.name) + " = " + format_expr(is.expr);
            }
            std::string step = " ";
            if (!stmt.else_body.empty() && stmt.else_body[0].kind == StmtKind::kAssign) {
                const auto& ss = stmt.else_body[0];
                step = display_name(ss.var.name) + " = " + format_expr(ss.expr);
            }
            
            std::string line = pad + "for (" + init + "; " + format_condition(stmt.condition) + "; " + step + ") {";
            out_lines.push_back(std::move(line));
            for (const auto& inner : stmt.body) {
                emit_stmt_to_lines(inner, indent + 1, used, return_type, out_lines);
            }
            out_lines.push_back(pad + "}");
            break;
        }
        case StmtKind::kAssign: {
            if (stmt.var.name.empty()) {
                break;
            }
            if (stmt.var.name == "sp" || stmt.var.name.find("sp_") == 0) {
                break;
            }
            if (used.find(stmt.var.name) == used.end()) {
                break;
            }
            if (expr_is_var_name(stmt.expr, stmt.var.name)) {
                break;
            }
            const std::string var_name = display_name(stmt.var.name);
            std::string line;
            if (stmt.expr.kind == mlil::MlilExprKind::kOp &&
                stmt.expr.args.size() == 2 &&
                (stmt.expr.op == mlil::MlilOp::kAdd || stmt.expr.op == mlil::MlilOp::kSub)) {
                const auto& a = stmt.expr.args[0];
                const auto& b = stmt.expr.args[1];
                const bool lhs_var = expr_is_var_name(a, stmt.var.name);
                const bool rhs_var = expr_is_var_name(b, stmt.var.name);
                if (stmt.expr.op == mlil::MlilOp::kAdd && (lhs_var || rhs_var)) {
                    const auto& other = lhs_var ? b : a;
                    if (expr_is_imm_value(other, 1)) {
                        line = pad + "++" + var_name + ";";
                    } else {
                        line = pad + var_name + " += " + format_expr(other) + ";";
                    }
                } else if (stmt.expr.op == mlil::MlilOp::kSub && lhs_var && !rhs_var) {
                    if (expr_is_imm_value(b, 1)) {
                        line = pad + "--" + var_name + ";";
                    } else {
                        line = pad + var_name + " -= " + format_expr(b) + ";";
                    }
                }
            }
            if (line.empty()) {
                mlil::MlilExpr simplified_expr = stmt.expr;
                simplify_expr(simplified_expr);
                std::string arr = try_format_array_access(simplified_expr);
                if (!arr.empty()) {
                    line = pad + var_name + " = " + arr + ";";
                } else {
                    line = pad + var_name + " = " + format_expr(stmt.expr) + ";";
                }
            }
            if (!stmt.comment.empty() && stmt.comment.find("phi") == std::string::npos && 
                stmt.comment.find("split edge") == std::string::npos) {
                line += " // " + stmt.comment;
            }
            if (!line.empty()) {
                out_lines.push_back(std::move(line));
            }
            break;
        }
        case StmtKind::kStore: {
            mlil::MlilExpr simplified_target = stmt.target;
            simplify_expr(simplified_target);
            mlil::MlilExpr fake_load;
            fake_load.kind = mlil::MlilExprKind::kLoad;
            fake_load.args.push_back(simplified_target);
            std::string lhs = try_format_array_access(fake_load);
            if (lhs.empty()) {
                lhs = "*(" + format_expr(stmt.target) + ")";
            }
            std::string line = pad + lhs + " = " + format_expr(stmt.expr) + ";";
            if (!stmt.comment.empty() && stmt.comment != "phi" && stmt.comment != "phi temp") {
                line += " // " + stmt.comment;
            }
            out_lines.push_back(std::move(line));
            break;
        }
        case StmtKind::kCall: {
            std::ostringstream oss;
            std::string call = format_expr(stmt.target);
            oss << call << "(";
            std::vector<mlil::MlilExpr> args = stmt.args;
            for (std::size_t i = 0; i < args.size(); ++i) {
                if (i > 0) {
                    oss << ", ";
                }
                oss << format_expr(args[i]);
            }
            oss << ")";
            std::string line;
            if (stmt.returns.empty()) {
                line = pad + oss.str() + ";";
            } else if (stmt.returns.size() == 1) {
                line = pad + display_name(stmt.returns.front().name) + " = " + oss.str() + ";";
            } else {
                line = pad + "/* multi-return */ " + display_name(stmt.returns.front().name) + " = " + oss.str() + ";";
            }
            if (!stmt.comment.empty()) {
                line += " // " + stmt.comment;
            }
            out_lines.push_back(std::move(line));
            break;
        }
        case StmtKind::kReturn: {
            std::string line = pad;
            if (stmt.expr.kind == mlil::MlilExprKind::kInvalid) {
                line += "return;";
            } else if (return_type == "void") {
                // If the function is void but returns a value, print it anyway for debugging/correctness
                if (stmt.expr.kind != mlil::MlilExprKind::kInvalid) {
                     line += "return " + format_expr(stmt.expr) + "; /* warning: void return */";
                } else {
                     line += "return;";
                }
            } else {
                line += "return " + format_expr(stmt.expr) + ";";
            }
            if (!stmt.comment.empty()) {
                line += " // " + stmt.comment;
            }
            out_lines.push_back(std::move(line));
            break;
        }
        case StmtKind::kLabel: {
            std::string line = pad + "label_" + format_hex(stmt.address) + ":";
            if (!stmt.comment.empty()) {
                line += " // " + stmt.comment;
            }
            out_lines.push_back(std::move(line));
            break;
        }
        case StmtKind::kGoto: {
            std::string line = pad + "goto label_" + format_hex(stmt.address) + ";";
            if (!stmt.comment.empty()) {
                line += " // " + stmt.comment;
            }
            out_lines.push_back(std::move(line));
            break;
        }
        case StmtKind::kBreak: {
            out_lines.push_back(pad + "break;");
            break;
        }
        case StmtKind::kContinue: {
            out_lines.push_back(pad + "continue;");
            break;
        }
        case StmtKind::kIf: {
            bool then_empty = stmt.then_body.empty();
            bool else_empty = stmt.else_body.empty();
            
            // Try to simplify empty blocks (last resort if HLIL opt missed it)
            if (then_empty && !else_empty) {
                 // Invert
                 std::string cond = format_condition(stmt.condition);
                 // Simple string inversion - fragile but works for display
                 if (cond.size() >= 2 && cond[0] == '!' && cond[1] == '(') {
                      // !!(x) -> x
                      cond = cond.substr(2, cond.size() - 3);
                 } else if (cond.size() >= 1 && cond[0] == '!') {
                      cond = cond.substr(1);
                 } else {
                      cond = "!(" + cond + ")";
                 }
                 
                 std::string line = pad + "if (" + cond + ") {";
                 out_lines.push_back(std::move(line));
                 for (const auto& inner : stmt.else_body) {
                     emit_stmt_to_lines(inner, indent + 1, used, return_type, out_lines);
                 }
                 out_lines.push_back(pad + "}");
                 return;
            }

            std::string line = pad + "if (" + format_condition(stmt.condition) + ") {";
            out_lines.push_back(std::move(line));
            for (const auto& inner : stmt.then_body) {
                emit_stmt_to_lines(inner, indent + 1, used, return_type, out_lines);
            }
            if (!stmt.else_body.empty()) {
                out_lines.push_back(pad + "} else {");
                for (const auto& inner : stmt.else_body) {
                    emit_stmt_to_lines(inner, indent + 1, used, return_type, out_lines);
                }
            }
            out_lines.push_back(pad + "}");
            break;
        }
        case StmtKind::kWhile: {
            std::string line = pad + "while (" + format_condition(stmt.condition) + ") {";
            out_lines.push_back(std::move(line));
            for (const auto& inner : stmt.body) {
                emit_stmt_to_lines(inner, indent + 1, used, return_type, out_lines);
            }
            out_lines.push_back(pad + "}");
            break;
        }
        case StmtKind::kDoWhile: {
            std::string line = pad + "do {";
            out_lines.push_back(std::move(line));
            for (const auto& inner : stmt.body) {
                emit_stmt_to_lines(inner, indent + 1, used, return_type, out_lines);
            }
            out_lines.push_back(pad + "} while (" + format_condition(stmt.condition) + ");");
            break;
        }
        case StmtKind::kSwitch: {
            std::string line = pad + "switch (" + format_condition(stmt.condition) + ") {";
            out_lines.push_back(std::move(line));
            for (std::size_t c = 0; c < stmt.case_values.size(); ++c) {
                out_lines.push_back(pad + "    case " + format_hex(stmt.case_values[c]) + ":");
                if (c < stmt.case_bodies.size()) {
                    for (const auto& inner : stmt.case_bodies[c]) {
                        emit_stmt_to_lines(inner, indent + 2, used, return_type, out_lines);
                    }
                    // Check if last statement is return/break, if not add break
                    if (stmt.case_bodies[c].empty() ||
                        (stmt.case_bodies[c].back().kind != StmtKind::kReturn &&
                         stmt.case_bodies[c].back().kind != StmtKind::kBreak)) {
                        out_lines.push_back(std::string((indent + 2) * 4, ' ') + "break;");
                    }
                }
            }
            if (!stmt.default_body.empty()) {
                out_lines.push_back(pad + "    default:");
                for (const auto& inner : stmt.default_body) {
                    emit_stmt_to_lines(inner, indent + 2, used, return_type, out_lines);
                }
            }
            out_lines.push_back(pad + "}");
            break;
        }
        case StmtKind::kNop:
            // Filter out phi-related comments for cleaner output
            if (!stmt.comment.empty() &&
                stmt.comment.find("phi") == std::string::npos &&
                stmt.comment.find("split edge") == std::string::npos) {
                out_lines.push_back(pad + "// " + stmt.comment);
            }
            break;
    }
}

namespace {

bool is_candidate_index_name(const std::string& name) {
    if (name.size() < 2) {
        return false;
    }
    if (name[0] != 'v') {
        return false;
    }
    for (std::size_t i = 1; i < name.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(name[i]))) {
            return false;
        }
    }
    return true;
}

void collect_index_candidates_from_addr(const mlil::MlilExpr& expr,
                                        const std::unordered_set<std::string>& pointer_names,
                                        std::unordered_map<std::string, int>& counts) {
    if (expr.kind != mlil::MlilExprKind::kOp || expr.op != mlil::MlilOp::kAdd || expr.args.size() != 2) {
        return;
    }
    const auto& a = expr.args[0];
    const auto& b = expr.args[1];
    if (a.kind == mlil::MlilExprKind::kVar && pointer_names.find(a.var.name) != pointer_names.end()) {
        if (b.kind == mlil::MlilExprKind::kVar && is_candidate_index_name(b.var.name)) {
            counts[b.var.name]++;
        }
    }
    if (b.kind == mlil::MlilExprKind::kVar && pointer_names.find(b.var.name) != pointer_names.end()) {
        if (a.kind == mlil::MlilExprKind::kVar && is_candidate_index_name(a.var.name)) {
            counts[a.var.name]++;
        }
    }
}

void collect_index_candidates_from_expr(const mlil::MlilExpr& expr,
                                        const std::unordered_set<std::string>& pointer_names,
                                        const std::unordered_set<std::string>& size_names,
                                        std::unordered_map<std::string, int>& counts) {
    if (expr.kind == mlil::MlilExprKind::kOp && expr.args.size() == 2) {
        if ((expr.op == mlil::MlilOp::kLt || expr.op == mlil::MlilOp::kLe ||
             expr.op == mlil::MlilOp::kGt || expr.op == mlil::MlilOp::kGe)) {
            const auto& a = expr.args[0];
            const auto& b = expr.args[1];
            if (a.kind == mlil::MlilExprKind::kVar && is_candidate_index_name(a.var.name) &&
                (b.kind == mlil::MlilExprKind::kImm ||
                 (b.kind == mlil::MlilExprKind::kVar && size_names.find(b.var.name) != size_names.end()))) {
                counts[a.var.name]++;
            } else if (b.kind == mlil::MlilExprKind::kVar && is_candidate_index_name(b.var.name) &&
                       (a.kind == mlil::MlilExprKind::kImm ||
                        (a.kind == mlil::MlilExprKind::kVar && size_names.find(a.var.name) != size_names.end()))) {
                counts[b.var.name]++;
            }
        }
    }
    for (const auto& arg : expr.args) {
        collect_index_candidates_from_expr(arg, pointer_names, size_names, counts);
    }
}

void collect_index_candidates_from_stmt(const Stmt& stmt,
                                        const std::unordered_set<std::string>& pointer_names,
                                        const std::unordered_set<std::string>& size_names,
                                        std::unordered_map<std::string, int>& counts) {
    switch (stmt.kind) {
        case StmtKind::kStore:
            collect_index_candidates_from_addr(stmt.target, pointer_names, counts);
            collect_index_candidates_from_expr(stmt.expr, pointer_names, size_names, counts);
            break;
        case StmtKind::kAssign:
            collect_index_candidates_from_expr(stmt.expr, pointer_names, size_names, counts);
            break;
        case StmtKind::kCall:
            collect_index_candidates_from_expr(stmt.target, pointer_names, size_names, counts);
            for (const auto& arg : stmt.args) {
                collect_index_candidates_from_expr(arg, pointer_names, size_names, counts);
            }
            break;
        case StmtKind::kReturn:
            collect_index_candidates_from_expr(stmt.expr, pointer_names, size_names, counts);
            break;
        case StmtKind::kIf:
        case StmtKind::kWhile:
        case StmtKind::kDoWhile:
            collect_index_candidates_from_expr(stmt.condition, pointer_names, size_names, counts);
            for (const auto& inner : stmt.then_body) {
                collect_index_candidates_from_stmt(inner, pointer_names, size_names, counts);
            }
            for (const auto& inner : stmt.else_body) {
                collect_index_candidates_from_stmt(inner, pointer_names, size_names, counts);
            }
            for (const auto& inner : stmt.body) {
                collect_index_candidates_from_stmt(inner, pointer_names, size_names, counts);
            }
            break;
        case StmtKind::kFor:
            collect_index_candidates_from_expr(stmt.condition, pointer_names, size_names, counts);
            for (const auto& inner : stmt.then_body) {
                collect_index_candidates_from_stmt(inner, pointer_names, size_names, counts);
            }
            for (const auto& inner : stmt.else_body) {
                collect_index_candidates_from_stmt(inner, pointer_names, size_names, counts);
            }
            for (const auto& inner : stmt.body) {
                collect_index_candidates_from_stmt(inner, pointer_names, size_names, counts);
            }
            break;
        default:
            break;
    }
}

std::unordered_map<std::string, std::string> build_display_name_map(const Function& function) {
    std::unordered_map<std::string, std::string> remap;
    std::unordered_set<std::string> used_names;
    std::unordered_set<std::string> pointer_names;
    std::unordered_set<std::string> size_names;

    for (const auto& param : function.params) {
        used_names.insert(param.name);
        if (param.type.find('*') != std::string::npos) {
            pointer_names.insert(param.name);
        }
        if (param.name == "cap" || param.name == "len" || param.name == "size") {
            size_names.insert(param.name);
        }
    }
    for (const auto& local : function.locals) {
        used_names.insert(local.name);
        if (local.type.find('*') != std::string::npos) {
            pointer_names.insert(local.name);
        }
    }

    std::unordered_map<std::string, int> counts;
    for (const auto& stmt : function.stmts) {
        collect_index_candidates_from_stmt(stmt, pointer_names, size_names, counts);
    }

    std::vector<std::pair<std::string, int>> ordered;
    ordered.reserve(counts.size());
    for (const auto& entry : counts) {
        ordered.push_back(entry);
    }
    std::sort(ordered.begin(), ordered.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    const char* fallback_names[] = {"i", "j", "k", "n", "m", "t"};
    std::size_t fallback_idx = 0;
    for (const auto& entry : ordered) {
        const std::string& name = entry.first;
        if (!is_candidate_index_name(name)) {
            continue;
        }
        while (fallback_idx < std::size(fallback_names)) {
            const std::string candidate = fallback_names[fallback_idx++];
            if (used_names.find(candidate) == used_names.end()) {
                remap[name] = candidate;
                used_names.insert(candidate);
                break;
            }
        }
        if (fallback_idx >= std::size(fallback_names)) {
            break;
        }
    }
    return remap;
}

void collect_expr_uses(const mlil::MlilExpr& expr, std::unordered_set<std::string>& used) {
    if (expr.kind == mlil::MlilExprKind::kVar && !expr.var.name.empty()) {
        used.insert(expr.var.name);
    }
    for (const auto& arg : expr.args) {
        collect_expr_uses(arg, used);
    }
}

void collect_stmt_uses(const Stmt& stmt,
                       std::unordered_set<std::string>& used,
                       bool ignore_return_expr) {
    switch (stmt.kind) {
        case StmtKind::kAssign:
            collect_expr_uses(stmt.expr, used);
            break;
        case StmtKind::kStore:
            collect_expr_uses(stmt.target, used);
            collect_expr_uses(stmt.expr, used);
            break;
        case StmtKind::kCall:
            collect_expr_uses(stmt.target, used);
            for (const auto& arg : stmt.args) {
                collect_expr_uses(arg, used);
            }
            break;
        case StmtKind::kReturn:
            collect_expr_uses(stmt.expr, used);
            break;
        case StmtKind::kIf:
            collect_expr_uses(stmt.condition, used);
            for (const auto& inner : stmt.then_body) {
                collect_stmt_uses(inner, used, ignore_return_expr);
            }
            for (const auto& inner : stmt.else_body) {
                collect_stmt_uses(inner, used, ignore_return_expr);
            }
            break;
        case StmtKind::kWhile:
            collect_expr_uses(stmt.condition, used);
            for (const auto& inner : stmt.body) {
                collect_stmt_uses(inner, used, ignore_return_expr);
            }
            break;
        case StmtKind::kDoWhile:
            collect_expr_uses(stmt.condition, used);
            for (const auto& inner : stmt.body) {
                collect_stmt_uses(inner, used, ignore_return_expr);
            }
            break;
        case StmtKind::kFor:
            collect_expr_uses(stmt.condition, used);
            for (const auto& inner : stmt.then_body) {
                collect_stmt_uses(inner, used, ignore_return_expr);
            }
            for (const auto& inner : stmt.else_body) {
                collect_stmt_uses(inner, used, ignore_return_expr);
            }
            for (const auto& inner : stmt.body) {
                collect_stmt_uses(inner, used, ignore_return_expr);
            }
            break;
        case StmtKind::kSwitch:
            collect_expr_uses(stmt.condition, used);
            for (const auto& case_body : stmt.case_bodies) {
                for (const auto& inner : case_body) {
                    collect_stmt_uses(inner, used, ignore_return_expr);
                }
            }
            for (const auto& inner : stmt.default_body) {
                collect_stmt_uses(inner, used, ignore_return_expr);
            }
            break;
        default:
            break;
    }
}

} // namespace

void emit_function_pseudoc(const Function& function, std::vector<std::string>& out_lines) {
    out_lines.clear();
    std::unordered_map<std::string, std::string> name_remap = build_display_name_map(function);
    g_name_remap = &name_remap;
    std::string name = function.name;
    if (name.empty()) {
        std::ostringstream oss;
        oss << "sub_" << format_hex(function.entry);
        name = oss.str();
    }
    std::string ret_type = function.return_type.empty() ? "void" : function.return_type;
    const bool ignore_return_expr = (ret_type == "void");
    std::unordered_set<std::string> used;
    for (const auto& stmt : function.stmts) {
        collect_stmt_uses(stmt, used, ignore_return_expr);
    }
    std::ostringstream signature;
    signature << ret_type << " " << name << "(";
    for (std::size_t i = 0; i < function.params.size(); ++i) {
        if (i > 0) {
            signature << ", ";
        }
        signature << function.params[i].type << " " << display_name(function.params[i].name);
    }
    signature << ") {";
    out_lines.push_back(signature.str());
    // Collect initial constant assignments for local variables
    // We need to look for assignments BEFORE any control flow structures
    std::unordered_map<std::string, std::uint64_t> initial_values;
    
    // Use the initial_values from the function struct (collected during pseudoc construction)
    for (const auto& [var_name, init_val] : function.initial_values) {
        std::string norm_name = display_name(var_name);
        initial_values[norm_name] = init_val;
    }
    
    for (std::size_t idx = 0; idx < function.stmts.size(); ++idx) {
        const auto& stmt = function.stmts[idx];
        
        if (stmt.kind == StmtKind::kAssign && !stmt.var.name.empty()) {
            std::uint64_t imm = 0;
            if (get_imm_value(stmt.expr, imm)) {
                // Use display_name to normalize the variable name
                std::string norm_name = display_name(stmt.var.name);
                // Only record if we haven't seen this variable yet (first assignment)
                if (initial_values.find(norm_name) == initial_values.end()) {
                    initial_values[norm_name] = imm;
                }
            }
        }
        // Stop at first control structure to avoid false positives
        if (stmt.kind == StmtKind::kIf || stmt.kind == StmtKind::kWhile ||
            stmt.kind == StmtKind::kDoWhile || stmt.kind == StmtKind::kFor ||
            stmt.kind == StmtKind::kSwitch) {
            break;
        }
    }

    // Build a set of normalized used names
    std::unordered_set<std::string> used_normalized;
    for (const auto& name : used) {
        used_normalized.insert(display_name(name));
    }
    
    if (!function.locals.empty()) {
        std::vector<VarDecl> locals;
        locals.reserve(function.locals.size());
        for (const auto& local : function.locals) {
            std::string disp = display_name(local.name);
            if (used_normalized.find(disp) != used_normalized.end()) {
                locals.push_back(local);
            }
        }
        if (!locals.empty()) {
            for (const auto& local : locals) {
                std::string disp_name = display_name(local.name);
                std::string decl = "    " + local.type + " " + disp_name;
                auto init_it = initial_values.find(disp_name);
                if (init_it != initial_values.end()) {
                    decl += " = " + format_hex(init_it->second);
                }
                decl += ";";
                out_lines.push_back(decl);
            }
            out_lines.push_back("");
        }
    }
    for (const auto& stmt : function.stmts) {
        emit_stmt_to_lines(stmt, 1, used, ret_type, out_lines);
    }
    out_lines.push_back("}");
    g_name_remap = nullptr;
}

} // namespace engine::decompiler