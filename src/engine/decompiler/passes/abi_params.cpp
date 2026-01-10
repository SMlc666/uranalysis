#include "engine/decompiler/passes/abi_params.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace engine::decompiler::passes {

namespace {

using types::SsaVarKey;

SsaVarKey make_key(const mlil::VarRef& var) {
    SsaVarKey key;
    key.name = var.name;
    key.version = var.version;
    return key;
}

bool reg_param_index(const std::string& name, int& index) {
    static const std::unordered_map<std::string, int> kAarch64 = {
        {"reg.x0", 0}, {"reg.x1", 1}, {"reg.x2", 2}, {"reg.x3", 3},
        {"reg.x4", 4}, {"reg.x5", 5}, {"reg.x6", 6}, {"reg.x7", 7},
        {"reg.w0", 0}, {"reg.w1", 1}, {"reg.w2", 2}, {"reg.w3", 3},
        {"reg.w4", 4}, {"reg.w5", 5}, {"reg.w6", 6}, {"reg.w7", 7},
        {"x0", 0},     {"x1", 1},     {"x2", 2},     {"x3", 3},
        {"x4", 4},     {"x5", 5},     {"x6", 6},     {"x7", 7},
        {"w0", 0},     {"w1", 1},     {"w2", 2},     {"w3", 3},
        {"w4", 4},     {"w5", 5},     {"w6", 6},     {"w7", 7},
    };
    static const std::unordered_map<std::string, int> kSysV = {
        {"reg.rdi", 0}, {"reg.rsi", 1}, {"reg.rdx", 2}, {"reg.rcx", 3},
        {"reg.r8", 4},  {"reg.r9", 5},  {"rdi", 0},     {"rsi", 1},
        {"rdx", 2},     {"rcx", 3},     {"r8", 4},      {"r9", 5},
    };
    static const std::unordered_map<std::string, int> kWin64 = {
        {"reg.rcx", 0},
        {"reg.rdx", 1},
        {"reg.r8", 2},
        {"reg.r9", 3},
        {"rcx", 0},
        {"rdx", 1},
        {"r8", 2},
        {"r9", 3},
    };

    auto it = kAarch64.find(name);
    if (it != kAarch64.end()) {
        index = it->second;
        return true;
    }
    it = kSysV.find(name);
    if (it != kSysV.end()) {
        index = it->second;
        return true;
    }
    it = kWin64.find(name);
    if (it != kWin64.end()) {
        index = it->second;
        return true;
    }
    return false;
}

void collect_uses_expr(const mlil::MlilExpr& expr,
                       std::unordered_map<SsaVarKey, bool, types::SsaVarKeyHash, types::SsaVarKeyEq>& uses) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        if (!expr.var.name.empty() && expr.var.version >= 0) {
            uses[make_key(expr.var)] = true;
        }
    }
    for (const auto& arg : expr.args) {
        collect_uses_expr(arg, uses);
    }
}

void collect_uses_stmt(const mlil::MlilStmt& stmt,
                       std::unordered_map<SsaVarKey, bool, types::SsaVarKeyHash, types::SsaVarKeyEq>& uses) {
    collect_uses_expr(stmt.expr, uses);
    collect_uses_expr(stmt.target, uses);
    collect_uses_expr(stmt.condition, uses);
    for (const auto& arg : stmt.args) {
        collect_uses_expr(arg, uses);
    }
}

std::string strip_reg_prefix(const std::string& name) {
    if (name.rfind("reg.", 0) == 0) {
        return name.substr(4);
    }
    return name;
}

bool reg_float_index(const std::string& name, int& index) {
    std::string base = strip_reg_prefix(name);
    if (base.size() < 2) {
        return false;
    }
    char prefix = base[0];
    if (prefix != 'v' && prefix != 's' && prefix != 'd' && prefix != 'q') {
        if (base.rfind("xmm", 0) == 0 && base.size() > 3) {
            base = base.substr(3);
            prefix = 'v';
        } else {
            return false;
        }
    }
    std::size_t start = (prefix == 'v' || prefix == 's' || prefix == 'd' || prefix == 'q') ? 1 : 0;
    if (start >= base.size()) {
        return false;
    }
    for (std::size_t i = start; i < base.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(base[i]))) {
            return false;
        }
    }
    index = std::stoi(base.substr(start));
    return true;
}

bool reg_arg_index(const std::string& name, int& index, bool& is_float) {
    if (reg_param_index(name, index)) {
        is_float = false;
        return true;
    }
    if (reg_float_index(name, index)) {
        is_float = true;
        return true;
    }
    return false;
}

std::string canonicalize_var_name(std::string name) {
    static constexpr const char* kRegPrefix = "reg.";
    if (name.rfind(kRegPrefix, 0) == 0) {
        std::string reg = name.substr(4);
        if (!reg.empty()) {
            const char prefix = reg[0];
            if ((prefix == 'w' || prefix == 'x') && reg.size() > 1) {
                bool digits = true;
                for (std::size_t i = 1; i < reg.size(); ++i) {
                    if (!std::isdigit(static_cast<unsigned char>(reg[i]))) {
                        digits = false;
                        break;
                    }
                }
                if (digits) {
                    reg = std::string("x").append(reg.substr(1));
                }
            } else if ((prefix == 'v' || prefix == 'q' || prefix == 'd' || prefix == 's' ||
                        prefix == 'h' || prefix == 'b') &&
                       reg.size() > 1) {
                bool digits = true;
                for (std::size_t i = 1; i < reg.size(); ++i) {
                    if (!std::isdigit(static_cast<unsigned char>(reg[i]))) {
                        digits = false;
                        break;
                    }
                }
                if (digits) {
                    reg = std::string("v").append(reg.substr(1));
                }
            }
        }
        return std::string(kRegPrefix).append(reg);
    }
    return name;
}

void collect_non_call_uses_stmt(const mlil::MlilStmt& stmt,
                                std::unordered_map<SsaVarKey, bool, types::SsaVarKeyHash, types::SsaVarKeyEq>& uses) {
    collect_uses_expr(stmt.expr, uses);
    collect_uses_expr(stmt.target, uses);
    collect_uses_expr(stmt.condition, uses);
    if (stmt.kind != mlil::MlilStmtKind::kCall) {
        for (const auto& arg : stmt.args) {
            collect_uses_expr(arg, uses);
        }
    }
}

void collect_defs_stmt(const mlil::MlilStmt& stmt,
                       std::unordered_map<SsaVarKey, bool, types::SsaVarKeyHash, types::SsaVarKeyEq>& defs) {
    if (stmt.comment == "call clobber") {
        return;
    }
    auto record_def = [&](const mlil::VarRef& var) {
        if (!var.name.empty() && var.version >= 0) {
            defs[make_key(var)] = true;
        }
    };
    if (stmt.kind == mlil::MlilStmtKind::kAssign || stmt.kind == mlil::MlilStmtKind::kPhi) {
        record_def(stmt.var);
    }
    if (stmt.kind == mlil::MlilStmtKind::kCall) {
        for (const auto& ret : stmt.returns) {
            record_def(ret);
        }
    }
}

int resolve_alias_version(const std::string& name,
                          int version,
                          const std::unordered_map<SsaVarKey, int, types::SsaVarKeyHash, types::SsaVarKeyEq>& alias) {
    SsaVarKey key{canonicalize_var_name(name), version};
    int resolved = version;
    std::size_t guard = 0;
    while (guard++ < 8) {
        auto it = alias.find(key);
        if (it == alias.end()) {
            break;
        }
        if (it->second == resolved) {
            break;
        }
        resolved = it->second;
        key.version = resolved;
    }
    return resolved;
}

void rewrite_expr_alias(mlil::MlilExpr& expr,
                        const std::unordered_map<SsaVarKey, int, types::SsaVarKeyHash, types::SsaVarKeyEq>& alias) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        const std::string canonical = canonicalize_var_name(expr.var.name);
        const int resolved = resolve_alias_version(canonical, expr.var.version, alias);
        if (resolved != expr.var.version || canonical != expr.var.name) {
            expr.var.name = canonical;
            expr.var.version = resolved;
        }
    }
    for (auto& arg : expr.args) {
        rewrite_expr_alias(arg, alias);
    }
}

void recover_call_arg_sources(mlil::Function& function) {
    std::unordered_map<SsaVarKey, int, types::SsaVarKeyHash, types::SsaVarKeyEq> alias;
    for (auto& block : function.blocks) {
        alias.clear();
        std::unordered_map<std::string, int> last_call_args;
        bool pending_clobbers = false;
        for (auto& inst : block.instructions) {
            for (auto& stmt : inst.stmts) {
                if (stmt.kind == mlil::MlilStmtKind::kCall) {
                    for (auto& arg : stmt.args) {
                        rewrite_expr_alias(arg, alias);
                    }
                    last_call_args.clear();
                    for (const auto& arg : stmt.args) {
                        if (arg.kind != mlil::MlilExprKind::kVar) {
                            continue;
                        }
                        int idx = -1;
                        bool is_float = false;
                        if (!reg_arg_index(arg.var.name, idx, is_float)) {
                            continue;
                        }
                        const std::string canonical = canonicalize_var_name(arg.var.name);
                        last_call_args[canonical] = arg.var.version;
                    }
                    pending_clobbers = true;
                    continue;
                }
                if (stmt.kind == mlil::MlilStmtKind::kAssign && stmt.comment == "call clobber" && pending_clobbers) {
                    const std::string canonical = canonicalize_var_name(stmt.var.name);
                    auto it = last_call_args.find(canonical);
                    if (it != last_call_args.end()) {
                        SsaVarKey key{canonical, stmt.var.version};
                        alias[key] = it->second;
                    }
                    continue;
                }
                pending_clobbers = false;
                last_call_args.clear();
            }
        }
    }
}

}  // namespace

std::vector<ParamInfo> collect_abi_params(const mlil::Function& function) {
    std::unordered_map<SsaVarKey, bool, types::SsaVarKeyHash, types::SsaVarKeyEq> uses;
    for (const auto& block : function.blocks) {
        for (const auto& phi : block.phis) {
            collect_uses_stmt(phi, uses);
        }
        for (const auto& inst : block.instructions) {
            for (const auto& stmt : inst.stmts) {
                collect_uses_stmt(stmt, uses);
            }
        }
    }

    // Collect integer and float parameters separately for continuity checking.
    std::unordered_map<int, types::SsaVarKey> found_int_params;
    std::unordered_map<int, types::SsaVarKey> found_float_params;
    int max_int_index = -1;
    int max_float_index = -1;

    for (const auto& [key, _] : uses) {
        // A variable with version 0 is live at the function entry point, making it a parameter.
        if (key.version == 0) {
            int index = -1;
            bool is_float = false;
            if (reg_arg_index(key.name, index, is_float)) {
                if (is_float) {
                    if (found_float_params.find(index) == found_float_params.end()) {
                        found_float_params[index] = key;
                        max_float_index = std::max(max_float_index, index);
                    }
                } else {
                    if (found_int_params.find(index) == found_int_params.end()) {
                        found_int_params[index] = key;
                        max_int_index = std::max(max_int_index, index);
                    }
                }
            }
        }
    }

    // Enforce ABI continuity: Parameters must be contiguous from index 0.
    // If there's a gap, only keep parameters before the gap.
    // For example: if x0 and x3 are detected but x1 is not, we only keep x0.
    int valid_int_max = -1;
    for (int i = 0; i <= max_int_index; ++i) {
        if (found_int_params.find(i) != found_int_params.end()) {
            valid_int_max = i;
        } else {
            // Found a gap - stop here, parameters beyond this are likely not real params.
            break;
        }
    }

    int valid_float_max = -1;
    for (int i = 0; i <= max_float_index; ++i) {
        if (found_float_params.find(i) != found_float_params.end()) {
            valid_float_max = i;
        } else {
            // Found a gap - stop here.
            break;
        }
    }

    std::vector<ParamInfo> params;
    params.reserve(static_cast<std::size_t>(valid_int_max + 1 + valid_float_max + 1));

    // Add valid integer parameters (0 to valid_int_max inclusive).
    for (int i = 0; i <= valid_int_max; ++i) {
        auto it = found_int_params.find(i);
        if (it != found_int_params.end()) {
            ParamInfo info;
            info.key = it->second;
            info.index = i;
            params.push_back(std::move(info));
        }
    }

    // Add valid float parameters (0 to valid_float_max inclusive).
    // Float params come after int params in the param list, with offset 8 to distinguish.
    for (int i = 0; i <= valid_float_max; ++i) {
        auto it = found_float_params.find(i);
        if (it != found_float_params.end()) {
            ParamInfo info;
            info.key = it->second;
            info.index = 8 + i;  // Offset float indices to avoid collision with int params.
            params.push_back(std::move(info));
        }
    }

    // Sort by index to ensure a consistent, predictable order.
    std::sort(params.begin(), params.end(),
              [](const ParamInfo& a, const ParamInfo& b) { return a.index < b.index; });

    return params;
}

std::string infer_return_type(const mlil::Function& function) {
    bool returns_int = false;
    bool returns_float = false;

    for (const auto& block : function.blocks) {
        if (block.instructions.empty()) {
            continue;
        }
        const auto& last_inst = block.instructions.back();
        for (const auto& stmt : last_inst.stmts) {
            if (stmt.kind == mlil::MlilStmtKind::kRet) {
                if (stmt.expr.kind == mlil::MlilExprKind::kVar) {
                    int index = -1;
                    bool is_float = false;
                    if (reg_arg_index(stmt.expr.var.name, index, is_float)) {
                        if (index == 0) {
                            if (is_float) {
                                returns_float = true;
                            } else {
                                returns_int = true;
                            }
                        }
                    }
                }
            }
        }
    }

    if (returns_int) {
        return "uint64_t";
    }
    if (returns_float) {
        return "double";
    }
    return "void";
}

void prune_call_args(mlil::Function& function) {
    recover_call_arg_sources(function);

    std::unordered_map<SsaVarKey, bool, types::SsaVarKeyHash, types::SsaVarKeyEq> non_call_uses;
    std::unordered_map<SsaVarKey, bool, types::SsaVarKeyHash, types::SsaVarKeyEq> defs;

    for (const auto& block : function.blocks) {
        for (const auto& phi : block.phis) {
            collect_non_call_uses_stmt(phi, non_call_uses);
            collect_defs_stmt(phi, defs);
        }
        for (const auto& inst : block.instructions) {
            for (const auto& stmt : inst.stmts) {
                collect_non_call_uses_stmt(stmt, non_call_uses);
                collect_defs_stmt(stmt, defs);
            }
        }
    }

    for (auto& block : function.blocks) {
        for (auto& inst : block.instructions) {
            for (auto& stmt : inst.stmts) {
                if (stmt.kind != mlil::MlilStmtKind::kCall || stmt.args.empty()) {
                    continue;
                }
                int max_int = -1;
                int max_float = -1;
                std::vector<bool> keep(stmt.args.size(), false);
                for (std::size_t i = 0; i < stmt.args.size(); ++i) {
                    const auto& arg = stmt.args[i];
                    if (arg.kind != mlil::MlilExprKind::kVar) {
                        keep[i] = true;
                        continue;
                    }
                    int index = -1;
                    bool is_float = false;
                    if (!reg_arg_index(arg.var.name, index, is_float)) {
                        keep[i] = true;
                        continue;
                    }
                    SsaVarKey key = make_key(arg.var);
                    const bool used_elsewhere = (non_call_uses.find(key) != non_call_uses.end());
                    const bool defined_here = (arg.var.version > 0 && defs.find(key) != defs.end());
                    const bool is_param_reg = (!is_float && arg.var.version == 0);
                    if (defined_here || used_elsewhere || is_param_reg) {
                        keep[i] = true;
                        if (is_float) {
                            max_float = std::max(max_float, index);
                        } else {
                            max_int = std::max(max_int, index);
                        }
                    }
                }

                if (max_int >= 0 || max_float >= 0) {
                    for (std::size_t i = 0; i < stmt.args.size(); ++i) {
                        if (keep[i]) {
                            continue;
                        }
                        const auto& arg = stmt.args[i];
                        if (arg.kind != mlil::MlilExprKind::kVar) {
                            continue;
                        }
                        int index = -1;
                        bool is_float = false;
                        if (!reg_arg_index(arg.var.name, index, is_float)) {
                            continue;
                        }
                        if ((!is_float && index <= max_int) || (is_float && index <= max_float)) {
                            keep[i] = true;
                        }
                    }
                }

                if (std::all_of(keep.begin(), keep.end(), [](bool v) { return v; })) {
                    continue;
                }
                std::vector<mlil::MlilExpr> filtered;
                filtered.reserve(stmt.args.size());
                for (std::size_t i = 0; i < stmt.args.size(); ++i) {
                    if (keep[i]) {
                        filtered.push_back(stmt.args[i]);
                    }
                }
                stmt.args = std::move(filtered);
            }
        }
    }
}

}  // namespace engine::decompiler::passes
