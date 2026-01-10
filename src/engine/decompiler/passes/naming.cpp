#include "engine/decompiler/passes/naming.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>

namespace engine::decompiler::passes {

namespace {

bool is_keyword(const std::string& name) {
    static const char* kKeywords[] = {
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
        "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int",
        "long", "register", "restrict", "return", "short", "signed", "sizeof", "static",
        "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while",
        "_Bool", "_Complex", "_Imaginary"};
    for (const char* keyword : kKeywords) {
        if (name == keyword) {
            return true;
        }
    }
    return false;
}

std::string sanitize_name(std::string name) {
    for (char& c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
            c = '_';
        }
    }
    if (name.empty()) {
        name = "var";
    }
    if (std::isdigit(static_cast<unsigned char>(name.front()))) {
        name.insert(name.begin(), 'v');
    }
    if (is_keyword(name)) {
        name.push_back('_');
    }
    return name;
}

std::string normalize_name(const std::string& raw,
                           const std::unordered_map<std::string, std::string>& renames) {
    if (raw.empty()) {
        return "";
    }
    auto it = renames.find(raw);
    std::string base = (it != renames.end()) ? it->second : raw;
    constexpr const char* kRegPrefix = "reg.";
    constexpr const char* kStackPrefix = "stack.";
    constexpr const char* kArgPrefix = "arg.";
    
    if (base.rfind(kRegPrefix, 0) == 0) {
        base = base.substr(4); // "reg.x0" -> "x0"
    } else if (base.rfind(kStackPrefix, 0) == 0) {
        // "stack.32" -> "v32" (more concise than stack_32)
        base = "v" + base.substr(6);
    } else if (base.rfind(kArgPrefix, 0) == 0) {
        base = "a" + base.substr(4);
    }
    return base;
}

bool is_special_implicit(const std::string& name) {
    return name == "sp";
}

bool group_has_reg(const std::vector<types::SsaVarKey>& members, const std::string& reg_name) {
    for (const auto& key : members) {
        if (key.name == reg_name) {
            return true;
        }
        if (reg_name.rfind("reg.", 0) == 0 && key.name == reg_name.substr(4)) {
            return true;
        }
        if (key.name.rfind("reg.", 0) == 0 && reg_name == key.name.substr(4)) {
            return true;
        }
    }
    return false;
}

struct ParamPick {
    std::size_t group = 0;
    int version = std::numeric_limits<int>::max();
    bool is_w = true;
    bool valid = false;
    types::Type merged_type = types::make_unknown();
};

bool reg_index_for_key(const types::SsaVarKey& key, int& index, bool& is_w) {
    static const std::unordered_map<std::string, int> kAarch64 = {
        {"reg.x0", 0}, {"reg.x1", 1}, {"reg.x2", 2}, {"reg.x3", 3},
        {"reg.x4", 4}, {"reg.x5", 5}, {"reg.x6", 6}, {"reg.x7", 7},
        {"reg.w0", 0}, {"reg.w1", 1}, {"reg.w2", 2}, {"reg.w3", 3},
        {"reg.w4", 4}, {"reg.w5", 5}, {"reg.w6", 6}, {"reg.w7", 7},
        {"x0", 0}, {"x1", 1}, {"x2", 2}, {"x3", 3},
        {"x4", 4}, {"x5", 5}, {"x6", 6}, {"x7", 7},
        {"w0", 0}, {"w1", 1}, {"w2", 2}, {"w3", 3},
        {"w4", 4}, {"w5", 5}, {"w6", 6}, {"w7", 7},
    };
    static const std::unordered_map<std::string, int> kSysV = {
        {"reg.rdi", 0}, {"reg.rsi", 1}, {"reg.rdx", 2}, {"reg.rcx", 3},
        {"reg.r8", 4}, {"reg.r9", 5},
        {"rdi", 0}, {"rsi", 1}, {"rdx", 2}, {"rcx", 3},
        {"r8", 4}, {"r9", 5},
    };
    static const std::unordered_map<std::string, int> kWin64 = {
        {"reg.rcx", 0}, {"reg.rdx", 1}, {"reg.r8", 2}, {"reg.r9", 3},
        {"rcx", 0}, {"rdx", 1}, {"r8", 2}, {"r9", 3},
    };

    auto it = kAarch64.find(key.name);
    if (it != kAarch64.end()) {
        index = it->second;
        is_w = (key.name.rfind("reg.w", 0) == 0) ||
               (key.name.size() >= 2 && key.name[0] == 'w' &&
                std::isdigit(static_cast<unsigned char>(key.name[1])));
        return true;
    }
    it = kSysV.find(key.name);
    if (it != kSysV.end()) {
        index = it->second;
        is_w = false;
        return true;
    }
    it = kWin64.find(key.name);
    if (it != kWin64.end()) {
        index = it->second;
        is_w = false;
        return true;
    }
    return false;
}

}  // namespace

NamingResult build_naming(const mlil::Function& function,
                          const hlil::Function& hlil_ssa,
                          const types::TypeSolver& solver,
                          const SsaGroups& groups,
                          const std::vector<ParamInfo>& params,
                          const std::vector<VarDecl>* param_hints) {
    NamingResult result;
    std::unordered_map<std::size_t, types::Type> group_types;
    for (const auto& [group, members] : groups.members) {
        types::Type merged = types::make_unknown();
        for (const auto& key : members) {
            merged = types::merge(merged, solver.get_type(key));
        }
        group_types[group] = merged;
    }

    std::unordered_set<int> abi_indices;
    abi_indices.reserve(params.size());
    for (const auto& param : params) {
        if (param.index >= 0) {
            abi_indices.insert(param.index);
        }
    }

    std::unordered_map<int, ParamPick> param_picks;
    for (const auto& [group, members] : groups.members) {
        for (const auto& key : members) {
            int index = -1;
            bool is_w = false;
            if (!reg_index_for_key(key, index, is_w)) {
                continue;
            }
            auto& pick = param_picks[index];
            pick.merged_type = types::merge(pick.merged_type, solver.get_type(key));
            if (!pick.valid || key.version < pick.version || (key.version == pick.version && pick.is_w && !is_w)) {
                pick.valid = true;
                pick.version = key.version;
                pick.is_w = is_w;
                pick.group = group;
            }
        }
    }

    std::unordered_map<std::size_t, int> group_param_index;
    std::unordered_map<int, types::Type> param_types;
    for (const auto& [index, pick] : param_picks) {
        if (!pick.valid) {
            continue;
        }
        // Only accept parameters that are in the ABI-validated list from collect_abi_params.
        // This enforces parameter continuity - if x0, x1 are detected but x2 is missing,
        // we should not accept x4-x7 as parameters even if they have version 0.
        if (!abi_indices.empty() && abi_indices.find(index) == abi_indices.end()) {
            continue;
        }
        group_param_index[pick.group] = index;
        param_types[index] = pick.merged_type;
    }

    std::unordered_set<std::string> param_names;
    for (const auto& [index, _] : param_types) {
        std::string name = "arg" + std::to_string(index);
        if (param_hints && index < static_cast<int>(param_hints->size())) {
            const auto& hinted = (*param_hints)[index].name;
            if (!hinted.empty()) {
                name = hinted;
            }
        }
        param_names.insert(name);
    }

    std::unordered_set<std::string> used_names;
    used_names.reserve(groups.members.size() + param_names.size());
    for (const auto& name : param_names) {
        used_names.insert(name);
    }

    std::unordered_map<int, VarDecl> ordered_params;

    for (const auto& [group, members] : groups.members) {
        std::string base;
        if (group_has_reg(members, "reg.sp") || group_has_reg(members, "reg.wsp")) {
            base = "sp";
        }
        auto param_it = group_param_index.find(group);
        if (param_it != group_param_index.end()) {
            base = "arg" + std::to_string(param_it->second);
            if (param_hints && param_it->second < static_cast<int>(param_hints->size())) {
                const auto& hinted = (*param_hints)[param_it->second].name;
                if (!hinted.empty()) {
                    base = hinted;
                }
            }
        } else {
            for (const auto& key : members) {
                if (key.name.rfind("stack.", 0) == 0) {
                    base = normalize_name(key.name, hlil_ssa.var_renames);
                    break;
                }
            }
            if (base.empty()) {
                for (const auto& key : members) {
                    if (key.name.rfind("arg.", 0) == 0) {
                        base = normalize_name(key.name, hlil_ssa.var_renames);
                        break;
                    }
                }
            }
            if (base.empty() && !members.empty()) {
                base = normalize_name(members.front().name, hlil_ssa.var_renames);
            }
        }

        base = sanitize_name(base);
        std::string name = base;
        if (param_it != group_param_index.end()) {
            name = base;
        } else {
            if (base.rfind("arg", 0) == 0 && param_names.find(base) != param_names.end()) {
                base = "t" + base.substr(3);
            }
            name = base;
            int suffix = 1;
            while (used_names.find(name) != used_names.end()) {
                ++suffix;
                name = base + "_" + std::to_string(suffix);
            }
        }
        used_names.insert(name);

        if (is_special_implicit(base)) {
            result.implicit_names.insert(name);
        }

        for (const auto& key : members) {
            result.names.emplace(key, name);
        }

        std::string type_name;
        if (param_it != group_param_index.end()) {
            if (param_hints && param_it->second < static_cast<int>(param_hints->size())) {
                const auto& hinted_type = (*param_hints)[param_it->second].type;
                if (!hinted_type.empty()) {
                    type_name = hinted_type;
                }
            }
            if (type_name.empty()) {
                auto type_it = param_types.find(param_it->second);
                if (type_it != param_types.end()) {
                    type_name = types::to_c_type(type_it->second);
                }
            }
        }
        if (type_name.empty()) {
            type_name = types::to_c_type(group_types[group]);
        }
        VarDecl decl{name, type_name};
        if (param_it != group_param_index.end()) {
            ordered_params[param_it->second] = decl;
        } else if (result.implicit_names.find(name) == result.implicit_names.end()) {
            result.locals.push_back(std::move(decl));
        }
    }

    if (!ordered_params.empty()) {
        std::vector<int> indices;
        indices.reserve(ordered_params.size());
        for (const auto& [index, _] : ordered_params) {
            indices.push_back(index);
        }
        std::sort(indices.begin(), indices.end());
        for (int index : indices) {
            result.params.push_back(ordered_params[index]);
        }
    }
    return result;
}

}  // namespace engine::decompiler::passes
