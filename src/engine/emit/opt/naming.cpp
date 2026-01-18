#include "engine/emit/opt/naming.h"

#include <algorithm>
#include <cctype>

namespace engine::emit::opt {

namespace {

bool is_version_suffix(const std::string& s, std::size_t pos, bool allow_plain_digits = false) {
    if (pos >= s.size()) return false;
    
    // Check for "v<digits>" pattern
    if (s[pos] == 'v' || s[pos] == 'V') {
        if (pos + 1 >= s.size()) return false;
        for (std::size_t i = pos + 1; i < s.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
                return false;
            }
        }
        return true;
    }
    
    // Check for plain "<digits>" pattern
    if (allow_plain_digits && std::isdigit(static_cast<unsigned char>(s[pos]))) {
        for (std::size_t i = pos; i < s.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
                return false;
            }
        }
        return true;
    }
    
    return false;
}

bool ends_with_ver_suffix(const std::string& s, std::size_t& suffix_start) {
    const std::string ver_marker = "_ver_";
    std::size_t pos = s.rfind(ver_marker);
    if (pos == std::string::npos || pos + ver_marker.size() >= s.size()) {
        return false;
    }
    for (std::size_t i = pos + ver_marker.size(); i < s.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
            return false;
        }
    }
    suffix_start = pos;
    return true;
}

}  // namespace

NamingContext::NamingContext(NamingOptions opts) : opts_(std::move(opts)) {}

std::string NamingContext::clean_ssa_suffix(const std::string& name) const {
    if (name.empty() || !opts_.clean_ssa_suffixes) {
        return name;
    }
    
    // Check for "_ver_<digits>" pattern
    std::size_t ver_pos = 0;
    if (ends_with_ver_suffix(name, ver_pos)) {
        return clean_ssa_suffix(name.substr(0, ver_pos));
    }
    
    // Check for "_v<digits>" or "_<digits>" pattern
    std::size_t last_underscore = name.rfind('_');
    if (last_underscore != std::string::npos && last_underscore + 1 < name.size()) {
        if (is_version_suffix(name, last_underscore + 1, false)) {
            return clean_ssa_suffix(name.substr(0, last_underscore));
        }
        if (is_version_suffix(name, last_underscore + 1, true)) {
            return clean_ssa_suffix(name.substr(0, last_underscore));
        }
    }
    
    return name;
}

void NamingContext::init_from_function(const decompiler::Function& func) {
    // Collect parameter and local names
    for (const auto& param : func.params) {
        used_names_.insert(param.name);
        if (param.type.find('*') != std::string::npos) {
            pointer_names_.insert(param.name);
        }
    }
    
    for (const auto& local : func.locals) {
        used_names_.insert(local.name);
        if (local.type.find('*') != std::string::npos) {
            pointer_names_.insert(local.name);
        }
    }
    
    assign_short_names();
}

void NamingContext::hint_index_var(const std::string& name) {
    index_candidates_.insert(name);
}

void NamingContext::hint_pointer_var(const std::string& name) {
    pointer_names_.insert(name);
}

void NamingContext::assign_short_names() {
    if (!opts_.use_short_index_names) {
        return;
    }
    
    // Sort index candidates by frequency (would need usage count, simplified here)
    std::vector<std::string> candidates(index_candidates_.begin(), index_candidates_.end());
    
    std::size_t short_idx = 0;
    for (const auto& candidate : candidates) {
        while (short_idx < short_names_.size()) {
            const std::string& short_name = short_names_[short_idx++];
            if (used_names_.find(short_name) == used_names_.end()) {
                renames_[candidate] = short_name;
                used_names_.insert(short_name);
                break;
            }
        }
        if (short_idx >= short_names_.size()) {
            break;
        }
    }
}

std::string NamingContext::resolve(const std::string& name) const {
    if (name.empty()) {
        return name;
    }
    
    // Check explicit remap first
    auto it = renames_.find(name);
    if (it != renames_.end()) {
        return it->second;
    }
    
    // Clean SSA suffix
    std::string cleaned = clean_ssa_suffix(name);
    
    // Check if cleaned name has a remap
    if (cleaned != name) {
        it = renames_.find(cleaned);
        if (it != renames_.end()) {
            return it->second;
        }
    }
    
    // Normalize stack variable names
    if (opts_.normalize_stack_vars && cleaned.rfind("stack.", 0) == 0 && cleaned.size() > 6) {
        return "v" + cleaned.substr(6);
    }
    
    // Normalize arg slot names
    if (opts_.normalize_arg_slots && cleaned.rfind("arg.", 0) == 0 && cleaned.size() > 4) {
        return "a" + cleaned.substr(4);
    }
    
    return cleaned;
}

std::string NamingContext::resolve(const mlil::VarRef& var) const {
    return resolve(var.name);
}

namespace {

void collect_expr_uses(const mlil::MlilExpr& expr, std::unordered_set<std::string>& used) {
    if (expr.kind == mlil::MlilExprKind::kVar && !expr.var.name.empty()) {
        used.insert(expr.var.name);
    }
    for (const auto& arg : expr.args) {
        collect_expr_uses(arg, used);
    }
}

void collect_stmt_uses(const decompiler::Stmt& stmt, std::unordered_set<std::string>& used) {
    switch (stmt.kind) {
        case decompiler::StmtKind::kAssign:
            collect_expr_uses(stmt.expr, used);
            break;
        case decompiler::StmtKind::kStore:
            collect_expr_uses(stmt.target, used);
            collect_expr_uses(stmt.expr, used);
            break;
        case decompiler::StmtKind::kCall:
            collect_expr_uses(stmt.target, used);
            for (const auto& arg : stmt.args) {
                collect_expr_uses(arg, used);
            }
            break;
        case decompiler::StmtKind::kReturn:
            collect_expr_uses(stmt.expr, used);
            break;
        case decompiler::StmtKind::kIf:
            collect_expr_uses(stmt.condition, used);
            for (const auto& inner : stmt.then_body) {
                collect_stmt_uses(inner, used);
            }
            for (const auto& inner : stmt.else_body) {
                collect_stmt_uses(inner, used);
            }
            break;
        case decompiler::StmtKind::kWhile:
        case decompiler::StmtKind::kDoWhile:
            collect_expr_uses(stmt.condition, used);
            for (const auto& inner : stmt.body) {
                collect_stmt_uses(inner, used);
            }
            break;
        case decompiler::StmtKind::kFor:
            collect_expr_uses(stmt.condition, used);
            for (const auto& inner : stmt.then_body) {
                collect_stmt_uses(inner, used);
            }
            for (const auto& inner : stmt.else_body) {
                collect_stmt_uses(inner, used);
            }
            for (const auto& inner : stmt.body) {
                collect_stmt_uses(inner, used);
            }
            break;
        case decompiler::StmtKind::kSwitch:
            collect_expr_uses(stmt.condition, used);
            for (const auto& case_body : stmt.case_bodies) {
                for (const auto& inner : case_body) {
                    collect_stmt_uses(inner, used);
                }
            }
            for (const auto& inner : stmt.default_body) {
                collect_stmt_uses(inner, used);
            }
            break;
        default:
            break;
    }
}

}  // namespace

std::unordered_set<std::string> collect_used_vars(const decompiler::Function& func) {
    std::unordered_set<std::string> used;
    for (const auto& stmt : func.stmts) {
        collect_stmt_uses(stmt, used);
    }
    return used;
}

NamingContext build_naming_context(const decompiler::Function& func, NamingOptions opts) {
    NamingContext ctx(opts);
    ctx.init_from_function(func);
    return ctx;
}

}  // namespace engine::emit::opt
