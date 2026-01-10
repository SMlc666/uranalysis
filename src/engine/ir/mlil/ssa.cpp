#include "engine/mlil_ssa.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace engine::mlil {

namespace {

using VarMap = std::unordered_map<std::string, int>;

bool is_all_digits(const std::string& text, std::size_t start) {
    if (start >= text.size()) {
        return false;
    }
    for (std::size_t i = start; i < text.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(text[i]))) {
            return false;
        }
    }
    return true;
}

std::string canonical_reg_name(const std::string& name) {
    if (name == "wsp" || name == "sp") {
        return "sp";
    }
    if (name == "wzr" || name == "xzr") {
        return "xzr";
    }
    if (name == "fp") {
        return "x29";
    }
    if (name == "lr") {
        return "x30";
    }
    if (!name.empty()) {
        const char prefix = name[0];
        if ((prefix == 'w' || prefix == 'x') && is_all_digits(name, 1)) {
            return std::string("x").append(name.substr(1));
        }
        if ((prefix == 'v' || prefix == 'q' || prefix == 'd' || prefix == 's' || prefix == 'h' ||
             prefix == 'b') &&
            is_all_digits(name, 1)) {
            return std::string("v").append(name.substr(1));
        }
    }
    return name;
}

std::string canonical_var_name(const std::string& name) {
    constexpr const char* kRegPrefix = "reg.";
    if (name.rfind(kRegPrefix, 0) == 0) {
        std::string reg = name.substr(4);
        reg = canonical_reg_name(reg);
        return std::string(kRegPrefix).append(reg);
    }
    return name;
}

bool is_zero_var(const std::string& name) {
    return canonical_var_name(name) == "reg.xzr";
}

VarRefKey make_key(const VarRef& var) {
    VarRefKey key;
    key.name = canonical_var_name(var.name);
    key.version = var.version;
    return key;
}

void record_defs(const std::vector<VarRef>& defs,
                 const MlilDefUseSite& site,
                 MlilSsaDefUse& out) {
    for (const auto& var : defs) {
        if (var.name.empty() || var.version < 0) {
            continue;
        }
        VarRefKey key = make_key(var);
        if (out.defs.find(key) == out.defs.end()) {
            out.defs.emplace(std::move(key), site);
        }
    }
}

void record_uses(const std::vector<VarRef>& uses,
                 const MlilDefUseSite& site,
                 MlilSsaDefUse& out) {
    std::unordered_set<VarRefKey, VarRefKeyHash, VarRefKeyEq> seen;
    for (const auto& var : uses) {
        if (var.name.empty() || var.version < 0) {
            continue;
        }
        VarRefKey key = make_key(var);
        if (!seen.insert(key).second) {
            continue;
        }
        out.uses[key].push_back(site);
    }
}

void collect_expr_uses(const MlilExpr& expr, std::vector<VarRef>& out) {
    if (expr.kind == MlilExprKind::kVar) {
        out.push_back(expr.var);
    }
    for (const auto& arg : expr.args) {
        collect_expr_uses(arg, out);
    }
}

void rename_expr(MlilExpr& expr, const VarMap& current) {
    if (expr.kind == MlilExprKind::kVar) {
        expr.var.name = canonical_var_name(expr.var.name);
        auto it = current.find(expr.var.name);
        if (it != current.end()) {
            expr.var.version = it->second;
        } else {
            expr.var.version = 0;
        }
    }
    for (auto& arg : expr.args) {
        rename_expr(arg, current);
    }
}

bool maps_equal(const VarMap& a, const VarMap& b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (const auto& [key, value] : a) {
        auto it = b.find(key);
        if (it == b.end()) {
            return false;
        }
        if (it->second != value) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::size_t VarRefKeyHash::operator()(const VarRefKey& key) const {
    std::size_t h = std::hash<std::string>{}(key.name);
    h ^= static_cast<std::size_t>(std::hash<int>{}(key.version)) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

bool VarRefKeyEq::operator()(const VarRefKey& a, const VarRefKey& b) const {
    return a.version == b.version && a.name == b.name;
}

MlilDefUse compute_def_use(const MlilStmt& stmt) {
    MlilDefUse result;
    compute_def_use(stmt, result.uses, result.defs);
    return result;
}

void compute_def_use(const MlilStmt& stmt, std::vector<VarRef>& uses, std::vector<VarRef>& defs) {
    uses.clear();
    defs.clear();
    switch (stmt.kind) {
        case MlilStmtKind::kAssign:
            defs.push_back(stmt.var);
            collect_expr_uses(stmt.expr, uses);
            break;
        case MlilStmtKind::kStore:
            collect_expr_uses(stmt.target, uses);
            collect_expr_uses(stmt.expr, uses);
            break;
        case MlilStmtKind::kCall:
        case MlilStmtKind::kJump:
            collect_expr_uses(stmt.target, uses);
            for (const auto& arg : stmt.args) {
                collect_expr_uses(arg, uses);
            }
            if (stmt.kind == MlilStmtKind::kCall) {
                for (const auto& ret : stmt.returns) {
                    defs.push_back(ret);
                }
            }
            break;
        case MlilStmtKind::kCJump:
            collect_expr_uses(stmt.condition, uses);
            collect_expr_uses(stmt.target, uses);
            break;
        case MlilStmtKind::kPhi:
            defs.push_back(stmt.var);
            for (const auto& arg : stmt.expr.args) {
                collect_expr_uses(arg, uses);
            }
            break;
        default:
            collect_expr_uses(stmt.expr, uses);
            collect_expr_uses(stmt.target, uses);
            collect_expr_uses(stmt.condition, uses);
            break;
    }
}

bool build_ssa_def_use(const Function& function, MlilSsaDefUse& out, std::string& error) {
    out.defs.clear();
    out.uses.clear();
    error.clear();

    for (std::size_t block_idx = 0; block_idx < function.blocks.size(); ++block_idx) {
        const auto& block = function.blocks[block_idx];
        for (std::size_t phi_idx = 0; phi_idx < block.phis.size(); ++phi_idx) {
            const auto& phi = block.phis[phi_idx];
            std::vector<VarRef> uses;
            std::vector<VarRef> defs;
            compute_def_use(phi, uses, defs);
            MlilDefUseSite site;
            site.block_index = block_idx;
            site.inst_index = std::numeric_limits<std::size_t>::max();
            site.stmt_index = phi_idx;
            site.is_phi = true;
            record_defs(defs, site, out);
            record_uses(uses, site, out);
        }
        for (std::size_t inst_idx = 0; inst_idx < block.instructions.size(); ++inst_idx) {
            const auto& inst = block.instructions[inst_idx];
            for (std::size_t stmt_idx = 0; stmt_idx < inst.stmts.size(); ++stmt_idx) {
                const auto& stmt = inst.stmts[stmt_idx];
                std::vector<VarRef> uses;
                std::vector<VarRef> defs;
                compute_def_use(stmt, uses, defs);
                MlilDefUseSite site;
                site.block_index = block_idx;
                site.inst_index = inst_idx;
                site.stmt_index = stmt_idx;
                site.is_phi = false;
                record_defs(defs, site, out);
                record_uses(uses, site, out);
            }
        }
    }

    return true;
}

bool build_ssa(Function& function, std::string& error) {
    std::vector<VarRef> empty;
    return build_ssa_with_call_clobbers(function, empty, error);
}

bool build_ssa_with_call_clobbers(Function& function,
                                  const std::vector<VarRef>& call_clobbers,
                                  std::string& error) {
    error.clear();
    if (function.blocks.empty()) {
        return true;
    }

    std::vector<VarRef> canonical_clobbers;
    std::unordered_set<std::string> clobber_names;
    std::unordered_map<std::string, std::size_t> clobber_index;
    auto add_clobber = [&](const std::string& name) {
        const std::string canonical = canonical_var_name(name);
        if (canonical.empty() || is_zero_var(canonical)) {
            return;
        }
        if (!clobber_names.insert(canonical).second) {
            return;
        }
        VarRef var;
        var.name = canonical;
        var.version = -1;
        clobber_index[canonical] = canonical_clobbers.size();
        canonical_clobbers.push_back(std::move(var));
    };
    for (const auto& var : call_clobbers) {
        add_clobber(var.name);
    }

    std::unordered_map<std::uint64_t, std::size_t> block_index;
    block_index.reserve(function.blocks.size());
    for (std::size_t i = 0; i < function.blocks.size(); ++i) {
        block_index[function.blocks[i].start] = i;
    }

    std::vector<std::vector<std::size_t>> preds(function.blocks.size());
    for (std::size_t i = 0; i < function.blocks.size(); ++i) {
        for (std::uint64_t pred_addr : function.blocks[i].predecessors) {
            auto it = block_index.find(pred_addr);
            if (it != block_index.end()) {
                preds[i].push_back(it->second);
            }
        }
    }

    struct PhiInfo {
        int version = 0;
        std::vector<std::pair<std::size_t, int>> incomings;
    };

    int next_id = 1;
    auto allocate_id = [&]() -> int {
        return next_id++;
    };

    std::vector<std::vector<std::vector<int>>> def_ids(function.blocks.size());
    std::vector<std::vector<std::vector<std::vector<int>>>> call_def_ids(function.blocks.size());
    for (std::size_t idx = 0; idx < function.blocks.size(); ++idx) {
        auto& insts = function.blocks[idx].instructions;
        def_ids[idx].resize(insts.size());
        call_def_ids[idx].resize(insts.size());
        for (std::size_t inst_idx = 0; inst_idx < insts.size(); ++inst_idx) {
            const auto& stmts = insts[inst_idx].stmts;
            def_ids[idx][inst_idx].resize(stmts.size(), 0);
            call_def_ids[idx][inst_idx].resize(stmts.size());
            for (std::size_t stmt_idx = 0; stmt_idx < stmts.size(); ++stmt_idx) {
                if (stmts[stmt_idx].kind == MlilStmtKind::kAssign) {
                    const std::string canonical = canonical_var_name(stmts[stmt_idx].var.name);
                    if (!canonical.empty() && !is_zero_var(canonical)) {
                        def_ids[idx][inst_idx][stmt_idx] = allocate_id();
                    }
                } else if (stmts[stmt_idx].kind == MlilStmtKind::kCall) {
                    auto& clobber_ids = call_def_ids[idx][inst_idx][stmt_idx];
                    clobber_ids.resize(canonical_clobbers.size());
                    for (std::size_t i = 0; i < canonical_clobbers.size(); ++i) {
                        clobber_ids[i] = allocate_id();
                    }
                }
            }
        }
    }

    std::vector<VarMap> in_versions(function.blocks.size());
    std::vector<VarMap> out_versions(function.blocks.size());
    std::vector<std::unordered_map<std::string, PhiInfo>> phi_infos(function.blocks.size());

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::size_t idx = 0; idx < function.blocks.size(); ++idx) {
            VarMap in;
            if (!preds[idx].empty()) {
                std::unordered_set<std::string> vars;
                for (std::size_t pred : preds[idx]) {
                    for (const auto& [var, version] : out_versions[pred]) {
                        vars.insert(var);
                    }
                }
                for (const auto& var : vars) {
                    if (is_zero_var(var)) {
                        continue;
                    }
                    std::vector<std::pair<std::size_t, int>> versions;
                    versions.reserve(preds[idx].size());
                    for (std::size_t pred : preds[idx]) {
                        auto it = out_versions[pred].find(var);
                        int version = (it != out_versions[pred].end()) ? it->second : 0;
                        versions.push_back({pred, version});
                    }
                    int unique = versions.front().second;
                    bool all_same = true;
                    for (const auto& entry : versions) {
                        if (entry.second != unique) {
                            all_same = false;
                            break;
                        }
                    }
                    if (all_same) {
                        in[var] = unique;
                    } else {
                        PhiInfo& phi = phi_infos[idx][var];
                        if (phi.version == 0) {
                            phi.version = allocate_id();
                        }
                        phi.incomings = versions;
                        in[var] = phi.version;
                    }
                }
            } else {
                in = in_versions[idx];
            }

            if (!maps_equal(in, in_versions[idx])) {
                in_versions[idx] = in;
                changed = true;
            }

            VarMap current = in;
            for (std::size_t inst_idx = 0; inst_idx < function.blocks[idx].instructions.size(); ++inst_idx) {
                const auto& inst = function.blocks[idx].instructions[inst_idx];
                for (std::size_t stmt_idx = 0; stmt_idx < inst.stmts.size(); ++stmt_idx) {
                    if (inst.stmts[stmt_idx].kind == MlilStmtKind::kAssign) {
                        const int id = def_ids[idx][inst_idx][stmt_idx];
                        const std::string canonical = canonical_var_name(inst.stmts[stmt_idx].var.name);
                        if (!canonical.empty() && !is_zero_var(canonical) && id != 0) {
                            current[canonical] = id;
                        }
                    } else if (inst.stmts[stmt_idx].kind == MlilStmtKind::kCall) {
                        const auto& clobber_ids = call_def_ids[idx][inst_idx][stmt_idx];
                        for (std::size_t i = 0; i < canonical_clobbers.size() && i < clobber_ids.size(); ++i) {
                            current[canonical_clobbers[i].name] = clobber_ids[i];
                        }
                    }
                }
            }
            if (!maps_equal(current, out_versions[idx])) {
                out_versions[idx] = current;
                changed = true;
            }
        }
    }

    for (std::size_t idx = 0; idx < function.blocks.size(); ++idx) {
        auto& block = function.blocks[idx];
        block.phis.clear();
        for (const auto& [var, phi] : phi_infos[idx]) {
            MlilStmt stmt;
            stmt.kind = MlilStmtKind::kPhi;
            stmt.var.name = var;
            stmt.var.version = phi.version;
            stmt.expr.kind = MlilExprKind::kOp;
            stmt.expr.op = MlilOp::kSelect;
            stmt.expr.size = 0;
            std::ostringstream oss;
            bool first = true;
            for (const auto& incoming : phi.incomings) {
                MlilExpr arg;
                arg.kind = MlilExprKind::kVar;
                arg.var.name = var;
                arg.var.version = incoming.second;
                stmt.expr.args.push_back(std::move(arg));
                if (incoming.first < function.blocks.size()) {
                    if (!first) {
                        oss << ", ";
                    }
                    oss << "0x" << std::hex << function.blocks[incoming.first].start;
                    first = false;
                }
            }
            stmt.comment = oss.str();
            block.phis.push_back(std::move(stmt));
        }
    }

    for (std::size_t idx = 0; idx < function.blocks.size(); ++idx) {
        VarMap current = in_versions[idx];
        for (const auto& phi : function.blocks[idx].phis) {
            current[phi.var.name] = phi.var.version;
        }
        for (std::size_t inst_idx = 0; inst_idx < function.blocks[idx].instructions.size(); ++inst_idx) {
            auto& inst = function.blocks[idx].instructions[inst_idx];
            std::vector<MlilStmt> rewritten;
            rewritten.reserve(inst.stmts.size());
            for (std::size_t stmt_idx = 0; stmt_idx < inst.stmts.size(); ++stmt_idx) {
                const auto& stmt = inst.stmts[stmt_idx];
                MlilStmt ssa = stmt;
                rename_expr(ssa.expr, current);
                rename_expr(ssa.target, current);
                rename_expr(ssa.condition, current);
                for (auto& arg : ssa.args) {
                    rename_expr(arg, current);
                }
                if (ssa.kind == MlilStmtKind::kAssign) {
                    const int version = def_ids[idx][inst_idx][stmt_idx];
                    ssa.var.name = canonical_var_name(ssa.var.name);
                    if (!ssa.var.name.empty() && !is_zero_var(ssa.var.name) && version != 0) {
                        ssa.var.version = version;
                        current[ssa.var.name] = version;
                    } else {
                        ssa.var.version = -1;
                    }
                }
                if (ssa.kind == MlilStmtKind::kCall && !ssa.returns.empty()) {
                    std::unordered_set<std::string> ret_names;
                    const auto& clobber_ids = call_def_ids[idx][inst_idx][stmt_idx];
                    for (auto& ret : ssa.returns) {
                        const std::string canonical = canonical_var_name(ret.name);
                        ret.name = canonical;
                        auto it = clobber_index.find(canonical);
                        if (it != clobber_index.end() && it->second < clobber_ids.size()) {
                            ret.version = clobber_ids[it->second];
                            if (!canonical.empty()) {
                                current[canonical] = ret.version;
                                ret_names.insert(canonical);
                            }
                        }
                    }
                }
                rewritten.push_back(std::move(ssa));
                if (stmt.kind == MlilStmtKind::kCall && !canonical_clobbers.empty()) {
                    std::unordered_set<std::string> ret_names;
                    for (const auto& ret : stmt.returns) {
                        const std::string canonical = canonical_var_name(ret.name);
                        if (!canonical.empty()) {
                            ret_names.insert(canonical);
                        }
                    }
                    const auto& clobber_ids = call_def_ids[idx][inst_idx][stmt_idx];
                    for (std::size_t i = 0; i < canonical_clobbers.size() && i < clobber_ids.size(); ++i) {
                        if (ret_names.find(canonical_clobbers[i].name) != ret_names.end()) {
                            continue;
                        }
                        MlilStmt clobber;
                        clobber.kind = MlilStmtKind::kAssign;
                        clobber.var.name = canonical_clobbers[i].name;
                        clobber.var.version = clobber_ids[i];
                        clobber.comment = "call clobber";
                        rewritten.push_back(std::move(clobber));
                        current[canonical_clobbers[i].name] = clobber_ids[i];
                    }
                }
            }
            inst.stmts = std::move(rewritten);
        }
    }

    return true;
}

}  // namespace engine::mlil
