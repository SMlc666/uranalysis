#include "engine/llir_ssa.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace engine::llir {

namespace {

using RegMap = std::unordered_map<std::string, int>;

constexpr const char* kFlagN = "flag_n";
constexpr const char* kFlagZ = "flag_z";
constexpr const char* kFlagC = "flag_c";
constexpr const char* kFlagV = "flag_v";

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

bool is_zero_reg(const std::string& name) {
    return name == "xzr";
}

RegRefKey make_key(const RegRef& reg) {
    RegRefKey key;
    key.name = canonical_reg_name(reg.name);
    key.version = reg.version;
    return key;
}

void record_defs(const std::vector<RegRef>& defs,
                 const LlilDefUseSite& site,
                 LlilSsaDefUse& out) {
    for (const auto& reg : defs) {
        if (reg.name.empty() || reg.version < 0) {
            continue;
        }
        RegRefKey key = make_key(reg);
        if (out.defs.find(key) == out.defs.end()) {
            out.defs.emplace(std::move(key), site);
        }
    }
}

void record_uses(const std::vector<RegRef>& uses,
                 const LlilDefUseSite& site,
                 LlilSsaDefUse& out) {
    std::unordered_set<RegRefKey, RegRefKeyHash, RegRefKeyEq> seen;
    for (const auto& reg : uses) {
        if (reg.name.empty() || reg.version < 0) {
            continue;
        }
        RegRefKey key = make_key(reg);
        if (!seen.insert(key).second) {
            continue;
        }
        out.uses[key].push_back(site);
    }
}

void collect_expr_uses(const LlilExpr& expr, std::vector<RegRef>& out) {
    if (expr.kind == LlilExprKind::kReg) {
        out.push_back(expr.reg);
    }
    for (const auto& arg : expr.args) {
        collect_expr_uses(arg, out);
    }
}

void rename_expr(LlilExpr& expr, const RegMap& current) {
    if (expr.kind == LlilExprKind::kReg) {
        expr.reg.name = canonical_reg_name(expr.reg.name);
        auto it = current.find(expr.reg.name);
        if (it != current.end()) {
            expr.reg.version = it->second;
        } else {
            expr.reg.version = 0;
        }
    }
    for (auto& arg : expr.args) {
        rename_expr(arg, current);
    }
}

bool maps_equal(const RegMap& a, const RegMap& b) {
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

std::size_t RegRefKeyHash::operator()(const RegRefKey& key) const {
    std::size_t h = std::hash<std::string>{}(key.name);
    h ^= static_cast<std::size_t>(std::hash<int>{}(key.version)) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

bool RegRefKeyEq::operator()(const RegRefKey& a, const RegRefKey& b) const {
    return a.version == b.version && a.name == b.name;
}

LlilDefUse compute_def_use(const LlilStmt& stmt) {
    LlilDefUse result;
    compute_def_use(stmt, result.uses, result.defs);
    return result;
}

void compute_def_use(const LlilStmt& stmt, std::vector<RegRef>& uses, std::vector<RegRef>& defs) {
    uses.clear();
    defs.clear();
    switch (stmt.kind) {
        case LlilStmtKind::kSetReg:
            defs.push_back(stmt.reg);
            collect_expr_uses(stmt.expr, uses);
            break;
        case LlilStmtKind::kStore:
            collect_expr_uses(stmt.target, uses);
            collect_expr_uses(stmt.expr, uses);
            break;
        case LlilStmtKind::kCall:
        case LlilStmtKind::kJump:
            collect_expr_uses(stmt.target, uses);
            for (const auto& arg : stmt.args) {
                collect_expr_uses(arg, uses);
            }
            if (stmt.kind == LlilStmtKind::kCall) {
                for (const auto& ret : stmt.returns) {
                    defs.push_back(ret);
                }
            }
            break;
        case LlilStmtKind::kCJump:
            collect_expr_uses(stmt.condition, uses);
            collect_expr_uses(stmt.target, uses);
            break;
        case LlilStmtKind::kPhi:
            defs.push_back(stmt.reg);
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

bool build_ssa_def_use(const Function& function, LlilSsaDefUse& out, std::string& error) {
    out.defs.clear();
    out.uses.clear();
    error.clear();

    for (std::size_t block_idx = 0; block_idx < function.blocks.size(); ++block_idx) {
        const auto& block = function.blocks[block_idx];
        for (std::size_t phi_idx = 0; phi_idx < block.phis.size(); ++phi_idx) {
            const auto& phi = block.phis[phi_idx];
            std::vector<RegRef> uses;
            std::vector<RegRef> defs;
            compute_def_use(phi, uses, defs);
            LlilDefUseSite site;
            site.block_index = block_idx;
            site.inst_index = std::numeric_limits<std::size_t>::max();
            site.stmt_index = phi_idx;
            site.is_phi = true;
            record_defs(defs, site, out);
            record_uses(uses, site, out);
        }
        for (std::size_t inst_idx = 0; inst_idx < block.instructions.size(); ++inst_idx) {
            const auto& inst = block.instructions[inst_idx];
            const auto& stmts = inst.llil_ssa.empty() ? inst.llil : inst.llil_ssa;
            for (std::size_t stmt_idx = 0; stmt_idx < stmts.size(); ++stmt_idx) {
                const auto& stmt = stmts[stmt_idx];
                std::vector<RegRef> uses;
                std::vector<RegRef> defs;
                compute_def_use(stmt, uses, defs);
                LlilDefUseSite site;
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
    std::vector<RegRef> empty;
    return build_ssa_with_call_clobbers(function, empty, error);
}

bool build_ssa_with_call_clobbers(Function& function,
                                  const std::vector<RegRef>& call_clobbers,
                                  std::string& error) {
    error.clear();
    if (function.blocks.empty()) {
        return true;
    }

    std::vector<RegRef> canonical_clobbers;
    std::unordered_set<std::string> clobber_names;
    std::unordered_map<std::string, std::size_t> clobber_index;
    auto add_clobber = [&](const std::string& name) {
        const std::string canonical = canonical_reg_name(name);
        if (canonical.empty() || is_zero_reg(canonical)) {
            return;
        }
        if (!clobber_names.insert(canonical).second) {
            return;
        }
        RegRef reg;
        reg.name = canonical;
        reg.version = -1;
        clobber_index[canonical] = canonical_clobbers.size();
        canonical_clobbers.push_back(std::move(reg));
    };
    for (const auto& reg : call_clobbers) {
        add_clobber(reg.name);
    }
    add_clobber(kFlagN);
    add_clobber(kFlagZ);
    add_clobber(kFlagC);
    add_clobber(kFlagV);

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
            const auto& stmts = insts[inst_idx].llil;
            def_ids[idx][inst_idx].resize(stmts.size(), 0);
            call_def_ids[idx][inst_idx].resize(stmts.size());
            for (std::size_t stmt_idx = 0; stmt_idx < stmts.size(); ++stmt_idx) {
                if (stmts[stmt_idx].kind == LlilStmtKind::kSetReg) {
                    def_ids[idx][inst_idx][stmt_idx] = allocate_id();
                } else if (stmts[stmt_idx].kind == LlilStmtKind::kCall) {
                    auto& clobber_ids = call_def_ids[idx][inst_idx][stmt_idx];
                    clobber_ids.resize(canonical_clobbers.size());
                    for (std::size_t i = 0; i < canonical_clobbers.size(); ++i) {
                        clobber_ids[i] = allocate_id();
                    }
                }
            }
        }
    }

    std::vector<RegMap> in_versions(function.blocks.size());
    std::vector<RegMap> out_versions(function.blocks.size());
    std::vector<std::unordered_map<std::string, PhiInfo>> phi_infos(function.blocks.size());

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::size_t idx = 0; idx < function.blocks.size(); ++idx) {
            RegMap in;
            if (!preds[idx].empty()) {
                std::unordered_set<std::string> regs;
                for (std::size_t pred : preds[idx]) {
                    for (const auto& [reg, version] : out_versions[pred]) {
                        regs.insert(reg);
                    }
                }
                for (const auto& reg : regs) {
                    if (is_zero_reg(reg)) {
                        continue;
                    }
                    std::vector<std::pair<std::size_t, int>> versions;
                    versions.reserve(preds[idx].size());
                    for (std::size_t pred : preds[idx]) {
                        auto it = out_versions[pred].find(reg);
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
                        in[reg] = unique;
                    } else {
                        PhiInfo& phi = phi_infos[idx][reg];
                        if (phi.version == 0) {
                            phi.version = allocate_id();
                        }
                        phi.incomings = versions;
                        in[reg] = phi.version;
                    }
                }
            } else {
                in = in_versions[idx];
            }

            if (!maps_equal(in, in_versions[idx])) {
                in_versions[idx] = in;
                changed = true;
            }

            RegMap current = in;
            for (std::size_t inst_idx = 0; inst_idx < function.blocks[idx].instructions.size(); ++inst_idx) {
                const auto& inst = function.blocks[idx].instructions[inst_idx];
                for (std::size_t stmt_idx = 0; stmt_idx < inst.llil.size(); ++stmt_idx) {
                    if (inst.llil[stmt_idx].kind == LlilStmtKind::kSetReg) {
                        const int id = def_ids[idx][inst_idx][stmt_idx];
                        const std::string canonical = canonical_reg_name(inst.llil[stmt_idx].reg.name);
                        if (!canonical.empty() && !is_zero_reg(canonical)) {
                            current[canonical] = id;
                        }
                    } else if (inst.llil[stmt_idx].kind == LlilStmtKind::kCall) {
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
        for (const auto& [reg, phi] : phi_infos[idx]) {
            LlilStmt stmt;
            stmt.kind = LlilStmtKind::kPhi;
            stmt.reg.name = reg;
            stmt.reg.version = phi.version;
            stmt.expr.kind = LlilExprKind::kOp;
            stmt.expr.op = LlilOp::kSelect;
            stmt.expr.size = 0;
            std::ostringstream oss;
            bool first = true;
            for (const auto& incoming : phi.incomings) {
                LlilExpr arg;
                arg.kind = LlilExprKind::kReg;
                arg.reg.name = reg;
                arg.reg.version = incoming.second;
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
        RegMap current = in_versions[idx];
        for (const auto& phi : function.blocks[idx].phis) {
            current[phi.reg.name] = phi.reg.version;
        }
        for (std::size_t inst_idx = 0; inst_idx < function.blocks[idx].instructions.size(); ++inst_idx) {
            auto& inst = function.blocks[idx].instructions[inst_idx];
            inst.llil_ssa.clear();
            inst.llil_ssa.reserve(inst.llil.size());
            for (std::size_t stmt_idx = 0; stmt_idx < inst.llil.size(); ++stmt_idx) {
                const auto& stmt = inst.llil[stmt_idx];
                LlilStmt ssa = stmt;
                rename_expr(ssa.expr, current);
                rename_expr(ssa.target, current);
                rename_expr(ssa.condition, current);
                for (auto& arg : ssa.args) {
                    rename_expr(arg, current);
                }
                if (ssa.kind == LlilStmtKind::kSetReg) {
                    int version = def_ids[idx][inst_idx][stmt_idx];
                    ssa.reg.name = canonical_reg_name(ssa.reg.name);
                    if (!ssa.reg.name.empty() && !is_zero_reg(ssa.reg.name)) {
                        ssa.reg.version = version;
                        current[ssa.reg.name] = version;
                    } else {
                        ssa.reg.version = -1;
                    }
                }
                if (ssa.kind == LlilStmtKind::kCall && !ssa.returns.empty()) {
                    std::unordered_set<std::string> ret_names;
                    const auto& clobber_ids = call_def_ids[idx][inst_idx][stmt_idx];
                    for (auto& ret : ssa.returns) {
                        const std::string canonical = canonical_reg_name(ret.name);
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
                inst.llil_ssa.push_back(std::move(ssa));
                if (stmt.kind == LlilStmtKind::kCall) {
                    std::unordered_set<std::string> ret_names;
                    for (const auto& ret : stmt.returns) {
                        const std::string canonical = canonical_reg_name(ret.name);
                        if (!canonical.empty()) {
                            ret_names.insert(canonical);
                        }
                    }
                    const auto& clobber_ids = call_def_ids[idx][inst_idx][stmt_idx];
                    for (std::size_t i = 0; i < canonical_clobbers.size() && i < clobber_ids.size(); ++i) {
                        if (ret_names.find(canonical_clobbers[i].name) != ret_names.end()) {
                            continue;
                        }
                        LlilStmt clobber;
                        clobber.kind = LlilStmtKind::kSetReg;
                        clobber.reg.name = canonical_clobbers[i].name;
                        clobber.reg.version = clobber_ids[i];
                        clobber.comment = "call clobber";
                        inst.llil_ssa.push_back(std::move(clobber));
                        current[canonical_clobbers[i].name] = clobber_ids[i];
                    }
                }
            }
        }
    }

    return true;
}

}  // namespace engine::llir
