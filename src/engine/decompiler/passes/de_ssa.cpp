#include "engine/decompiler/passes/de_ssa.h"

#include <cctype>
#include <cstddef>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace engine::decompiler::passes {

namespace {

bool parse_hex_u64(std::string_view text, std::uint64_t& out) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
    }
    if (text.empty()) {
        return false;
    }
    std::uint64_t value = 0;
    for (char c : text) {
        int digit = -1;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            digit = 10 + (c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            digit = 10 + (c - 'A');
        } else if (std::isspace(static_cast<unsigned char>(c)) != 0) {
            break;
        } else {
            return false;
        }
        value = (value << 4) | static_cast<std::uint64_t>(digit);
    }
    out = value;
    return true;
}

std::string format_hex_u64(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

std::vector<std::uint64_t> parse_phi_pred_addrs(const mlil::MlilStmt& phi) {
    std::vector<std::uint64_t> out;
    std::string_view text = phi.comment;
    while (!text.empty()) {
        const std::size_t comma = text.find(',');
        std::string_view part = (comma == std::string_view::npos) ? text : text.substr(0, comma);
        std::uint64_t addr = 0;
        if (parse_hex_u64(part, addr)) {
            out.push_back(addr);
        }
        if (comma == std::string_view::npos) {
            break;
        }
        text.remove_prefix(comma + 1);
    }
    return out;
}

void update_phi_comments(mlil::BasicBlock& block, std::uint64_t old_pred, std::uint64_t new_pred) {
    for (auto& phi : block.phis) {
        if (phi.comment.empty()) {
            continue;
        }
        auto addrs = parse_phi_pred_addrs(phi);
        bool changed = false;
        for (auto& addr : addrs) {
            if (addr == old_pred) {
                addr = new_pred;
                changed = true;
            }
        }
        if (!changed) {
            continue;
        }
        std::ostringstream oss;
        for (std::size_t i = 0; i < addrs.size(); ++i) {
            if (i > 0) {
                oss << ", ";
            }
            oss << format_hex_u64(addrs[i]);
        }
        phi.comment = oss.str();
    }
}

bool is_terminator(mlil::MlilStmtKind kind) {
    return kind == mlil::MlilStmtKind::kJump || kind == mlil::MlilStmtKind::kCJump ||
           kind == mlil::MlilStmtKind::kRet;
}

bool find_terminator(const mlil::BasicBlock& block, std::size_t& inst_index, std::size_t& stmt_index) {
    for (std::size_t i = 0; i < block.instructions.size(); ++i) {
        const auto& inst = block.instructions[i];
        for (std::size_t j = 0; j < inst.stmts.size(); ++j) {
            if (is_terminator(inst.stmts[j].kind)) {
                inst_index = i;
                stmt_index = j;
                return true;
            }
        }
    }
    return false;
}

void insert_copies(mlil::BasicBlock& block, const std::vector<mlil::MlilStmt>& copies) {
    if (copies.empty()) {
        return;
    }
    if (block.instructions.empty()) {
        mlil::Instruction inst;
        inst.address = block.start;
        inst.stmts = copies;
        block.instructions.push_back(std::move(inst));
        return;
    }
    std::size_t inst_index = 0;
    std::size_t stmt_index = 0;
    if (find_terminator(block, inst_index, stmt_index)) {
        auto& stmts = block.instructions[inst_index].stmts;
        stmts.insert(stmts.begin() + static_cast<std::ptrdiff_t>(stmt_index), copies.begin(), copies.end());
    } else {
        auto& stmts = block.instructions.back().stmts;
        stmts.insert(stmts.end(), copies.begin(), copies.end());
    }
}

bool update_terminator_target(mlil::BasicBlock& block, std::uint64_t old_target, std::uint64_t new_target) {
    for (auto& inst : block.instructions) {
        for (auto& stmt : inst.stmts) {
            if (stmt.kind != mlil::MlilStmtKind::kJump && stmt.kind != mlil::MlilStmtKind::kCJump) {
                continue;
            }
            if (stmt.target.kind == mlil::MlilExprKind::kImm) {
                if (stmt.target.imm == old_target) {
                    stmt.target.imm = new_target;
                    return true;
                }
            } else {
                stmt.target.kind = mlil::MlilExprKind::kImm;
                stmt.target.imm = new_target;
                return true;
            }
        }
    }
    return false;
}

bool is_var_expr(const mlil::MlilExpr& expr) {
    return expr.kind == mlil::MlilExprKind::kVar;
}

std::string var_expr_name(const mlil::MlilExpr& expr) {
    if (expr.kind != mlil::MlilExprKind::kVar) {
        return "";
    }
    return expr.var.name;
}

std::vector<mlil::MlilStmt> order_phi_copies(std::vector<mlil::MlilStmt> copies, int& temp_counter) {
    std::vector<mlil::MlilStmt> ordered;
    std::unordered_set<std::string> dsts;
    dsts.reserve(copies.size());
    for (const auto& copy : copies) {
        if (!copy.var.name.empty()) {
            dsts.insert(copy.var.name);
        }
    }

    while (!copies.empty()) {
        bool progress = false;
        for (std::size_t i = 0; i < copies.size();) {
            const auto& copy = copies[i];
            const bool src_is_var = is_var_expr(copy.expr);
            const std::string src_name = var_expr_name(copy.expr);
            if (!src_is_var || dsts.find(src_name) == dsts.end()) {
                if (!(src_is_var && src_name == copy.var.name)) {
                    ordered.push_back(copy);
                }
                dsts.erase(copy.var.name);
                copies.erase(copies.begin() + static_cast<std::ptrdiff_t>(i));
                progress = true;
            } else {
                ++i;
            }
        }
        if (progress) {
            continue;
        }

        auto cycle = copies.front();
        if (cycle.expr.kind != mlil::MlilExprKind::kVar) {
            ordered.push_back(cycle);
            dsts.erase(cycle.var.name);
            copies.erase(copies.begin());
            continue;
        }

        mlil::VarRef tmp;
        tmp.name = "__phi_tmp" + std::to_string(temp_counter++);
        tmp.size = cycle.var.size;
        tmp.version = -1;

        mlil::MlilExpr tmp_expr;
        tmp_expr.kind = mlil::MlilExprKind::kVar;
        tmp_expr.size = tmp.size;
        tmp_expr.var = tmp;

        mlil::MlilStmt tmp_assign;
        tmp_assign.kind = mlil::MlilStmtKind::kAssign;
        tmp_assign.var = tmp;
        tmp_assign.expr = cycle.expr;
        tmp_assign.comment = "phi temp";
        ordered.push_back(std::move(tmp_assign));

        for (auto& copy : copies) {
            if (copy.expr.kind == mlil::MlilExprKind::kVar &&
                copy.expr.var.name == cycle.expr.var.name) {
                copy.expr = tmp_expr;
            }
        }
    }

    return ordered;
}

void rewrite_mlil_expr(mlil::MlilExpr& expr) {
    if (expr.kind == mlil::MlilExprKind::kVar) {
        expr.var.version = -1;
    }
    for (auto& arg : expr.args) {
        rewrite_mlil_expr(arg);
    }
}

void rewrite_mlil_stmt(mlil::MlilStmt& stmt) {
    stmt.var.version = -1;
    for (auto& ret : stmt.returns) {
        ret.version = -1;
    }
    rewrite_mlil_expr(stmt.expr);
    rewrite_mlil_expr(stmt.target);
    rewrite_mlil_expr(stmt.condition);
    for (auto& arg : stmt.args) {
        rewrite_mlil_expr(arg);
    }
}

}  // namespace

void split_critical_edges(mlil::Function& function) {
    if (function.blocks.empty()) {
        return;
    }
    std::unordered_map<std::uint64_t, std::size_t> block_index;
    block_index.reserve(function.blocks.size());
    std::uint64_t next_virtual = 1;
    for (std::size_t i = 0; i < function.blocks.size(); ++i) {
        block_index[function.blocks[i].start] = i;
        if (function.blocks[i].start >= next_virtual) {
            next_virtual = function.blocks[i].start + 1;
        }
    }

    struct Edge {
        std::uint64_t pred;
        std::uint64_t succ;
    };
    std::vector<Edge> to_split;
    for (const auto& block : function.blocks) {
        if (block.successors.size() < 2) {
            continue;
        }
        for (auto succ : block.successors) {
            auto it = block_index.find(succ);
            if (it == block_index.end()) {
                continue;
            }
            const auto& succ_block = function.blocks[it->second];
            if (succ_block.predecessors.size() > 1) {
                to_split.push_back({block.start, succ});
            }
        }
    }

    for (const auto& edge : to_split) {
        auto pred_it = block_index.find(edge.pred);
        auto succ_it = block_index.find(edge.succ);
        if (pred_it == block_index.end() || succ_it == block_index.end()) {
            continue;
        }
        auto& pred = function.blocks[pred_it->second];
        auto& succ = function.blocks[succ_it->second];

        mlil::BasicBlock split;
        split.start = next_virtual++;
        split.end = split.start;
        split.predecessors.push_back(pred.start);
        split.successors.push_back(succ.start);
        mlil::Instruction inst;
        inst.address = split.start;
        mlil::MlilStmt jump;
        jump.kind = mlil::MlilStmtKind::kJump;
        jump.target.kind = mlil::MlilExprKind::kImm;
        jump.target.imm = succ.start;
        jump.comment = "split edge";
        inst.stmts.push_back(std::move(jump));
        split.instructions.push_back(std::move(inst));

        for (auto& succ_addr : pred.successors) {
            if (succ_addr == succ.start) {
                succ_addr = split.start;
                break;
            }
        }
        update_terminator_target(pred, succ.start, split.start);

        for (auto& pred_addr : succ.predecessors) {
            if (pred_addr == pred.start) {
                pred_addr = split.start;
                break;
            }
        }
        update_phi_comments(succ, pred.start, split.start);

        function.blocks.push_back(std::move(split));
        block_index[function.blocks.back().start] = function.blocks.size() - 1;
    }
}

bool lower_mlil_ssa(mlil::Function& function, std::string& error) {
    error.clear();
    if (function.blocks.empty()) {
        return true;
    }
    std::unordered_map<std::uint64_t, std::size_t> block_index;
    block_index.reserve(function.blocks.size());
    for (std::size_t i = 0; i < function.blocks.size(); ++i) {
        block_index.emplace(function.blocks[i].start, i);
    }

    int temp_counter = 0;
    for (std::size_t idx = 0; idx < function.blocks.size(); ++idx) {
        auto& block = function.blocks[idx];
        if (block.phis.empty()) {
            continue;
        }
        std::unordered_map<std::size_t, std::vector<mlil::MlilStmt>> pending;
        for (const auto& phi : block.phis) {
            if (phi.kind != mlil::MlilStmtKind::kPhi) {
                continue;
            }
            std::vector<std::uint64_t> preds = parse_phi_pred_addrs(phi);
            if (preds.size() != phi.expr.args.size()) {
                preds = block.predecessors;
            }
            const std::size_t count = std::min(preds.size(), phi.expr.args.size());
            for (std::size_t i = 0; i < count; ++i) {
                const auto& incoming = phi.expr.args[i];
                auto it = block_index.find(preds[i]);
                if (it == block_index.end()) {
                    continue;
                }
                if (incoming.kind == mlil::MlilExprKind::kVar &&
                    incoming.var.name == phi.var.name) {
                    continue;
                }
                mlil::MlilStmt copy;
                copy.kind = mlil::MlilStmtKind::kAssign;
                copy.var = phi.var;
                copy.expr = incoming;
                copy.comment = "phi";
                pending[it->second].push_back(std::move(copy));
            }
        }
        for (auto& [pred_index, copies] : pending) {
            if (pred_index < function.blocks.size()) {
                auto ordered = order_phi_copies(std::move(copies), temp_counter);
                insert_copies(function.blocks[pred_index], ordered);
            }
        }
        block.phis.clear();
    }

    for (auto& block : function.blocks) {
        for (auto& inst : block.instructions) {
            for (auto& stmt : inst.stmts) {
                rewrite_mlil_stmt(stmt);
            }
        }
    }

    return true;
}

}  // namespace engine::decompiler::passes
