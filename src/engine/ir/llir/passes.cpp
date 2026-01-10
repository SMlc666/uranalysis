#include "engine/llir_passes.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace engine::llir {

namespace {

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
    }
    return name;
}

bool is_stack_base(const std::string& name, std::string& out_base) {
    const std::string canonical = canonical_reg_name(name);
    if (canonical == "sp") {
        out_base = "stack";
        return true;
    }
    if (canonical == "x29") {
        out_base = "frame";
        return true;
    }
    if (canonical == "rsp" || canonical == "esp") {
        out_base = "stack";
        return true;
    }
    if (canonical == "rbp" || canonical == "ebp") {
        out_base = "frame";
        return true;
    }
    return false;
}

bool extract_stack_addr(const LlilExpr& expr, std::string& base, std::int64_t& offset) {
    if (expr.kind == LlilExprKind::kReg) {
        if (is_stack_base(expr.reg.name, base)) {
            offset = 0;
            return true;
        }
        return false;
    }
    if (expr.kind != LlilExprKind::kOp || expr.args.size() != 2) {
        return false;
    }
    const LlilExpr& lhs = expr.args[0];
    const LlilExpr& rhs = expr.args[1];
    if (expr.op == LlilOp::kAdd || expr.op == LlilOp::kSub) {
        const LlilExpr* reg_expr = nullptr;
        const LlilExpr* imm_expr = nullptr;
        if (lhs.kind == LlilExprKind::kReg && rhs.kind == LlilExprKind::kImm) {
            reg_expr = &lhs;
            imm_expr = &rhs;
        } else if (rhs.kind == LlilExprKind::kReg && lhs.kind == LlilExprKind::kImm) {
            reg_expr = &rhs;
            imm_expr = &lhs;
        }
        if (!reg_expr || !imm_expr) {
            return false;
        }
        if (!is_stack_base(reg_expr->reg.name, base)) {
            return false;
        }
        const std::int64_t imm = static_cast<std::int64_t>(imm_expr->imm);
        if (expr.op == LlilOp::kSub && reg_expr == &lhs) {
            offset = -imm;
        } else {
            offset = imm;
        }
        return true;
    }
    return false;
}

std::string type_name_for_size(std::size_t size) {
    switch (size) {
        case 1: return "i8";
        case 2: return "i16";
        case 4: return "i32";
        case 8: return "i64";
        case 16: return "i128";
        default: return "";
    }
}

VarRef make_stack_var(const std::string& base, std::int64_t offset, std::size_t size) {
    VarRef var;
    std::ostringstream oss;
    if (base == "frame" && offset >= 16) {
        oss << "arg." << offset;
    } else {
        oss << base << "." << offset;
    }
    var.name = oss.str();
    var.size = size;
    var.type_name = type_name_for_size(size);
    return var;
}

bool rewrite_stack_load(LlilExpr& expr) {
    if (expr.kind == LlilExprKind::kLoad && !expr.args.empty()) {
        std::string base;
        std::int64_t offset = 0;
        if (extract_stack_addr(expr.args[0], base, offset)) {
            VarRef var = make_stack_var(base, offset, expr.size);
            LlilExpr rewritten;
            rewritten.kind = LlilExprKind::kVar;
            rewritten.size = expr.size;
            rewritten.var = std::move(var);
            expr = std::move(rewritten);
            return true;
        }
    }
    bool changed = false;
    for (auto& arg : expr.args) {
        changed |= rewrite_stack_load(arg);
    }
    return changed;
}

bool eval_const_expr(const LlilExpr& expr, std::uint64_t& out) {
    if (expr.kind == LlilExprKind::kImm) {
        out = expr.imm;
        return true;
    }
    if (expr.kind != LlilExprKind::kOp || expr.args.empty()) {
        return false;
    }
    if (expr.args.size() == 1) {
        std::uint64_t value = 0;
        if (!eval_const_expr(expr.args[0], value)) {
            return false;
        }
        switch (expr.op) {
            case LlilOp::kNot:
                out = ~value;
                return true;
            case LlilOp::kNeg:
                out = static_cast<std::uint64_t>(-static_cast<std::int64_t>(value));
                return true;
            default:
                return false;
        }
    }
    if (expr.args.size() != 2) {
        return false;
    }
    std::uint64_t lhs = 0;
    std::uint64_t rhs = 0;
    if (!eval_const_expr(expr.args[0], lhs) || !eval_const_expr(expr.args[1], rhs)) {
        return false;
    }
    switch (expr.op) {
        case LlilOp::kAdd:
            out = lhs + rhs;
            return true;
        case LlilOp::kSub:
            out = lhs - rhs;
            return true;
        case LlilOp::kMul:
            out = lhs * rhs;
            return true;
        case LlilOp::kDiv:
            if (rhs == 0) {
                return false;
            }
            out = lhs / rhs;
            return true;
        case LlilOp::kMod:
            if (rhs == 0) {
                return false;
            }
            out = lhs % rhs;
            return true;
        case LlilOp::kAnd:
            out = lhs & rhs;
            return true;
        case LlilOp::kOr:
            out = lhs | rhs;
            return true;
        case LlilOp::kXor:
            out = lhs ^ rhs;
            return true;
        case LlilOp::kShl:
            out = lhs << rhs;
            return true;
        case LlilOp::kShr:
            out = lhs >> rhs;
            return true;
        case LlilOp::kSar:
            out = static_cast<std::uint64_t>(static_cast<std::int64_t>(lhs) >> rhs);
            return true;
        case LlilOp::kRor: {
            if (rhs == 0) {
                out = lhs;
                return true;
            }
            const std::size_t bits = expr.size ? expr.size * 8 : 64;
            const std::size_t rot = bits ? (rhs % bits) : 0;
            if (rot == 0) {
                out = lhs;
                return true;
            }
            out = (lhs >> rot) | (lhs << (bits - rot));
            return true;
        }
        default:
            return false;
    }
}

}  // namespace

bool lift_stack_vars(Function& function, std::string& error) {
    error.clear();
    for (auto& block : function.blocks) {
        for (auto& phi : block.phis) {
            rewrite_stack_load(phi.expr);
        }
        for (auto& inst : block.instructions) {
            auto& stmts = inst.llil_ssa.empty() ? inst.llil : inst.llil_ssa;
            for (auto& stmt : stmts) {
                if (stmt.kind == LlilStmtKind::kStore) {
                    std::string base;
                    std::int64_t offset = 0;
                    if (extract_stack_addr(stmt.target, base, offset)) {
                        stmt.kind = LlilStmtKind::kSetVar;
                        stmt.var = make_stack_var(base, offset, stmt.expr.size);
                        stmt.target = {};
                    }
                }
                rewrite_stack_load(stmt.expr);
                rewrite_stack_load(stmt.target);
                rewrite_stack_load(stmt.condition);
                for (auto& arg : stmt.args) {
                    rewrite_stack_load(arg);
                }
            }
        }
    }
    return true;
}

bool resolve_indirect_branches(Function& function, std::string& error) {
    error.clear();
    bool changed = false;
    for (auto& block : function.blocks) {
        if (block.instructions.empty()) {
            continue;
        }
        auto& inst = block.instructions.back();
        auto& stmts = inst.llil_ssa.empty() ? inst.llil : inst.llil_ssa;
        for (auto it = stmts.rbegin(); it != stmts.rend(); ++it) {
            if (it->kind != LlilStmtKind::kJump && it->kind != LlilStmtKind::kCJump) {
                continue;
            }
            std::uint64_t target = 0;
            if (!eval_const_expr(it->target, target)) {
                break;
            }
            if (std::find(inst.targets.begin(), inst.targets.end(), target) == inst.targets.end()) {
                inst.targets.push_back(target);
                block.successors.push_back(target);
                changed = true;
            }
            break;
        }
    }

    if (!changed) {
        return true;
    }

    std::unordered_map<std::uint64_t, std::size_t> block_index;
    block_index.reserve(function.blocks.size());
    for (std::size_t i = 0; i < function.blocks.size(); ++i) {
        block_index[function.blocks[i].start] = i;
    }
    for (auto& block : function.blocks) {
        std::sort(block.successors.begin(), block.successors.end());
        block.successors.erase(std::unique(block.successors.begin(), block.successors.end()),
                               block.successors.end());
        block.predecessors.clear();
    }
    for (const auto& block : function.blocks) {
        for (std::uint64_t succ : block.successors) {
            auto it = block_index.find(succ);
            if (it == block_index.end()) {
                continue;
            }
            function.blocks[it->second].predecessors.push_back(block.start);
        }
    }
    for (auto& block : function.blocks) {
        std::sort(block.predecessors.begin(), block.predecessors.end());
        block.predecessors.erase(std::unique(block.predecessors.begin(), block.predecessors.end()),
                                 block.predecessors.end());
    }

    return true;
}

}  // namespace engine::llir
