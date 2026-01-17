#include "engine/llir_passes.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <limits>

namespace engine::llir {

namespace {

// Jump table analysis helpers

bool read_le(const std::vector<std::uint8_t>& data, std::size_t size, std::uint64_t& value) {
    if (size == 0 || size > 8 || size > data.size()) {
        return false;
    }
    value = 0;
    for (std::size_t i = 0; i < size; ++i) {
        value |= static_cast<std::uint64_t>(data[i]) << (i * 8);
    }
    return true;
}

std::uint64_t mask_for_size(std::size_t size) {
    if (size == 0 || size >= 8) {
        return ~static_cast<std::uint64_t>(0);
    }
    const std::size_t bits = size * 8;
    return (static_cast<std::uint64_t>(1) << bits) - 1;
}

std::string normalize_reg_name(const std::string& name) {
    if (name == "wsp") {
        return "sp";
    }
    if (!name.empty() && name[0] == 'w' && name.size() > 1 &&
        std::isdigit(static_cast<unsigned char>(name[1]))) {
        return std::string("x").append(name.substr(1));
    }
    return name;
}

using RegMap = std::unordered_map<std::string, std::uint64_t>;

bool is_zero_reg(const std::string& name) {
    return name == "xzr" || name == "wzr";
}

bool is_pc_reg(const std::string& name) {
    return name == "pc";
}

std::optional<std::uint64_t> read_reg(const RegMap& regs,
                                      const std::string& name,
                                      std::size_t size,
                                      std::uint64_t pc) {
    if (is_zero_reg(name)) {
        return 0;
    }
    if (is_pc_reg(name)) {
        return pc;
    }
    const std::string key = normalize_reg_name(name);
    auto it = regs.find(key);
    if (it == regs.end()) {
        return std::nullopt;
    }
    std::uint64_t value = it->second;
    const std::uint64_t mask = mask_for_size(size);
    return value & mask;
}

void write_reg(RegMap& regs,
               const std::string& name,
               std::size_t size,
               const std::optional<std::uint64_t>& value) {
    if (is_zero_reg(name) || is_pc_reg(name)) {
        return;
    }
    const std::string key = normalize_reg_name(name);
    if (!value) {
        regs.erase(key);
        return;
    }
    std::uint64_t masked = *value & mask_for_size(size);
    regs[key] = masked;
}

std::optional<std::uint64_t> eval_expr(const LlilExpr& expr,
                                       const RegMap& regs,
                                       const LoadedImage& image,
                                       std::uint64_t pc) {
    const std::size_t size = expr.size ? expr.size : 8;
    const std::uint64_t mask = mask_for_size(size);
    switch (expr.kind) {
        case LlilExprKind::kUnknown:
        case LlilExprKind::kUndef:
            return std::nullopt;
        case LlilExprKind::kImm:
            return expr.imm & mask;
        case LlilExprKind::kReg:
            return read_reg(regs, expr.reg.name, size, pc);
        case LlilExprKind::kLoad: {
            if (expr.args.empty()) {
                return std::nullopt;
            }
            auto addr = eval_expr(expr.args[0], regs, image, pc);
            if (!addr) {
                return std::nullopt;
            }
            std::vector<std::uint8_t> data;
            if (!image.read_bytes(*addr, size, data)) {
                return std::nullopt;
            }
            std::uint64_t value = 0;
            if (!read_le(data, size, value)) {
                return std::nullopt;
            }
            return value & mask;
        }
        case LlilExprKind::kOp: {
            if (expr.args.empty()) {
                return std::nullopt;
            }
            auto lhs = eval_expr(expr.args[0], regs, image, pc);
            if (!lhs) {
                return std::nullopt;
            }
            auto get_rhs = [&]() -> std::optional<std::uint64_t> {
                if (expr.args.size() < 2) {
                    return std::nullopt;
                }
                return eval_expr(expr.args[1], regs, image, pc);
            };
            switch (expr.op) {
                case LlilOp::kAdd: {
                    auto rhs = get_rhs();
                    if (!rhs) return std::nullopt;
                    return (*lhs + *rhs) & mask;
                }
                case LlilOp::kSub: {
                    auto rhs = get_rhs();
                    if (!rhs) return std::nullopt;
                    return (*lhs - *rhs) & mask;
                }
                case LlilOp::kAnd: {
                    auto rhs = get_rhs();
                    if (!rhs) return std::nullopt;
                    return (*lhs & *rhs) & mask;
                }
                case LlilOp::kOr: {
                    auto rhs = get_rhs();
                    if (!rhs) return std::nullopt;
                    return (*lhs | *rhs) & mask;
                }
                case LlilOp::kXor: {
                    auto rhs = get_rhs();
                    if (!rhs) return std::nullopt;
                    return (*lhs ^ *rhs) & mask;
                }
                case LlilOp::kShl: {
                    auto rhs = get_rhs();
                    if (!rhs) return std::nullopt;
                    return (*lhs << (*rhs & 0x3f)) & mask;
                }
                case LlilOp::kShr: {
                    auto rhs = get_rhs();
                    if (!rhs) return std::nullopt;
                    return (*lhs >> (*rhs & 0x3f)) & mask;
                }
                case LlilOp::kNot:
                    return (~(*lhs)) & mask;
                case LlilOp::kNeg:
                    return (~(*lhs) + 1) & mask;
                case LlilOp::kCast:
                    return *lhs & mask;
                default:
                    return std::nullopt;
            }
        }
        default:
            return std::nullopt;
    }
}

struct TableInfo {
    std::uint64_t base = 0;
    std::size_t entry_size = 8;
    bool relative = false;
    std::size_t max_entries = 0;
    std::string index_reg;
};

bool extract_index_limit(const LlilExpr& expr, std::size_t& max_entries) {
    const LlilExpr* cur = &expr;
    while (cur->kind == LlilExprKind::kOp && cur->op == LlilOp::kCast && !cur->args.empty()) {
        cur = &cur->args[0];
    }
    if (cur->kind != LlilExprKind::kOp || cur->op != LlilOp::kAnd || cur->args.size() < 2) {
        return false;
    }
    std::uint64_t mask_val = 0;
    if (cur->args[0].kind == LlilExprKind::kImm) {
        mask_val = cur->args[0].imm;
    } else if (cur->args[1].kind == LlilExprKind::kImm) {
        mask_val = cur->args[1].imm;
    } else {
        return false;
    }
    if (mask_val == 0 || mask_val + 1u == 0) {
        return false;
    }
    max_entries = static_cast<std::size_t>(mask_val + 1u);
    return true;
}

std::optional<std::string> extract_reg_name(const LlilExpr& expr) {
    const LlilExpr* cur = &expr;
    while (cur->kind == LlilExprKind::kOp && cur->op == LlilOp::kCast && !cur->args.empty()) {
        cur = &cur->args[0];
    }
    if (cur->kind == LlilExprKind::kReg) {
        return cur->reg.name;
    }
    if (cur->kind == LlilExprKind::kOp && cur->op == LlilOp::kAnd && cur->args.size() >= 2) {
        if (cur->args[0].kind == LlilExprKind::kImm) {
            return extract_reg_name(cur->args[1]);
        }
        if (cur->args[1].kind == LlilExprKind::kImm) {
            return extract_reg_name(cur->args[0]);
        }
    }
    return std::nullopt;
}

bool match_index_term(const LlilExpr& expr,
                      std::size_t& scale_out,
                      std::size_t& max_entries_out,
                      std::string& index_reg_out) {
    max_entries_out = 0;
    if (expr.kind != LlilExprKind::kOp || expr.args.size() < 2) {
        return false;
    }
    if (expr.op == LlilOp::kMul) {
        std::uint64_t imm = 0;
        const LlilExpr* index_expr = nullptr;
        if (expr.args[0].kind == LlilExprKind::kImm) {
            imm = expr.args[0].imm;
            index_expr = &expr.args[1];
        } else if (expr.args[1].kind == LlilExprKind::kImm) {
            imm = expr.args[1].imm;
            index_expr = &expr.args[0];
        } else {
            return false;
        }
        if (imm == 0) {
            return false;
        }
        scale_out = static_cast<std::size_t>(imm);
        if (index_expr) {
            extract_index_limit(*index_expr, max_entries_out);
            auto reg_name = extract_reg_name(*index_expr);
            if (reg_name) {
                index_reg_out = *reg_name;
            }
        }
        return true;
    }
    if (expr.op == LlilOp::kShl) {
        if (expr.args[1].kind != LlilExprKind::kImm) {
            return false;
        }
        const std::uint64_t shift = expr.args[1].imm;
        if (shift >= 8) {
            return false;
        }
        scale_out = static_cast<std::size_t>(1u << shift);
        extract_index_limit(expr.args[0], max_entries_out);
        auto reg_name = extract_reg_name(expr.args[0]);
        if (reg_name) {
            index_reg_out = *reg_name;
        }
        return true;
    }
    return false;
}

bool eval_constant(const LlilExpr& expr,
                   const RegMap& regs,
                   const LoadedImage& image,
                   std::uint64_t pc,
                   std::uint64_t& out) {
    auto value = eval_expr(expr, regs, image, pc);
    if (!value) {
        return false;
    }
    out = *value;
    return true;
}

bool extract_table_info(const LlilExpr& expr,
                        const RegMap& regs,
                        const LoadedImage& image,
                        std::uint64_t pc,
                        TableInfo& out) {
    if (expr.kind != LlilExprKind::kLoad || expr.args.empty()) {
        return false;
    }
    out.max_entries = 0;
    out.index_reg.clear();
    const LlilExpr& addr = expr.args[0];
    std::uint64_t base = 0;
    bool base_found = false;
    std::size_t scale = 0;
    if (addr.kind == LlilExprKind::kReg) {
        const std::string key = normalize_reg_name(addr.reg.name);
        auto it = regs.find(key);
        if (it != regs.end()) {
            base = it->second;
            base_found = true;
        }
    }
    if (addr.kind == LlilExprKind::kOp && addr.op == LlilOp::kAdd && addr.args.size() >= 2) {
        std::uint64_t const_value = 0;
        std::size_t max_entries = 0;
        if (eval_constant(addr.args[0], regs, image, pc, const_value)) {
            if (match_index_term(addr.args[1], scale, max_entries, out.index_reg)) {
                base = const_value;
                base_found = true;
                out.max_entries = max_entries;
            } else {
                base = const_value;
                scale = 0;
                base_found = true;
            }
        } else if (eval_constant(addr.args[1], regs, image, pc, const_value)) {
            if (match_index_term(addr.args[0], scale, max_entries, out.index_reg)) {
                base = const_value;
                base_found = true;
                out.max_entries = max_entries;
            } else {
                base = const_value;
                scale = 0;
                base_found = true;
            }
        } else {
            return false;
        }
    } else if (eval_constant(addr, regs, image, pc, base)) {
        scale = 0;
        base_found = true;
    } else {
        return false;
    }

    if (!base_found) {
        return false;
    }

    out.base = base;
    if (expr.size == 1 || expr.size == 2 || expr.size == 4 || expr.size == 8) {
        out.entry_size = expr.size;
    } else {
        out.entry_size = (scale == 1 || scale == 2 || scale == 4 || scale == 8) ? scale : 8;
    }
    out.relative = (out.entry_size == 4);
    return true;
}

bool is_executable_address(const std::vector<BinarySegment>& segments, std::uint64_t address) {
    constexpr std::uint32_t kElfPfExecute = 0x1;
    for (const auto& seg : segments) {
        if ((seg.flags & kElfPfExecute) == 0) {
            continue;
        }
        if (address >= seg.vaddr && address < (seg.vaddr + seg.memsz)) {
            return true;
        }
    }
    return false;
}

const BinarySegment* find_segment(const std::vector<BinarySegment>& segments, std::uint64_t address) {
    for (const auto& seg : segments) {
        if (address >= seg.vaddr && address < (seg.vaddr + seg.memsz)) {
            return &seg;
        }
    }
    return nullptr;
}

std::vector<std::uint64_t> read_table_targets(const TableInfo& info,
                                              const LoadedImage& image,
                                              const std::vector<BinarySegment>& segments) {
    std::vector<std::uint64_t> targets;
    if (info.base == 0 || info.entry_size == 0) {
        return targets;
    }
    constexpr std::size_t kMaxEntries = 256;
    constexpr std::size_t kMinHits = 3;
    constexpr std::size_t kMaxMisses = 8;
    const BinarySegment* base_seg = find_segment(segments, info.base);
    if (!base_seg) {
        return targets;
    }
    const bool base_exec = (base_seg->flags & 0x1) != 0;
    const std::size_t min_hits = base_exec ? 6 : kMinHits;
    const std::uint64_t seg_end = base_seg->vaddr + base_seg->memsz;
    std::size_t max_entries =
        std::min(kMaxEntries,
                 static_cast<std::size_t>((seg_end - info.base) / info.entry_size));
    if (info.max_entries > 0) {
        max_entries = std::min(max_entries, info.max_entries);
    }
    std::size_t misses = 0;
    for (std::size_t i = 0; i < max_entries; ++i) {
        const std::uint64_t addr = info.base + i * info.entry_size;
        std::vector<std::uint8_t> data;
        if (!image.read_bytes(addr, info.entry_size, data)) {
            break;
        }
        std::uint64_t value = 0;
        if (!read_le(data, info.entry_size, value)) {
            break;
        }
        std::uint64_t target = value;
        if (info.relative) {
            const std::int32_t disp = static_cast<std::int32_t>(value);
            target = info.base + static_cast<std::int64_t>(disp);
        }
        if (is_executable_address(segments, target)) {
            targets.push_back(target);
            misses = 0;
        } else {
            ++misses;
            if (misses >= kMaxMisses) {
                break;
            }
        }
    }
    if (targets.size() < min_hits) {
        targets.clear();
    }
    return targets;
}

std::size_t reg_size_from_name(const std::string& name) {
    if (name == "wsp") {
        return 4;
    }
    if (name == "sp") {
        return 8;
    }
    if (name.empty()) {
        return 8;
    }
    switch (name[0]) {
        case 'w':
        case 's':
            return 4;
        case 'x':
        case 'd':
            return 8;
        case 'q':
        case 'v':
            return 16;
        case 'h':
            return 2;
        case 'b':
            return 1;
        default:
            return 8;
    }
}

}  // namespace

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

bool resolve_jump_tables(Function& function,
                         const LoadedImage& image,
                         const std::vector<BinarySegment>& segments,
                         std::string& error) {
    error.clear();
    if (segments.empty()) {
        return true;  // No segment info available, skip
    }

    bool changed = false;

    for (auto& block : function.blocks) {
        if (block.instructions.empty()) {
            continue;
        }

        // Check if the last instruction is an indirect jump with no known targets
        auto& inst = block.instructions.back();
        if (inst.branch != BranchKind::kJump || !inst.targets.empty()) {
            continue;
        }

        // Simulate register state to find jump table base
        RegMap regs;
        for (const auto& prev_inst : block.instructions) {
            for (const auto& stmt : prev_inst.llil_ssa.empty() ? prev_inst.llil : prev_inst.llil_ssa) {
                if (stmt.kind == LlilStmtKind::kSetReg) {
                    const std::size_t reg_sz = reg_size_from_name(stmt.reg.name);
                    auto value = eval_expr(stmt.expr, regs, image, prev_inst.address);
                    write_reg(regs, stmt.reg.name, reg_sz, value);
                }
            }
        }

        // Look for jump table pattern in the last instruction's LLIL
        auto& stmts = inst.llil_ssa.empty() ? inst.llil : inst.llil_ssa;
        for (const auto& stmt : stmts) {
            if (stmt.kind != LlilStmtKind::kJump && stmt.kind != LlilStmtKind::kCJump) {
                continue;
            }

            TableInfo table;
            if (!extract_table_info(stmt.target, regs, image, inst.address, table)) {
                continue;
            }

            // Read targets from the jump table
            std::vector<std::uint64_t> targets = read_table_targets(table, image, segments);
            if (targets.empty()) {
                continue;
            }

            // Add all jump table targets to the instruction and block successors
            for (std::uint64_t target : targets) {
                if (std::find(inst.targets.begin(), inst.targets.end(), target) == inst.targets.end()) {
                    inst.targets.push_back(target);
                }
                if (std::find(block.successors.begin(), block.successors.end(), target) == block.successors.end()) {
                    block.successors.push_back(target);
                }
            }

            // Store jump table info in the instruction
            inst.jump_table_base = table.base;
            inst.jump_table_size = targets.size();
            inst.is_switch = true;

            changed = true;
            break;
        }
    }

    if (!changed) {
        return true;
    }

    // Rebuild predecessor lists
    std::unordered_map<std::uint64_t, std::size_t> block_index;
    block_index.reserve(function.blocks.size());
    for (std::size_t i = 0; i < function.blocks.size(); ++i) {
        block_index[function.blocks[i].start] = i;
    }
    for (auto& block : function.blocks) {
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
