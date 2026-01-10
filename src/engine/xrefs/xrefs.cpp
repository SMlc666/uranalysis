#include "engine/xrefs.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "engine/llir.h"

namespace engine::xrefs {

namespace {

using LlilExpr = llir::LlilExpr;

constexpr std::uint32_t kRelocAarch64Abs64 = 257;
constexpr std::uint32_t kRelocAarch64GlobDat = 1025;
constexpr std::uint32_t kRelocAarch64JumpSlot = 1026;
constexpr std::uint32_t kRelocAarch64Relative = 1027;
constexpr std::uint32_t kRelocAarch64TlsDtpMod64 = 1029;
constexpr std::uint32_t kRelocAarch64TlsDtpRel64 = 1030;
constexpr std::uint32_t kRelocAarch64TlsTpRel64 = 1031;
constexpr std::uint32_t kRelocAarch64IRelative = 1032;
constexpr std::uint32_t kRelocPeHighLow = 3;
constexpr std::uint32_t kRelocPeDir64 = 10;
constexpr std::uint32_t kElfPtTls = 7;
constexpr const char* kFlagN = "flag_n";
constexpr const char* kFlagZ = "flag_z";
constexpr const char* kFlagC = "flag_c";
constexpr const char* kFlagV = "flag_v";

bool read_u64(const std::vector<std::uint8_t>& data, std::size_t offset, std::uint64_t& value) {
    if (offset + 8 > data.size()) {
        return false;
    }
    value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(data[offset + i]) << (i * 8);
    }
    return true;
}

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

bool is_zero_reg(const std::string& name) {
    return name == "xzr" || name == "wzr";
}

bool is_pc_reg(const std::string& name) {
    return name == "pc";
}

bool is_flag_reg_name(const std::string& name) {
    return name == kFlagN || name == kFlagZ || name == kFlagC || name == kFlagV;
}

using RegMap = std::unordered_map<std::string, std::uint64_t>;

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

std::optional<std::uint64_t> eval_expr(const llir::LlilExpr& expr,
                                       const RegMap& regs,
                                       const LoadedImage& image,
                                       std::uint64_t pc) {
    const std::size_t size = expr.size ? expr.size : 8;
    const std::uint64_t mask = mask_for_size(size);
    switch (expr.kind) {
        case llir::LlilExprKind::kUnknown:
        case llir::LlilExprKind::kUndef:
            return std::nullopt;
        case llir::LlilExprKind::kImm:
            return expr.imm & mask;
        case llir::LlilExprKind::kReg:
            return read_reg(regs, expr.reg.name, size, pc);
        case llir::LlilExprKind::kLoad: {
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
        case llir::LlilExprKind::kOp: {
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
                case llir::LlilOp::kAdd: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs + *rhs) & mask;
                }
                case llir::LlilOp::kSub: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs - *rhs) & mask;
                }
                case llir::LlilOp::kAnd: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs & *rhs) & mask;
                }
                case llir::LlilOp::kOr: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs | *rhs) & mask;
                }
                case llir::LlilOp::kXor: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs ^ *rhs) & mask;
                }
                case llir::LlilOp::kShl: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs << (*rhs & 0x3f)) & mask;
                }
                case llir::LlilOp::kShr: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs >> (*rhs & 0x3f)) & mask;
                }
                case llir::LlilOp::kDiv: {
                    auto rhs = get_rhs();
                    if (!rhs || *rhs == 0) {
                        return std::nullopt;
                    }
                    return (*lhs / *rhs) & mask;
                }
                case llir::LlilOp::kMod: {
                    auto rhs = get_rhs();
                    if (!rhs || *rhs == 0) {
                        return std::nullopt;
                    }
                    return (*lhs % *rhs) & mask;
                }
                case llir::LlilOp::kSar: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    const std::uint64_t shift = (*rhs & 0x3f);
                    std::int64_t signed_val = static_cast<std::int64_t>(*lhs);
                    std::int64_t shifted = signed_val >> shift;
                    return static_cast<std::uint64_t>(shifted) & mask;
                }
                case llir::LlilOp::kRor: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    const std::uint64_t shift = (*rhs & 0x3f);
                    if (shift == 0) {
                        return (*lhs) & mask;
                    }
                    const std::uint64_t width = (size == 0) ? 64 : (size * 8);
                    const std::uint64_t rot = shift % width;
                    const std::uint64_t low = (*lhs) >> rot;
                    const std::uint64_t high = (*lhs) << (width - rot);
                    return (low | high) & mask;
                }
                case llir::LlilOp::kNot:
                    return (~(*lhs)) & mask;
                case llir::LlilOp::kNeg:
                    return (~(*lhs) + 1) & mask;
                case llir::LlilOp::kAbs: {
                    std::int64_t signed_val = static_cast<std::int64_t>(*lhs);
                    if (signed_val < 0) {
                        signed_val = -signed_val;
                    }
                    return static_cast<std::uint64_t>(signed_val) & mask;
                }
                case llir::LlilOp::kMin: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs < *rhs ? *lhs : *rhs) & mask;
                }
                case llir::LlilOp::kMax: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs > *rhs ? *lhs : *rhs) & mask;
                }
                case llir::LlilOp::kBswap: {
                    if (size > 8) {
                        return std::nullopt;
                    }
                    std::uint64_t v = *lhs & mask;
                    std::uint64_t result = 0;
                    for (std::size_t i = 0; i < size; ++i) {
                        result = (result << 8) | (v & 0xff);
                        v >>= 8;
                    }
                    return result & mask;
                }
                case llir::LlilOp::kClz: {
                    std::uint64_t v = *lhs & mask;
                    std::uint64_t count = 0;
                    const std::size_t width = size * 8;
                    for (std::size_t i = 0; i < width; ++i) {
                        if ((v & (static_cast<std::uint64_t>(1) << (width - 1 - i))) != 0) {
                            break;
                        }
                        ++count;
                    }
                    return count & mask;
                }
                case llir::LlilOp::kRbit: {
                    std::uint64_t v = *lhs & mask;
                    std::uint64_t result = 0;
                    const std::size_t width = size * 8;
                    for (std::size_t i = 0; i < width; ++i) {
                        if (v & (static_cast<std::uint64_t>(1) << i)) {
                            result |= static_cast<std::uint64_t>(1) << (width - 1 - i);
                        }
                    }
                    return result & mask;
                }
                case llir::LlilOp::kSqrt:
                    return std::nullopt;
                case llir::LlilOp::kCast:
                    return *lhs & mask;
                case llir::LlilOp::kSelect: {
                    if (expr.args.size() < 3) {
                        return std::nullopt;
                    }
                    auto cond = eval_expr(expr.args[0], regs, image, pc);
                    if (!cond) {
                        return std::nullopt;
                    }
                    if ((*cond & 0x1) != 0) {
                        return eval_expr(expr.args[1], regs, image, pc);
                    }
                    return eval_expr(expr.args[2], regs, image, pc);
                }
                case llir::LlilOp::kEq: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs == *rhs) ? 1 : 0;
                }
                case llir::LlilOp::kNe: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs != *rhs) ? 1 : 0;
                }
                case llir::LlilOp::kLt: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs < *rhs) ? 1 : 0;
                }
                case llir::LlilOp::kLe: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs <= *rhs) ? 1 : 0;
                }
                case llir::LlilOp::kGt: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs > *rhs) ? 1 : 0;
                }
                case llir::LlilOp::kGe: {
                    auto rhs = get_rhs();
                    if (!rhs) {
                        return std::nullopt;
                    }
                    return (*lhs >= *rhs) ? 1 : 0;
                }
                default:
                    break;
            }
            break;
        }
        default:
            break;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> resolve_llil_branch_target(const llir::Instruction& inst,
                                                        const RegMap& regs,
                                                        const LoadedImage& image) {
    for (const auto& stmt : inst.llil) {
        if (stmt.kind == llir::LlilStmtKind::kCall || stmt.kind == llir::LlilStmtKind::kJump ||
            stmt.kind == llir::LlilStmtKind::kCJump) {
            return eval_expr(stmt.target, regs, image, inst.address);
        }
    }
    return std::nullopt;
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

struct TableInfo {
    std::uint64_t base = 0;
    std::size_t entry_size = 8;
    bool relative = false;
    std::size_t max_entries = 0;
    std::string index_reg;
};

enum class CondKind {
    kUnknown,
    kEq,
    kNe,
    kHs,
    kLo,
    kHi,
    kLs,
    kMi,
    kPl,
    kVs,
    kVc,
    kGe,
    kLt,
    kGt,
    kLe
};

const LlilExpr* unwrap_cast(const LlilExpr& expr) {
    const LlilExpr* cur = &expr;
    while (cur->kind == llir::LlilExprKind::kOp && cur->op == llir::LlilOp::kCast && !cur->args.empty()) {
        cur = &cur->args[0];
    }
    return cur;
}

bool is_imm_zero(const LlilExpr& expr) {
    return expr.kind == llir::LlilExprKind::kImm && expr.imm == 0;
}

bool is_flag_expr(const LlilExpr& expr, const char* name) {
    const LlilExpr* cur = unwrap_cast(expr);
    return cur->kind == llir::LlilExprKind::kReg && cur->reg.name == name;
}

bool is_eq_zero_expr(const LlilExpr& expr, const LlilExpr*& value_out) {
    if (expr.kind != llir::LlilExprKind::kOp || expr.op != llir::LlilOp::kEq || expr.args.size() < 2) {
        return false;
    }
    if (is_imm_zero(expr.args[0])) {
        value_out = &expr.args[1];
        return true;
    }
    if (is_imm_zero(expr.args[1])) {
        value_out = &expr.args[0];
        return true;
    }
    return false;
}

bool is_cmp_expr(const LlilExpr& expr, llir::LlilOp op, const LlilExpr*& lhs, const LlilExpr*& rhs) {
    if (expr.kind != llir::LlilExprKind::kOp || expr.op != op || expr.args.size() < 2) {
        return false;
    }
    lhs = &expr.args[0];
    rhs = &expr.args[1];
    return true;
}

bool is_bool_and(const LlilExpr& expr, const LlilExpr*& lhs, const LlilExpr*& rhs) {
    return is_cmp_expr(expr, llir::LlilOp::kAnd, lhs, rhs);
}

bool is_bool_or(const LlilExpr& expr, const LlilExpr*& lhs, const LlilExpr*& rhs) {
    return is_cmp_expr(expr, llir::LlilOp::kOr, lhs, rhs);
}

CondKind infer_cond_kind(const LlilExpr& expr) {
    if (expr.kind == llir::LlilExprKind::kImm) {
        return CondKind::kUnknown;
    }
    if (is_flag_expr(expr, kFlagZ)) {
        return CondKind::kEq;
    }
    const LlilExpr* inner = nullptr;
    if (is_eq_zero_expr(expr, inner)) {
        if (is_flag_expr(*inner, kFlagZ)) {
            return CondKind::kNe;
        }
        if (is_flag_expr(*inner, kFlagC)) {
            return CondKind::kLo;
        }
        if (is_flag_expr(*inner, kFlagN)) {
            return CondKind::kPl;
        }
        if (is_flag_expr(*inner, kFlagV)) {
            return CondKind::kVc;
        }
    }
    if (is_flag_expr(expr, kFlagC)) {
        return CondKind::kHs;
    }
    if (is_flag_expr(expr, kFlagN)) {
        return CondKind::kMi;
    }
    if (is_flag_expr(expr, kFlagV)) {
        return CondKind::kVs;
    }
    const LlilExpr* lhs = nullptr;
    const LlilExpr* rhs = nullptr;
    if (is_bool_and(expr, lhs, rhs)) {
        const LlilExpr* not_z = nullptr;
        if ((is_flag_expr(*lhs, kFlagC) && is_eq_zero_expr(*rhs, not_z) && is_flag_expr(*not_z, kFlagZ)) ||
            (is_flag_expr(*rhs, kFlagC) && is_eq_zero_expr(*lhs, not_z) && is_flag_expr(*not_z, kFlagZ))) {
            return CondKind::kHi;
        }
        const LlilExpr* nz = nullptr;
        const LlilExpr* eq = nullptr;
        if (is_eq_zero_expr(*lhs, nz)) {
            eq = rhs;
        } else if (is_eq_zero_expr(*rhs, nz)) {
            eq = lhs;
        }
        if (nz && is_flag_expr(*nz, kFlagZ) && is_cmp_expr(*eq, llir::LlilOp::kEq, lhs, rhs)) {
            if ((is_flag_expr(*lhs, kFlagN) && is_flag_expr(*rhs, kFlagV)) ||
                (is_flag_expr(*lhs, kFlagV) && is_flag_expr(*rhs, kFlagN))) {
                return CondKind::kGt;
            }
        }
    }
    if (is_bool_or(expr, lhs, rhs)) {
        const LlilExpr* not_c = nullptr;
        if ((is_eq_zero_expr(*lhs, not_c) && is_flag_expr(*not_c, kFlagC) && is_flag_expr(*rhs, kFlagZ)) ||
            (is_eq_zero_expr(*rhs, not_c) && is_flag_expr(*not_c, kFlagC) && is_flag_expr(*lhs, kFlagZ))) {
            return CondKind::kLs;
        }
        if (is_flag_expr(*lhs, kFlagZ) && is_cmp_expr(*rhs, llir::LlilOp::kNe, lhs, rhs)) {
            if ((is_flag_expr(*lhs, kFlagN) && is_flag_expr(*rhs, kFlagV)) ||
                (is_flag_expr(*lhs, kFlagV) && is_flag_expr(*rhs, kFlagN))) {
                return CondKind::kLe;
            }
        }
        if (is_flag_expr(*rhs, kFlagZ) && is_cmp_expr(*lhs, llir::LlilOp::kNe, lhs, rhs)) {
            if ((is_flag_expr(*lhs, kFlagN) && is_flag_expr(*rhs, kFlagV)) ||
                (is_flag_expr(*lhs, kFlagV) && is_flag_expr(*rhs, kFlagN))) {
                return CondKind::kLe;
            }
        }
    }
    if (is_cmp_expr(expr, llir::LlilOp::kEq, lhs, rhs)) {
        if ((is_flag_expr(*lhs, kFlagN) && is_flag_expr(*rhs, kFlagV)) ||
            (is_flag_expr(*lhs, kFlagV) && is_flag_expr(*rhs, kFlagN))) {
            return CondKind::kGe;
        }
    }
    if (is_cmp_expr(expr, llir::LlilOp::kNe, lhs, rhs)) {
        if ((is_flag_expr(*lhs, kFlagN) && is_flag_expr(*rhs, kFlagV)) ||
            (is_flag_expr(*lhs, kFlagV) && is_flag_expr(*rhs, kFlagN))) {
            return CondKind::kLt;
        }
    }
    return CondKind::kUnknown;
}

bool eval_constant(const llir::LlilExpr& expr,
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

std::optional<std::string> extract_reg_name(const llir::LlilExpr& expr) {
    const LlilExpr* cur = unwrap_cast(expr);
    if (cur->kind == llir::LlilExprKind::kReg) {
        return cur->reg.name;
    }
    if (cur->kind == llir::LlilExprKind::kOp && cur->op == llir::LlilOp::kAnd && cur->args.size() >= 2) {
        if (cur->args[0].kind == llir::LlilExprKind::kImm) {
            return extract_reg_name(cur->args[1]);
        }
        if (cur->args[1].kind == llir::LlilExprKind::kImm) {
            return extract_reg_name(cur->args[0]);
        }
    }
    return std::nullopt;
}

std::optional<std::uint64_t> extract_imm_value(const llir::LlilExpr& expr) {
    const LlilExpr* cur = unwrap_cast(expr);
    if (cur->kind == llir::LlilExprKind::kImm) {
        return cur->imm;
    }
    return std::nullopt;
}

bool extract_index_limit(const llir::LlilExpr& expr, std::size_t& max_entries) {
    const llir::LlilExpr* cur = &expr;
    while (cur->kind == llir::LlilExprKind::kOp && cur->op == llir::LlilOp::kCast && !cur->args.empty()) {
        cur = &cur->args[0];
    }
    if (cur->kind != llir::LlilExprKind::kOp || cur->op != llir::LlilOp::kAnd || cur->args.size() < 2) {
        return false;
    }
    std::uint64_t mask = 0;
    if (cur->args[0].kind == llir::LlilExprKind::kImm) {
        mask = cur->args[0].imm;
    } else if (cur->args[1].kind == llir::LlilExprKind::kImm) {
        mask = cur->args[1].imm;
    } else {
        return false;
    }
    if (mask == 0) {
        return false;
    }
    if (mask + 1u == 0) {
        return false;
    }
    max_entries = static_cast<std::size_t>(mask + 1u);
    return true;
}

bool match_index_term(const llir::LlilExpr& expr,
                      std::size_t& scale_out,
                      std::size_t& max_entries_out,
                      std::string& index_reg_out) {
    max_entries_out = 0;
    if (expr.kind != llir::LlilExprKind::kOp || expr.args.size() < 2) {
        return false;
    }
    if (expr.op == llir::LlilOp::kMul) {
        std::uint64_t imm = 0;
        const llir::LlilExpr* index_expr = nullptr;
        if (expr.args[0].kind == llir::LlilExprKind::kImm) {
            imm = expr.args[0].imm;
            index_expr = &expr.args[1];
        } else if (expr.args[1].kind == llir::LlilExprKind::kImm) {
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
    if (expr.op == llir::LlilOp::kShl) {
        if (expr.args[1].kind != llir::LlilExprKind::kImm) {
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

bool extract_table_info(const llir::LlilExpr& expr,
                        const RegMap& regs,
                        const LoadedImage& image,
                        std::uint64_t pc,
                        TableInfo& out) {
    if (expr.kind != llir::LlilExprKind::kLoad || expr.args.empty()) {
        return false;
    }
    out.max_entries = 0;
    out.index_reg.clear();
    const llir::LlilExpr& addr = expr.args[0];
    std::uint64_t base = 0;
    bool base_found = false;
    std::size_t scale = 0;
    if (addr.kind == llir::LlilExprKind::kReg) {
        const std::string key = normalize_reg_name(addr.reg.name);
        auto it = regs.find(key);
        if (it != regs.end()) {
            base = it->second;
            base_found = true;
        }
    }
    if (addr.kind == llir::LlilExprKind::kOp && addr.op == llir::LlilOp::kAdd && addr.args.size() >= 2) {
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

struct CompareInfo {
    std::string reg;
    std::uint64_t imm = 0;
    bool reg_is_lhs = false;
    bool valid = false;
};

bool extract_compare_reg_imm(const LlilExpr& lhs, const LlilExpr& rhs, CompareInfo& out) {
    auto lhs_reg = extract_reg_name(lhs);
    auto rhs_reg = extract_reg_name(rhs);
    auto lhs_imm = extract_imm_value(lhs);
    auto rhs_imm = extract_imm_value(rhs);
    if (lhs_reg && rhs_imm) {
        out.reg = *lhs_reg;
        out.imm = *rhs_imm;
        out.reg_is_lhs = true;
        out.valid = true;
        return true;
    }
    if (rhs_reg && lhs_imm) {
        out.reg = *rhs_reg;
        out.imm = *lhs_imm;
        out.reg_is_lhs = false;
        out.valid = true;
        return true;
    }
    return false;
}

bool derive_upper_bound(const CompareInfo& cmp, CondKind cond, std::size_t& out_max) {
    if (!cmp.valid || !cmp.reg_is_lhs) {
        return false;
    }
    if (cmp.imm > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }
    switch (cond) {
        case CondKind::kHi:
        case CondKind::kGt: {
            if (cmp.imm == std::numeric_limits<std::uint64_t>::max()) {
                return false;
            }
            const std::uint64_t candidate = cmp.imm + 1;
            if (candidate > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
                return false;
            }
            out_max = static_cast<std::size_t>(candidate);
            return true;
        }
        case CondKind::kHs:
        case CondKind::kGe: {
            out_max = static_cast<std::size_t>(cmp.imm);
            return true;
        }
        default:
            break;
    }
    return false;
}

std::uint64_t image_base(const std::vector<BinarySegment>& segments) {
    if (segments.empty()) {
        return 0;
    }
    std::uint64_t base = segments.front().vaddr;
    for (const auto& seg : segments) {
        if (seg.vaddr < base) {
            base = seg.vaddr;
        }
    }
    return base;
}

std::uint64_t tls_base(const std::vector<BinarySegment>& segments, bool& has_tls) {
    has_tls = false;
    std::uint64_t base = 0;
    for (const auto& seg : segments) {
        if (seg.type != kElfPtTls) {
            continue;
        }
        if (!has_tls || seg.vaddr < base) {
            base = seg.vaddr;
        }
        has_tls = true;
    }
    return base;
}

std::optional<std::uint64_t> reloc_value(const BinaryRelocation& reloc,
                                         std::uint64_t base,
                                         std::uint64_t tls,
                                         bool has_tls) {
    switch (reloc.type) {
        case kRelocAarch64Relative:
            return static_cast<std::uint64_t>(static_cast<std::int64_t>(base) + reloc.addend);
        case kRelocAarch64Abs64:
        case kRelocAarch64GlobDat:
        case kRelocAarch64JumpSlot:
            return static_cast<std::uint64_t>(static_cast<std::int64_t>(reloc.symbol_value) + reloc.addend);
        case kRelocAarch64IRelative:
            return static_cast<std::uint64_t>(static_cast<std::int64_t>(base) + reloc.addend);
        case kRelocAarch64TlsDtpMod64:
            return has_tls ? 1 : 0;
        case kRelocAarch64TlsDtpRel64:
        case kRelocAarch64TlsTpRel64:
            return static_cast<std::uint64_t>(static_cast<std::int64_t>(reloc.symbol_value) + reloc.addend -
                                              static_cast<std::int64_t>(has_tls ? tls : 0));
        case kRelocPeHighLow:
        case kRelocPeDir64:
            return static_cast<std::uint64_t>(static_cast<std::int64_t>(base) + reloc.addend);
        default:
            break;
    }
    return std::nullopt;
}

}  // namespace

bool find_xrefs_to_address(const LoadedImage& image,
                           std::uint64_t target,
                           std::size_t max_results,
                           std::vector<XrefEntry>& out) {
    out.clear();
    if (max_results == 0) {
        return true;
    }

    for (const auto& seg : image.segments) {
        const std::size_t size = seg.data.size();
        if (size < 8) {
            continue;
        }
        for (std::size_t offset = 0; offset + 8 <= size; ++offset) {
            std::uint64_t value = 0;
            if (!read_u64(seg.data, offset, value)) {
                break;
            }
            if (value == target) {
                XrefEntry entry;
                entry.source = seg.vaddr + offset;
                entry.target = target;
                entry.kind = XrefKind::kDataPointer;
                out.push_back(entry);
                if (out.size() >= max_results) {
                    return true;
                }
            }
        }
    }

    return true;
}

bool find_xrefs_to_address(const LoadedImage& image,
                           const std::vector<BinaryRelocation>& relocations,
                           const std::vector<BinarySegment>& segments,
                           std::uint64_t target,
                           std::size_t max_results,
                           std::vector<XrefEntry>& out) {
    out.clear();
    if (max_results == 0) {
        return true;
    }

    find_xrefs_to_address(image, target, max_results, out);
    std::unordered_set<std::uint64_t> seen;
    seen.reserve(out.size());
    for (const auto& entry : out) {
        seen.insert(entry.source);
    }
    if (out.size() >= max_results) {
        return true;
    }

    const std::uint64_t base = image_base(segments);
    bool has_tls = false;
    const std::uint64_t tls = tls_base(segments, has_tls);
    for (const auto& reloc : relocations) {
        auto value = reloc_value(reloc, base, tls, has_tls);
        if (!value || *value != target) {
            continue;
        }
        if (!seen.insert(reloc.offset).second) {
            continue;
        }
        XrefEntry entry;
        entry.source = reloc.offset;
        entry.target = target;
        entry.kind = XrefKind::kDataPointer;
        out.push_back(entry);
        if (out.size() >= max_results) {
            return true;
        }
    }

    return true;
}

void collect_code_xrefs(const LoadedImage& image, const llir::Function& function, std::vector<XrefEntry>& out) {
    collect_code_xrefs(image, {}, function, out);
}

void collect_code_xrefs(const LoadedImage& image,
                        const std::vector<BinarySegment>& segments,
                        const llir::Function& function,
                        std::vector<XrefEntry>& out) {
    for (const auto& block : function.blocks) {
        RegMap regs;
        std::unordered_map<std::string, std::size_t> bounds;
        CompareInfo last_compare;
        for (const auto& inst : block.instructions) {
            const LlilExpr* cmp_lhs = nullptr;
            const LlilExpr* cmp_rhs = nullptr;
            bool has_cmp = false;
            bool sets_non_flag = false;
            for (const auto& stmt : inst.llil) {
                if (stmt.kind == llir::LlilStmtKind::kSetReg) {
                    if (is_flag_reg_name(stmt.reg.name)) {
                        if (stmt.reg.name == kFlagC &&
                            is_cmp_expr(stmt.expr, llir::LlilOp::kGe, cmp_lhs, cmp_rhs)) {
                            has_cmp = true;
                        }
                    } else {
                        sets_non_flag = true;
                    }
                }
            }
            for (const auto& stmt : inst.llil) {
                if (stmt.kind == llir::LlilStmtKind::kSetReg) {
                    const std::size_t reg_size = reg_size_from_name(stmt.reg.name);
                    auto value = eval_expr(stmt.expr, regs, image, inst.address);
                    write_reg(regs, stmt.reg.name, reg_size, value);
                    if (!is_flag_reg_name(stmt.reg.name)) {
                        const std::string key = normalize_reg_name(stmt.reg.name);
                        bounds.erase(key);
                        if (last_compare.valid && normalize_reg_name(last_compare.reg) == key) {
                            last_compare.valid = false;
                        }
                    }
                } else if (stmt.kind == llir::LlilStmtKind::kCJump) {
                    const CondKind cond = infer_cond_kind(stmt.condition);
                    std::size_t max_entries = 0;
                    if (derive_upper_bound(last_compare, cond, max_entries) && max_entries > 0) {
                        const std::string key = normalize_reg_name(last_compare.reg);
                        auto it = bounds.find(key);
                        if (it == bounds.end()) {
                            bounds.emplace(key, max_entries);
                        } else if (max_entries < it->second) {
                            it->second = max_entries;
                        }
                    }
                }
            }
            if (has_cmp && !sets_non_flag && cmp_lhs && cmp_rhs) {
                CompareInfo cmp;
                if (extract_compare_reg_imm(*cmp_lhs, *cmp_rhs, cmp)) {
                    last_compare = cmp;
                }
            }
            std::optional<std::uint64_t> resolved_target;
            std::vector<std::uint64_t> indirect_targets;
            if (inst.targets.empty()) {
                resolved_target = resolve_llil_branch_target(inst, regs, image);
                if (resolved_target && *resolved_target == 0) {
                    resolved_target = std::nullopt;
                }
                if (!resolved_target && !segments.empty()) {
                    for (const auto& stmt : inst.llil) {
                        if (stmt.kind != llir::LlilStmtKind::kCall && stmt.kind != llir::LlilStmtKind::kJump &&
                            stmt.kind != llir::LlilStmtKind::kCJump) {
                            continue;
                        }
                        TableInfo table;
                        if (extract_table_info(stmt.target, regs, image, inst.address, table)) {
                            if (!table.index_reg.empty()) {
                                const std::string key = normalize_reg_name(table.index_reg);
                                auto it = bounds.find(key);
                                if (it != bounds.end() && it->second > 0) {
                                    if (table.max_entries == 0) {
                                        table.max_entries = it->second;
                                    } else {
                                        table.max_entries = std::min(table.max_entries, it->second);
                                    }
                                }
                            }
                            indirect_targets = read_table_targets(table, image, segments);
                            break;
                        }
                    }
                }
            }
            if (inst.branch == llir::BranchKind::kCall) {
                if (inst.targets.empty()) {
                    XrefEntry entry;
                    entry.source = inst.address;
                    if (resolved_target) {
                        entry.target = *resolved_target;
                        entry.kind = XrefKind::kCodeCall;
                    } else if (!indirect_targets.empty()) {
                        for (std::uint64_t target : indirect_targets) {
                            XrefEntry jt;
                            jt.source = inst.address;
                            jt.target = target;
                            jt.kind = XrefKind::kCodeCallIndirect;
                            out.push_back(jt);
                        }
                        continue;
                    } else {
                        entry.kind = XrefKind::kCodeCallIndirect;
                    }
                    out.push_back(entry);
                } else {
                    for (std::uint64_t target : inst.targets) {
                        XrefEntry entry;
                        entry.source = inst.address;
                        entry.target = target;
                        entry.kind = XrefKind::kCodeCall;
                        out.push_back(entry);
                    }
                }
            } else if (inst.branch == llir::BranchKind::kJump) {
                if (inst.targets.empty()) {
                    XrefEntry entry;
                    entry.source = inst.address;
                    if (resolved_target) {
                        entry.target = *resolved_target;
                        entry.kind = XrefKind::kCodeJump;
                    } else if (!indirect_targets.empty()) {
                        for (std::uint64_t target : indirect_targets) {
                            XrefEntry jt;
                            jt.source = inst.address;
                            jt.target = target;
                            jt.kind = XrefKind::kCodeJumpIndirect;
                            out.push_back(jt);
                        }
                        continue;
                    } else {
                        entry.kind = XrefKind::kCodeJumpIndirect;
                    }
                    out.push_back(entry);
                } else {
                    for (std::uint64_t target : inst.targets) {
                        XrefEntry entry;
                        entry.source = inst.address;
                        entry.target = target;
                        entry.kind = XrefKind::kCodeJump;
                        out.push_back(entry);
                    }
                }
            }
        }
    }
}

void collect_code_xrefs(const LoadedImage& image,
                        const std::vector<llir::Function>& functions,
                        std::vector<XrefEntry>& out) {
    collect_code_xrefs(image, {}, functions, out);
}

void collect_code_xrefs(const LoadedImage& image,
                        const std::vector<BinarySegment>& segments,
                        const std::vector<llir::Function>& functions,
                        std::vector<XrefEntry>& out) {
    for (const auto& function : functions) {
        collect_code_xrefs(image, segments, function, out);
    }
}

}  // namespace engine::xrefs
