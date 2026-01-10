#include "llil_lifter.h"

#include <cctype>
#include <cstring>
#include <sstream>
#include <utility>

#include "engine/arch/arm64/calling_convention.h"

namespace engine::llir::arm64 {

namespace {

constexpr const char* kFlagN = "flag_n";
constexpr const char* kFlagZ = "flag_z";
constexpr const char* kFlagC = "flag_c";
constexpr const char* kFlagV = "flag_v";

LlilExpr make_reg(csh handle, arm64_reg reg, std::size_t size) {
    LlilExpr expr;
    expr.kind = LlilExprKind::kReg;
    expr.size = size;
    const char* name = cs_reg_name(handle, reg);
    expr.reg.name = name ? name : "reg";
    return expr;
}

LlilExpr make_pseudo_reg(const std::string& name, std::size_t size) {
    LlilExpr expr;
    expr.kind = LlilExprKind::kReg;
    expr.size = size;
    expr.reg.name = name;
    return expr;
}

std::size_t reg_size_from_name(const std::string& name) {
    if (name.empty()) {
        return 0;
    }
    switch (name[0]) {
        case 'w': return 4;
        case 'x': return 8;
        case 'b': return 1;
        case 'h': return 2;
        case 's': return 4;
        case 'd': return 8;
        case 'q':
        case 'v': return 16;
        default: return 0;
    }
}

LlilExpr make_undef(std::size_t size) {
    LlilExpr expr;
    expr.kind = LlilExprKind::kUndef;
    expr.size = size;
    return expr;
}

bool is_atomic_load(arm64_insn id) {
    switch (id) {
        case ARM64_INS_LDXR:
        case ARM64_INS_LDXRB:
        case ARM64_INS_LDXRH:
        case ARM64_INS_LDAXR:
        case ARM64_INS_LDAXRB:
        case ARM64_INS_LDAXRH:
            return true;
        default:
            return false;
    }
}

bool is_atomic_store(arm64_insn id) {
    switch (id) {
        case ARM64_INS_STXR:
        case ARM64_INS_STXRB:
        case ARM64_INS_STXRH:
        case ARM64_INS_STLXR:
        case ARM64_INS_STLXRB:
        case ARM64_INS_STLXRH:
            return true;
        default:
            return false;
    }
}

bool is_atomic_swap(arm64_insn id) {
    switch (id) {
        case ARM64_INS_SWP:
        case ARM64_INS_SWPA:
        case ARM64_INS_SWPAL:
        case ARM64_INS_SWPL:
        case ARM64_INS_SWPB:
        case ARM64_INS_SWPAB:
        case ARM64_INS_SWPALB:
        case ARM64_INS_SWPLB:
        case ARM64_INS_SWPH:
        case ARM64_INS_SWPAH:
        case ARM64_INS_SWPALH:
        case ARM64_INS_SWPLH:
            return true;
        default:
            return false;
    }
}

bool is_atomic_compare_swap(arm64_insn id) {
    switch (id) {
        case ARM64_INS_CAS:
        case ARM64_INS_CASA:
        case ARM64_INS_CASAL:
        case ARM64_INS_CASL:
        case ARM64_INS_CASB:
        case ARM64_INS_CASAB:
        case ARM64_INS_CASALB:
        case ARM64_INS_CASLB:
        case ARM64_INS_CASH:
        case ARM64_INS_CASAH:
        case ARM64_INS_CASALH:
        case ARM64_INS_CASLH:
        case ARM64_INS_CASP:
        case ARM64_INS_CASPA:
        case ARM64_INS_CASPAL:
        case ARM64_INS_CASPL:
            return true;
        default:
            return false;
    }
}

std::size_t atomic_mem_size(arm64_insn id, std::size_t reg_size) {
    switch (id) {
        case ARM64_INS_LDXRB:
        case ARM64_INS_LDAXRB:
        case ARM64_INS_STXRB:
        case ARM64_INS_STLXRB:
        case ARM64_INS_SWPB:
        case ARM64_INS_SWPAB:
        case ARM64_INS_SWPALB:
        case ARM64_INS_SWPLB:
        case ARM64_INS_CASB:
        case ARM64_INS_CASAB:
        case ARM64_INS_CASALB:
        case ARM64_INS_CASLB:
            return 1;
        case ARM64_INS_LDXRH:
        case ARM64_INS_LDAXRH:
        case ARM64_INS_STXRH:
        case ARM64_INS_STLXRH:
        case ARM64_INS_SWPH:
        case ARM64_INS_SWPAH:
        case ARM64_INS_SWPALH:
        case ARM64_INS_SWPLH:
        case ARM64_INS_CASH:
        case ARM64_INS_CASAH:
        case ARM64_INS_CASALH:
        case ARM64_INS_CASLH:
            return 2;
        default:
            return reg_size;
    }
}

bool is_vector_load(arm64_insn id) {
    switch (id) {
        case ARM64_INS_LD1:
        case ARM64_INS_LD1B:
        case ARM64_INS_LD1D:
        case ARM64_INS_LD1H:
        case ARM64_INS_LD1Q:
        case ARM64_INS_LD1R:
        case ARM64_INS_LD1RB:
        case ARM64_INS_LD1RD:
        case ARM64_INS_LD1RH:
        case ARM64_INS_LD1ROB:
        case ARM64_INS_LD1ROD:
        case ARM64_INS_LD1ROH:
        case ARM64_INS_LD1ROW:
        case ARM64_INS_LD1RQB:
        case ARM64_INS_LD1RQD:
        case ARM64_INS_LD1RQH:
        case ARM64_INS_LD1RQW:
        case ARM64_INS_LD1RSB:
        case ARM64_INS_LD1RSH:
        case ARM64_INS_LD1RSW:
        case ARM64_INS_LD1RW:
        case ARM64_INS_LD1SB:
        case ARM64_INS_LD1SH:
        case ARM64_INS_LD1SW:
        case ARM64_INS_LD1W:
        case ARM64_INS_LD2:
        case ARM64_INS_LD2B:
        case ARM64_INS_LD2D:
        case ARM64_INS_LD2H:
        case ARM64_INS_LD2R:
        case ARM64_INS_LD2W:
        case ARM64_INS_LD3:
        case ARM64_INS_LD3B:
        case ARM64_INS_LD3D:
        case ARM64_INS_LD3H:
        case ARM64_INS_LD3R:
        case ARM64_INS_LD3W:
        case ARM64_INS_LD4:
        case ARM64_INS_LD4B:
        case ARM64_INS_LD4D:
        case ARM64_INS_LD4H:
        case ARM64_INS_LD4R:
        case ARM64_INS_LD4W:
            return true;
        default:
            return false;
    }
}

bool is_vector_store(arm64_insn id) {
    switch (id) {
        case ARM64_INS_ST1:
        case ARM64_INS_ST1B:
        case ARM64_INS_ST1D:
        case ARM64_INS_ST1H:
        case ARM64_INS_ST1Q:
        case ARM64_INS_ST1W:
        case ARM64_INS_ST2:
        case ARM64_INS_ST2B:
        case ARM64_INS_ST2D:
        case ARM64_INS_ST2G:
        case ARM64_INS_ST2H:
        case ARM64_INS_ST2W:
        case ARM64_INS_ST3:
        case ARM64_INS_ST3B:
        case ARM64_INS_ST3D:
        case ARM64_INS_ST3H:
        case ARM64_INS_ST3W:
        case ARM64_INS_ST4:
        case ARM64_INS_ST4B:
        case ARM64_INS_ST4D:
        case ARM64_INS_ST4H:
        case ARM64_INS_ST4W:
            return true;
        default:
            return false;
    }
}

std::size_t vector_mem_size(arm64_insn id, std::size_t reg_size) {
    switch (id) {
        case ARM64_INS_LD1B:
        case ARM64_INS_LD1RB:
        case ARM64_INS_LD1ROB:
        case ARM64_INS_LD1RQB:
        case ARM64_INS_LD1RSB:
        case ARM64_INS_LD1SB:
        case ARM64_INS_LD2B:
        case ARM64_INS_LD3B:
        case ARM64_INS_LD4B:
        case ARM64_INS_ST1B:
        case ARM64_INS_ST2B:
        case ARM64_INS_ST3B:
        case ARM64_INS_ST4B:
            return 1;
        case ARM64_INS_LD1H:
        case ARM64_INS_LD1RH:
        case ARM64_INS_LD1ROH:
        case ARM64_INS_LD1RQH:
        case ARM64_INS_LD1RSH:
        case ARM64_INS_LD1SH:
        case ARM64_INS_LD2H:
        case ARM64_INS_LD3H:
        case ARM64_INS_LD4H:
        case ARM64_INS_ST1H:
        case ARM64_INS_ST2H:
        case ARM64_INS_ST3H:
        case ARM64_INS_ST4H:
            return 2;
        case ARM64_INS_LD1W:
        case ARM64_INS_LD1RW:
        case ARM64_INS_LD1ROW:
        case ARM64_INS_LD1RQW:
        case ARM64_INS_LD1RSW:
        case ARM64_INS_LD1SW:
        case ARM64_INS_LD2W:
        case ARM64_INS_LD3W:
        case ARM64_INS_LD4W:
        case ARM64_INS_ST1W:
        case ARM64_INS_ST2W:
        case ARM64_INS_ST3W:
        case ARM64_INS_ST4W:
            return 4;
        case ARM64_INS_LD1D:
        case ARM64_INS_LD1RD:
        case ARM64_INS_LD1ROD:
        case ARM64_INS_LD1RQD:
        case ARM64_INS_LD2D:
        case ARM64_INS_LD3D:
        case ARM64_INS_LD4D:
        case ARM64_INS_ST1D:
        case ARM64_INS_ST2D:
        case ARM64_INS_ST3D:
        case ARM64_INS_ST4D:
            return 8;
        case ARM64_INS_LD1Q:
        case ARM64_INS_ST1Q:
            return 16;
        default:
            return reg_size;
    }
}

std::size_t reg_size_from_name(csh handle, arm64_reg reg) {
    const char* name = cs_reg_name(handle, reg);
    if (!name || name[0] == '\0') {
        return 8;
    }
    if (std::strcmp(name, "wsp") == 0) {
        return 4;
    }
    if (std::strcmp(name, "sp") == 0) {
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

LlilExpr make_imm(std::uint64_t value, std::size_t size) {
    LlilExpr expr;
    expr.kind = LlilExprKind::kImm;
    expr.size = size;
    expr.imm = value;
    return expr;
}

LlilExpr make_op(LlilOp op, std::vector<LlilExpr> args, std::size_t size) {
    LlilExpr expr;
    expr.kind = LlilExprKind::kOp;
    expr.op = op;
    expr.size = size;
    expr.args = std::move(args);
    return expr;
}

LlilExpr make_load(LlilExpr address, std::size_t size) {
    LlilExpr expr;
    expr.kind = LlilExprKind::kLoad;
    expr.size = size;
    expr.args.push_back(std::move(address));
    return expr;
}

LlilExpr build_mem_address(csh handle, const arm64_op_mem& mem) {
    LlilExpr addr;
    if (mem.base != ARM64_REG_INVALID) {
        addr = make_reg(handle, mem.base, 8);
    } else {
        addr = make_imm(0, 8);
    }
    if (mem.index != ARM64_REG_INVALID) {
        std::vector<LlilExpr> args;
        args.push_back(std::move(addr));
        args.push_back(make_reg(handle, mem.index, 8));
        addr = make_op(LlilOp::kAdd, std::move(args), 8);
    }
    if (mem.disp != 0) {
        std::vector<LlilExpr> args;
        args.push_back(std::move(addr));
        args.push_back(make_imm(static_cast<std::uint64_t>(mem.disp), 8));
        addr = make_op(LlilOp::kAdd, std::move(args), 8);
    }
    return addr;
}

LlilExpr operand_to_expr(csh handle, const cs_arm64_op& op, std::size_t size_hint) {
    switch (op.type) {
        case ARM64_OP_REG:
            return make_reg(handle, op.reg, reg_size_from_name(handle, op.reg));
        case ARM64_OP_IMM:
            return make_imm(static_cast<std::uint64_t>(op.imm), size_hint ? size_hint : 8);
        case ARM64_OP_MEM:
            return make_load(build_mem_address(handle, op.mem), size_hint ? size_hint : 8);
        default:
            break;
    }
    return {};
}

LlilExpr apply_shift(LlilExpr expr, const cs_arm64_op& op) {
    if (op.shift.type == ARM64_SFT_INVALID || op.shift.value == 0) {
        return expr;
    }
    const std::size_t expr_size = expr.size;
    LlilOp shift_op = LlilOp::kShl;
    switch (op.shift.type) {
        case ARM64_SFT_LSL:
            shift_op = LlilOp::kShl;
            break;
        case ARM64_SFT_LSR:
            shift_op = LlilOp::kShr;
            break;
        case ARM64_SFT_ASR:
            shift_op = LlilOp::kSar;
            break;
        case ARM64_SFT_ROR:
            shift_op = LlilOp::kRor;
            break;
        default:
            return expr;
    }
    std::vector<LlilExpr> args;
    args.push_back(std::move(expr));
    args.push_back(make_imm(op.shift.value, 8));
    return make_op(shift_op, std::move(args), expr_size);
}

LlilExpr operand_to_expr_shifted(csh handle, const cs_arm64_op& op, std::size_t size_hint) {
    LlilExpr expr = operand_to_expr(handle, op, size_hint);
    if (expr.kind == LlilExprKind::kInvalid) {
        return expr;
    }
    return apply_shift(std::move(expr), op);
}

void push_unimpl(Instruction& out, const cs_insn& insn) {
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kUnimpl;
    std::ostringstream oss;
    oss << insn.mnemonic;
    if (insn.op_str && insn.op_str[0] != '\0') {
        oss << " " << insn.op_str;
    }
    stmt.comment = oss.str();
    out.llil.push_back(std::move(stmt));
}

void push_unknown_effects(csh, const cs_arm64&, Instruction& out, const std::string& mnemonic) {
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kUnimpl;
    stmt.comment = mnemonic;
    out.llil.push_back(std::move(stmt));
}

std::uint32_t get_shift_value(const cs_arm64_op& op) {
    if (op.shift.type == ARM64_SFT_LSL) {
        return op.shift.value;
    }
    return 0;
}

std::size_t mem_access_size(arm64_insn id, std::size_t reg_size) {
    switch (id) {
        case ARM64_INS_LDRB:
        case ARM64_INS_LDURB:
        case ARM64_INS_LDRSB:
        case ARM64_INS_LDURSB:
        case ARM64_INS_STRB:
        case ARM64_INS_STURB:
            return 1;
        case ARM64_INS_LDRH:
        case ARM64_INS_LDURH:
        case ARM64_INS_LDRSH:
        case ARM64_INS_LDURSH:
        case ARM64_INS_STRH:
        case ARM64_INS_STURH:
            return 2;
        case ARM64_INS_LDRSW:
        case ARM64_INS_LDURSW:
            return 4;
        default:
            return reg_size ? reg_size : 8;
    }
}

LlilExpr make_flag_expr(const char* name) {
    return make_pseudo_reg(name, 1);
}

struct FlagExpr {
    LlilExpr n;
    LlilExpr z;
    LlilExpr c;
    LlilExpr v;
};

void emit_flag_set(Instruction& out, const char* name, LlilExpr expr) {
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kSetReg;
    stmt.reg = make_pseudo_reg(name, 1).reg;
    stmt.expr = std::move(expr);
    out.llil.push_back(std::move(stmt));
}

LlilExpr make_bool_op(LlilOp op, LlilExpr lhs, LlilExpr rhs) {
    std::vector<LlilExpr> args;
    args.push_back(std::move(lhs));
    args.push_back(std::move(rhs));
    return make_op(op, std::move(args), 1);
}

LlilExpr make_bool_not(LlilExpr value) {
    return make_bool_op(LlilOp::kEq, std::move(value), make_imm(0, 1));
}

LlilExpr make_msb_expr(LlilExpr value, std::size_t size) {
    std::size_t width = size;
    if (width == 0) {
        width = value.size;
    }
    if (width == 0) {
        width = 8;
    }
    const std::size_t shift = (width * 8) - 1;
    std::vector<LlilExpr> shift_args;
    shift_args.push_back(std::move(value));
    shift_args.push_back(make_imm(shift, 8));
    LlilExpr shifted = make_op(LlilOp::kShr, std::move(shift_args), width);
    std::vector<LlilExpr> and_args;
    and_args.push_back(std::move(shifted));
    and_args.push_back(make_imm(1, 1));
    return make_op(LlilOp::kAnd, std::move(and_args), 1);
}

void emit_nz_flags(Instruction& out, const LlilExpr& result, std::size_t size) {
    emit_flag_set(out, kFlagN, make_msb_expr(result, size));
    emit_flag_set(out, kFlagZ, make_bool_op(LlilOp::kEq, result, make_imm(0, size)));
}

FlagExpr make_nz_flags(const LlilExpr& result, std::size_t size) {
    FlagExpr flags;
    flags.n = make_msb_expr(result, size);
    flags.z = make_bool_op(LlilOp::kEq, result, make_imm(0, size));
    return flags;
}

FlagExpr make_flags_from_add(const LlilExpr& lhs,
                             const LlilExpr& rhs,
                             const LlilExpr& result,
                             const LlilExpr& carry_expr,
                             std::size_t size) {
    FlagExpr flags = make_nz_flags(result, size);
    if (carry_expr.kind == LlilExprKind::kInvalid) {
        flags.c = make_bool_op(LlilOp::kLt, result, lhs);
        LlilExpr n_l = make_msb_expr(lhs, size);
        LlilExpr n_r = make_msb_expr(rhs, size);
        LlilExpr n_res = make_msb_expr(result, size);
        LlilExpr same_sign = make_bool_op(LlilOp::kEq, n_l, n_r);
        LlilExpr diff_sign = make_bool_op(LlilOp::kNe, n_res, n_l);
        flags.v = make_bool_op(LlilOp::kAnd, same_sign, diff_sign);
        return flags;
    }
    LlilExpr sum = make_op(LlilOp::kAdd, {lhs, rhs}, size);
    LlilExpr carry1 = make_bool_op(LlilOp::kLt, sum, lhs);
    LlilExpr carry2 = make_bool_op(LlilOp::kLt, result, sum);
    flags.c = make_bool_op(LlilOp::kOr, carry1, carry2);
    LlilExpr n_l = make_msb_expr(lhs, size);
    LlilExpr rhs_with_carry = make_op(LlilOp::kAdd, {rhs, carry_expr}, size);
    LlilExpr n_r = make_msb_expr(rhs_with_carry, size);
    LlilExpr n_res = make_msb_expr(result, size);
    LlilExpr same_sign = make_bool_op(LlilOp::kEq, n_l, n_r);
    LlilExpr diff_sign = make_bool_op(LlilOp::kNe, n_res, n_l);
    flags.v = make_bool_op(LlilOp::kAnd, same_sign, diff_sign);
    return flags;
}

FlagExpr make_flags_from_sub(const LlilExpr& lhs,
                             const LlilExpr& rhs,
                             const LlilExpr& result,
                             std::size_t size) {
    FlagExpr flags = make_nz_flags(result, size);
    flags.c = make_bool_op(LlilOp::kGe, lhs, rhs);
    LlilExpr n_l = make_msb_expr(lhs, size);
    LlilExpr n_r = make_msb_expr(rhs, size);
    LlilExpr n_res = make_msb_expr(result, size);
    LlilExpr diff_sign = make_bool_op(LlilOp::kNe, n_l, n_r);
    LlilExpr diff_res = make_bool_op(LlilOp::kNe, n_res, n_l);
    flags.v = make_bool_op(LlilOp::kAnd, diff_sign, diff_res);
    return flags;
}

FlagExpr make_flags_from_logic(const LlilExpr& result, std::size_t size) {
    FlagExpr flags = make_nz_flags(result, size);
    flags.c = make_imm(0, 1);
    flags.v = make_imm(0, 1);
    return flags;
}

FlagExpr make_flags_from_nzcv(std::uint8_t imm) {
    FlagExpr flags;
    flags.n = make_imm((imm >> 3) & 0x1, 1);
    flags.z = make_imm((imm >> 2) & 0x1, 1);
    flags.c = make_imm((imm >> 1) & 0x1, 1);
    flags.v = make_imm(imm & 0x1, 1);
    return flags;
}

bool extract_nzcv_imm(const cs_arm64& arm, std::uint8_t& out) {
    bool found = false;
    std::uint64_t value = 0;
    for (std::uint8_t i = 0; i < arm.op_count; ++i) {
        const auto& op = arm.operands[i];
        if (op.type != ARM64_OP_IMM) {
            continue;
        }
        value = static_cast<std::uint64_t>(op.imm);
        found = true;
    }
    if (!found) {
        return false;
    }
    out = static_cast<std::uint8_t>(value & 0xf);
    return true;
}

void emit_nzcv_add(Instruction& out,
                   const LlilExpr& lhs,
                   const LlilExpr& rhs,
                   const LlilExpr& result,
                   const LlilExpr& carry_expr,
                   std::size_t size) {
    emit_nz_flags(out, result, size);
    if (carry_expr.kind == LlilExprKind::kInvalid) {
        emit_flag_set(out, kFlagC, make_bool_op(LlilOp::kLt, result, lhs));
        LlilExpr n_l = make_msb_expr(lhs, size);
        LlilExpr n_r = make_msb_expr(rhs, size);
        LlilExpr n_res = make_msb_expr(result, size);
        LlilExpr same_sign = make_bool_op(LlilOp::kEq, n_l, n_r);
        LlilExpr diff_sign = make_bool_op(LlilOp::kNe, n_res, n_l);
        emit_flag_set(out, kFlagV, make_bool_op(LlilOp::kAnd, same_sign, diff_sign));
        return;
    }
    std::vector<LlilExpr> sum_args;
    sum_args.push_back(lhs);
    sum_args.push_back(rhs);
    LlilExpr sum = make_op(LlilOp::kAdd, std::move(sum_args), size);
    LlilExpr carry1 = make_bool_op(LlilOp::kLt, sum, lhs);
    LlilExpr carry2 = make_bool_op(LlilOp::kLt, result, sum);
    emit_flag_set(out, kFlagC, make_bool_op(LlilOp::kOr, carry1, carry2));
    LlilExpr n_l = make_msb_expr(lhs, size);
    std::vector<LlilExpr> rhs_args;
    rhs_args.push_back(rhs);
    rhs_args.push_back(carry_expr);
    LlilExpr rhs_with_carry = make_op(LlilOp::kAdd, std::move(rhs_args), size);
    LlilExpr n_r = make_msb_expr(rhs_with_carry, size);
    LlilExpr n_res = make_msb_expr(result, size);
    LlilExpr same_sign = make_bool_op(LlilOp::kEq, n_l, n_r);
    LlilExpr diff_sign = make_bool_op(LlilOp::kNe, n_res, n_l);
    emit_flag_set(out, kFlagV, make_bool_op(LlilOp::kAnd, same_sign, diff_sign));
}

void emit_nzcv_sub(Instruction& out,
                   const LlilExpr& lhs,
                   const LlilExpr& rhs,
                   const LlilExpr& result,
                   std::size_t size) {
    emit_nz_flags(out, result, size);
    emit_flag_set(out, kFlagC, make_bool_op(LlilOp::kGe, lhs, rhs));
    LlilExpr n_l = make_msb_expr(lhs, size);
    LlilExpr n_r = make_msb_expr(rhs, size);
    LlilExpr n_res = make_msb_expr(result, size);
    LlilExpr diff_sign = make_bool_op(LlilOp::kNe, n_l, n_r);
    LlilExpr diff_res = make_bool_op(LlilOp::kNe, n_res, n_l);
    emit_flag_set(out, kFlagV, make_bool_op(LlilOp::kAnd, diff_sign, diff_res));
}

void emit_nzcv_logic(Instruction& out, const LlilExpr& result, std::size_t size) {
    const FlagExpr flags = make_flags_from_logic(result, size);
    emit_flag_set(out, kFlagN, flags.n);
    emit_flag_set(out, kFlagZ, flags.z);
    emit_flag_set(out, kFlagC, flags.c);
    emit_flag_set(out, kFlagV, flags.v);
}

LlilExpr make_cmp_cond_expr(arm64_cc cc) {
    LlilExpr n = make_flag_expr(kFlagN);
    LlilExpr z = make_flag_expr(kFlagZ);
    LlilExpr c = make_flag_expr(kFlagC);
    LlilExpr v = make_flag_expr(kFlagV);
    switch (cc) {
        case ARM64_CC_EQ:
            return z;
        case ARM64_CC_NE:
            return make_bool_not(z);
        case ARM64_CC_HS:
            return c;
        case ARM64_CC_LO:
            return make_bool_not(c);
        case ARM64_CC_MI:
            return n;
        case ARM64_CC_PL:
            return make_bool_not(n);
        case ARM64_CC_VS:
            return v;
        case ARM64_CC_VC:
            return make_bool_not(v);
        case ARM64_CC_HI: {
            LlilExpr not_z = make_bool_not(z);
            return make_bool_op(LlilOp::kAnd, c, not_z);
        }
        case ARM64_CC_LS:
            return make_bool_op(LlilOp::kOr, make_bool_not(c), z);
        case ARM64_CC_GE:
            return make_bool_op(LlilOp::kEq, n, v);
        case ARM64_CC_LT:
            return make_bool_op(LlilOp::kNe, n, v);
        case ARM64_CC_GT: {
            LlilExpr nz = make_bool_not(z);
            LlilExpr n_eq_v = make_bool_op(LlilOp::kEq, n, v);
            return make_bool_op(LlilOp::kAnd, nz, n_eq_v);
        }
        case ARM64_CC_LE: {
            LlilExpr n_ne_v = make_bool_op(LlilOp::kNe, n, v);
            return make_bool_op(LlilOp::kOr, z, n_ne_v);
        }
        case ARM64_CC_AL:
            return make_imm(1, 1);
        case ARM64_CC_NV:
            return make_imm(0, 1);
        default:
            return make_imm(0, 1);
    }
}

std::string trim_copy(const std::string& input) {
    std::size_t start = 0;
    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start]))) {
        ++start;
    }
    std::size_t end = input.size();
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) {
        --end;
    }
    return input.substr(start, end - start);
}

std::string sanitize_sysreg_name(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (char ch : raw) {
        const unsigned char uch = static_cast<unsigned char>(ch);
        if (std::isspace(uch) || ch == ',') {
            if (!out.empty() && out.back() != '.') {
                out.push_back('.');
            }
            continue;
        }
        if (ch == '#') {
            continue;
        }
        out.push_back(ch);
    }
    while (!out.empty() && out.back() == '.') {
        out.pop_back();
    }
    if (out.empty()) {
        out = "unknown";
    }
    return out;
}

std::string sysreg_from_op_str(const cs_insn& insn, bool is_read) {
    if (!insn.op_str || insn.op_str[0] == '\0') {
        return {};
    }
    std::string ops = insn.op_str;
    const std::size_t comma = ops.find(',');
    if (comma == std::string::npos) {
        return sanitize_sysreg_name(trim_copy(ops));
    }
    if (is_read) {
        return sanitize_sysreg_name(trim_copy(ops.substr(comma + 1)));
    }
    return sanitize_sysreg_name(trim_copy(ops.substr(0, comma)));
}

std::string sysreg_from_sys_op_str(const cs_insn& insn) {
    if (!insn.op_str || insn.op_str[0] == '\0') {
        return {};
    }
    std::string ops = insn.op_str;
    const std::size_t comma = ops.rfind(',');
    if (comma == std::string::npos) {
        return sanitize_sysreg_name(trim_copy(ops));
    }
    return sanitize_sysreg_name(trim_copy(ops.substr(0, comma)));
}

LlilExpr make_bit_test_expr(LlilExpr reg, std::uint64_t bit, bool invert) {
    std::vector<LlilExpr> shift_args;
    shift_args.push_back(std::move(reg));
    shift_args.push_back(make_imm(bit, 8));
    LlilExpr shifted = make_op(LlilOp::kShr, std::move(shift_args), 8);

    std::vector<LlilExpr> and_args;
    and_args.push_back(std::move(shifted));
    and_args.push_back(make_imm(1, 1));
    LlilExpr masked = make_op(LlilOp::kAnd, std::move(and_args), 1);

    LlilOp op = invert ? LlilOp::kEq : LlilOp::kNe;
    std::vector<LlilExpr> cond_args;
    cond_args.push_back(std::move(masked));
    cond_args.push_back(make_imm(0, 1));
    return make_op(op, std::move(cond_args), 1);
}

LlilExpr make_select_expr(LlilExpr cond, LlilExpr t, LlilExpr f, std::size_t size) {
    std::vector<LlilExpr> args;
    args.push_back(std::move(cond));
    args.push_back(std::move(t));
    args.push_back(std::move(f));
    return make_op(LlilOp::kSelect, std::move(args), size);
}

LlilExpr make_zero_extend(LlilExpr expr, std::size_t bits, std::size_t size) {
    std::uint64_t mask = ~static_cast<std::uint64_t>(0);
    if (bits < 64) {
        mask = (static_cast<std::uint64_t>(1) << bits) - 1;
    }
    std::vector<LlilExpr> args;
    args.push_back(std::move(expr));
    args.push_back(make_imm(mask, size));
    return make_op(LlilOp::kAnd, std::move(args), size);
}

LlilExpr make_sign_extend(LlilExpr expr, std::size_t bits, std::size_t size) {
    const std::size_t width = size * 8;
    if (bits >= width) {
        return expr;
    }
    const std::size_t shift = width - bits;
    std::vector<LlilExpr> shl_args;
    shl_args.push_back(expr);
    shl_args.push_back(make_imm(shift, 8));
    LlilExpr shifted = make_op(LlilOp::kShl, std::move(shl_args), size);
    std::vector<LlilExpr> sar_args;
    sar_args.push_back(std::move(shifted));
    sar_args.push_back(make_imm(shift, 8));
    return make_op(LlilOp::kSar, std::move(sar_args), size);
}

}  // namespace

void lift_instruction(csh handle, const cs_insn& insn, Instruction& out) {
    out.llil.clear();
    out.llil_ssa.clear();

    if (!insn.detail) {
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kNop;
        stmt.comment = insn.mnemonic ? insn.mnemonic : "";
        out.llil.push_back(std::move(stmt));
        return;
    }

    const cs_arm64& arm = insn.detail->arm64;
    const arm64_insn id = static_cast<arm64_insn>(insn.id);
    const std::string mnemonic = insn.mnemonic ? insn.mnemonic : "";

    if (id == ARM64_INS_RET) {
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kRet;
        stmt.expr = make_pseudo_reg("x0", 8);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_NOP) {
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kNop;
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_B) {
        if (arm.cc != ARM64_CC_INVALID && arm.cc != ARM64_CC_AL) {
            LlilStmt stmt;
            stmt.kind = LlilStmtKind::kCJump;
            stmt.condition = make_cmp_cond_expr(arm.cc);
            if (arm.op_count >= 1) {
                stmt.target = operand_to_expr(handle, arm.operands[0], 8);
            }
            stmt.comment = mnemonic;
            out.llil.push_back(std::move(stmt));
        } else {
            LlilStmt stmt;
            stmt.kind = LlilStmtKind::kJump;
            if (arm.op_count >= 1) {
                stmt.target = operand_to_expr(handle, arm.operands[0], 8);
            }
            out.llil.push_back(std::move(stmt));
        }
        return;
    }

    if (id == ARM64_INS_BR) {
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kJump;
        if (arm.op_count >= 1) {
            stmt.target = operand_to_expr(handle, arm.operands[0], 8);
        }
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_BL || id == ARM64_INS_BLR) {
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kCall;
        if (arm.op_count >= 1) {
            stmt.target = operand_to_expr(handle, arm.operands[0], 8);
        }
        const auto& cc = engine::arch::arm64::aapcs64();
        stmt.args.reserve(cc.int_args.size() + cc.float_args.size());
        for (const auto& name : cc.int_args) {
            stmt.args.push_back(make_pseudo_reg(name, reg_size_from_name(name)));
        }
        for (const auto& name : cc.float_args) {
            stmt.args.push_back(make_pseudo_reg(name, reg_size_from_name(name)));
        }
        if (!cc.int_return.empty()) {
            RegRef ret;
            ret.name = cc.int_return;
            stmt.returns.push_back(std::move(ret));
        }
        if (!cc.float_return.empty()) {
            RegRef ret;
            ret.name = cc.float_return;
            stmt.returns.push_back(std::move(ret));
        }
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_CBZ || id == ARM64_INS_CBNZ) {
        if (arm.op_count >= 2) {
            LlilStmt stmt;
            stmt.kind = LlilStmtKind::kCJump;
            LlilExpr reg = operand_to_expr(handle, arm.operands[0], 0);
            LlilExpr zero = make_imm(0, reg.size);
            LlilOp op = (id == ARM64_INS_CBZ) ? LlilOp::kEq : LlilOp::kNe;
            std::vector<LlilExpr> cond_args;
            cond_args.push_back(std::move(reg));
            cond_args.push_back(std::move(zero));
            stmt.condition = make_op(op, std::move(cond_args), 1);
            stmt.target = operand_to_expr(handle, arm.operands[1], 8);
            out.llil.push_back(std::move(stmt));
            return;
        }
    }

    if (id == ARM64_INS_TBZ || id == ARM64_INS_TBNZ) {
        if (arm.op_count >= 3) {
            LlilStmt stmt;
            stmt.kind = LlilStmtKind::kCJump;
            LlilExpr reg = operand_to_expr(handle, arm.operands[0], 8);
            const std::uint64_t bit = static_cast<std::uint64_t>(arm.operands[1].imm);
            const bool invert = (id == ARM64_INS_TBZ);
            stmt.condition = make_bit_test_expr(std::move(reg), bit, invert);
            stmt.target = operand_to_expr(handle, arm.operands[2], 8);
            out.llil.push_back(std::move(stmt));
            return;
        }
    }

    if (id == ARM64_INS_ADR || id == ARM64_INS_ADRP) {
        if (arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG && arm.operands[1].type == ARM64_OP_IMM) {
            const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
            LlilStmt stmt;
            stmt.kind = LlilStmtKind::kSetReg;
            stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
            stmt.expr = make_imm(static_cast<std::uint64_t>(arm.operands[1].imm), reg_size);
            out.llil.push_back(std::move(stmt));
            return;
        }
    }

    if (id == ARM64_INS_MOV) {
        if (arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
            const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
            LlilStmt stmt;
            stmt.kind = LlilStmtKind::kSetReg;
            stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
            stmt.expr = operand_to_expr_shifted(handle, arm.operands[1], reg_size);
            out.llil.push_back(std::move(stmt));
            return;
        }
    }

    if ((id == ARM64_INS_MOVZ || id == ARM64_INS_MOVK || id == ARM64_INS_MOVN) && arm.op_count >= 2 &&
        arm.operands[0].type == ARM64_OP_REG && arm.operands[1].type == ARM64_OP_IMM) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        const std::uint64_t imm = static_cast<std::uint64_t>(arm.operands[1].imm) & 0xffffu;
        const std::uint32_t shift = get_shift_value(arm.operands[1]);
        const std::uint64_t imm_shifted = imm << shift;
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        if (id == ARM64_INS_MOVZ) {
            stmt.expr = make_imm(imm_shifted, reg_size);
        } else if (id == ARM64_INS_MOVN) {
            std::vector<LlilExpr> args;
            args.push_back(make_imm(imm_shifted, reg_size));
            stmt.expr = make_op(LlilOp::kNot, std::move(args), reg_size);
        } else {
            const std::uint64_t mask = 0xffffu;
            const std::uint64_t field_mask = mask << shift;
            std::vector<LlilExpr> and_args;
            and_args.push_back(make_reg(handle, arm.operands[0].reg, reg_size));
            and_args.push_back(make_imm(~field_mask, reg_size));
            LlilExpr cleared = make_op(LlilOp::kAnd, std::move(and_args), reg_size);

            std::vector<LlilExpr> or_args;
            or_args.push_back(std::move(cleared));
            or_args.push_back(make_imm(imm_shifted, reg_size));
            stmt.expr = make_op(LlilOp::kOr, std::move(or_args), reg_size);
        }
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_UXTB || id == ARM64_INS_UXTH || id == ARM64_INS_UXTW || id == ARM64_INS_SXTB ||
         id == ARM64_INS_SXTH || id == ARM64_INS_SXTW) &&
        arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr src = operand_to_expr_shifted(handle, arm.operands[1], reg_size);
        std::size_t bits = 32;
        if (id == ARM64_INS_UXTB || id == ARM64_INS_SXTB) {
            bits = 8;
        } else if (id == ARM64_INS_UXTH || id == ARM64_INS_SXTH) {
            bits = 16;
        }
        LlilExpr expr = src;
        if (id == ARM64_INS_UXTB || id == ARM64_INS_UXTH || id == ARM64_INS_UXTW) {
            expr = make_zero_extend(std::move(src), bits, reg_size);
        } else {
            expr = make_sign_extend(std::move(src), bits, reg_size);
        }
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_MVN && arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        LlilExpr src = operand_to_expr_shifted(handle, arm.operands[1], reg_size);
        std::vector<LlilExpr> args;
        args.push_back(std::move(src));
        stmt.expr = make_op(LlilOp::kNot, std::move(args), reg_size);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_NEG && arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        LlilExpr src = operand_to_expr_shifted(handle, arm.operands[1], reg_size);
        std::vector<LlilExpr> args;
        args.push_back(std::move(src));
        stmt.expr = make_op(LlilOp::kNeg, std::move(args), reg_size);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_ADD || id == ARM64_INS_SUB || id == ARM64_INS_ADDS || id == ARM64_INS_SUBS ||
         id == ARM64_INS_ADC || id == ARM64_INS_ADCS || id == ARM64_INS_SBC || id == ARM64_INS_SBCS) &&
        arm.op_count >= 3 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        LlilExpr lhs = operand_to_expr_shifted(handle, arm.operands[1], reg_size);
        LlilExpr rhs = operand_to_expr_shifted(handle, arm.operands[2], reg_size);
        const bool is_add = (id == ARM64_INS_ADD || id == ARM64_INS_ADDS || id == ARM64_INS_ADC ||
                             id == ARM64_INS_ADCS);
        const bool uses_carry = (id == ARM64_INS_ADC || id == ARM64_INS_ADCS || id == ARM64_INS_SBC ||
                                 id == ARM64_INS_SBCS);
        LlilExpr rhs_for_flags = rhs;
        LlilExpr carry_expr;
        carry_expr.kind = LlilExprKind::kInvalid;
        LlilExpr expr;
        if (uses_carry) {
            LlilExpr carry_in = make_zero_extend(make_flag_expr(kFlagC), 1, reg_size);
            if (is_add) {
                LlilExpr sum = make_op(LlilOp::kAdd, {lhs, rhs}, reg_size);
                expr = make_op(LlilOp::kAdd, {sum, carry_in}, reg_size);
                carry_expr = carry_in;
            } else {
                LlilExpr borrow = make_op(LlilOp::kSub, {make_imm(1, reg_size), carry_in}, reg_size);
                rhs_for_flags = make_op(LlilOp::kAdd, {rhs, borrow}, reg_size);
                expr = make_op(LlilOp::kSub, {lhs, rhs_for_flags}, reg_size);
            }
        } else {
            LlilOp op = is_add ? LlilOp::kAdd : LlilOp::kSub;
            expr = make_op(op, {lhs, rhs}, reg_size);
        }
        stmt.expr = expr;
        out.llil.push_back(std::move(stmt));
        if (id == ARM64_INS_ADDS || id == ARM64_INS_SUBS || id == ARM64_INS_ADCS || id == ARM64_INS_SBCS) {
            if (is_add) {
                emit_nzcv_add(out, lhs, rhs, expr, carry_expr, reg_size);
            } else {
                emit_nzcv_sub(out, lhs, rhs_for_flags, expr, reg_size);
            }
        }
        return;
    }

    if ((id == ARM64_INS_SDIV || id == ARM64_INS_UDIV) && arm.op_count >= 3 &&
        arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr lhs = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilExpr rhs = operand_to_expr(handle, arm.operands[2], reg_size);
        std::vector<LlilExpr> args;
        args.push_back(std::move(lhs));
        args.push_back(std::move(rhs));
        LlilExpr expr = make_op(LlilOp::kDiv, std::move(args), reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_AND || id == ARM64_INS_ANDS || id == ARM64_INS_ORR || id == ARM64_INS_EOR ||
         id == ARM64_INS_BIC || id == ARM64_INS_ORN) &&
        arm.op_count >= 3 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilOp op = LlilOp::kAnd;
        if (id == ARM64_INS_ORR) {
            op = LlilOp::kOr;
        } else if (id == ARM64_INS_EOR) {
            op = LlilOp::kXor;
        }
        LlilExpr lhs = operand_to_expr_shifted(handle, arm.operands[1], reg_size);
        LlilExpr rhs = operand_to_expr_shifted(handle, arm.operands[2], reg_size);
        if (id == ARM64_INS_BIC || id == ARM64_INS_ORN) {
            std::vector<LlilExpr> not_args;
            not_args.push_back(std::move(rhs));
            rhs = make_op(LlilOp::kNot, std::move(not_args), reg_size);
            if (id == ARM64_INS_ORN) {
                op = LlilOp::kOr;
            } else {
                op = LlilOp::kAnd;
            }
        }
        std::vector<LlilExpr> args;
        args.push_back(std::move(lhs));
        args.push_back(std::move(rhs));
        LlilExpr expr = make_op(op, std::move(args), reg_size);

        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = expr;
        out.llil.push_back(std::move(stmt));

        if (id == ARM64_INS_ANDS) {
            emit_nzcv_logic(out, expr, reg_size);
        }
        return;
    }

    if ((id == ARM64_INS_LSL || id == ARM64_INS_LSR || id == ARM64_INS_ASR || id == ARM64_INS_ROR) &&
        arm.op_count >= 3 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilOp op = LlilOp::kShl;
        if (id == ARM64_INS_LSR) {
            op = LlilOp::kShr;
        } else if (id == ARM64_INS_ASR) {
            op = LlilOp::kSar;
        } else if (id == ARM64_INS_ROR) {
            op = LlilOp::kRor;
        }
        LlilExpr lhs = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilExpr rhs = operand_to_expr(handle, arm.operands[2], reg_size);
        std::vector<LlilExpr> args;
        args.push_back(std::move(lhs));
        args.push_back(std::move(rhs));
        LlilExpr expr = make_op(op, std::move(args), reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = expr;
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_MUL || id == ARM64_INS_MADD || id == ARM64_INS_MSUB) && arm.op_count >= 3 &&
        arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr lhs = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilExpr rhs = operand_to_expr(handle, arm.operands[2], reg_size);
        LlilExpr mul_expr;
        {
            std::vector<LlilExpr> args;
            args.push_back(std::move(lhs));
            args.push_back(std::move(rhs));
            mul_expr = make_op(LlilOp::kMul, std::move(args), reg_size);
        }
        LlilExpr final_expr = mul_expr;
        if ((id == ARM64_INS_MADD || id == ARM64_INS_MSUB) && arm.op_count >= 4) {
            LlilExpr acc = operand_to_expr(handle, arm.operands[3], reg_size);
            std::vector<LlilExpr> args;
            args.push_back(std::move(mul_expr));
            args.push_back(std::move(acc));
            LlilOp op = (id == ARM64_INS_MADD) ? LlilOp::kAdd : LlilOp::kSub;
            final_expr = make_op(op, std::move(args), reg_size);
        }
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(final_expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_CMP || id == ARM64_INS_CMN || id == ARM64_INS_TST) && arm.op_count >= 2) {
        std::size_t cmp_size = 8;
        if (arm.operands[0].type == ARM64_OP_REG) {
            cmp_size = reg_size_from_name(handle, arm.operands[0].reg);
        }
        LlilExpr lhs = operand_to_expr_shifted(handle, arm.operands[0], cmp_size);
        LlilExpr rhs = operand_to_expr_shifted(handle, arm.operands[1], cmp_size);
        LlilOp op = LlilOp::kSub;
        if (id == ARM64_INS_CMN) {
            op = LlilOp::kAdd;
        } else if (id == ARM64_INS_TST) {
            op = LlilOp::kAnd;
        }
        LlilExpr result = make_op(op, {lhs, rhs}, cmp_size);
        if (id == ARM64_INS_TST) {
            emit_nzcv_logic(out, result, cmp_size);
        } else if (id == ARM64_INS_CMN) {
            LlilExpr invalid;
            invalid.kind = LlilExprKind::kInvalid;
            emit_nzcv_add(out, lhs, rhs, result, invalid, cmp_size);
        } else {
            emit_nzcv_sub(out, lhs, rhs, result, cmp_size);
        }
        return;
    }

    if ((id == ARM64_INS_CCMP || id == ARM64_INS_CCMN) && arm.op_count >= 2) {
        std::size_t cmp_size = 8;
        if (arm.operands[0].type == ARM64_OP_REG) {
            cmp_size = reg_size_from_name(handle, arm.operands[0].reg);
        }
        LlilExpr lhs = operand_to_expr_shifted(handle, arm.operands[0], cmp_size);
        LlilExpr rhs = operand_to_expr_shifted(handle, arm.operands[1], cmp_size);
        const bool is_add = (id == ARM64_INS_CCMN);
        LlilExpr result = make_op(is_add ? LlilOp::kAdd : LlilOp::kSub, {lhs, rhs}, cmp_size);
        LlilExpr invalid;
        invalid.kind = LlilExprKind::kInvalid;
        FlagExpr cmp_flags = is_add ? make_flags_from_add(lhs, rhs, result, invalid, cmp_size)
                                    : make_flags_from_sub(lhs, rhs, result, cmp_size);
        std::uint8_t nzcv = 0;
        FlagExpr imm_flags = make_flags_from_nzcv(0);
        if (extract_nzcv_imm(arm, nzcv)) {
            imm_flags = make_flags_from_nzcv(nzcv);
        }
        LlilExpr cond = (arm.cc == ARM64_CC_INVALID) ? make_imm(1, 1) : make_cmp_cond_expr(arm.cc);
        emit_flag_set(out, kFlagN, make_select_expr(cond, cmp_flags.n, imm_flags.n, 1));
        emit_flag_set(out, kFlagZ, make_select_expr(cond, cmp_flags.z, imm_flags.z, 1));
        emit_flag_set(out, kFlagC, make_select_expr(cond, cmp_flags.c, imm_flags.c, 1));
        emit_flag_set(out, kFlagV, make_select_expr(cond, cmp_flags.v, imm_flags.v, 1));
        return;
    }

    if ((id == ARM64_INS_CSEL || id == ARM64_INS_CSINC || id == ARM64_INS_CSINV || id == ARM64_INS_CSNEG) &&
        arm.op_count >= 3 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr cond = make_cmp_cond_expr(arm.cc);
        LlilExpr t = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilExpr f = operand_to_expr(handle, arm.operands[2], reg_size);
        if (id == ARM64_INS_CSINC) {
            std::vector<LlilExpr> args;
            args.push_back(std::move(f));
            args.push_back(make_imm(1, reg_size));
            f = make_op(LlilOp::kAdd, std::move(args), reg_size);
        } else if (id == ARM64_INS_CSINV) {
            std::vector<LlilExpr> args;
            args.push_back(std::move(f));
            f = make_op(LlilOp::kNot, std::move(args), reg_size);
        } else if (id == ARM64_INS_CSNEG) {
            std::vector<LlilExpr> args;
            args.push_back(std::move(f));
            f = make_op(LlilOp::kNeg, std::move(args), reg_size);
        }
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = make_select_expr(std::move(cond), std::move(t), std::move(f), reg_size);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_CINC || id == ARM64_INS_CINV || id == ARM64_INS_CNEG) && arm.op_count >= 2 &&
        arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr cond = make_cmp_cond_expr(arm.cc);
        LlilExpr src = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilExpr t = src;
        if (id == ARM64_INS_CINC) {
            t = make_op(LlilOp::kAdd, {src, make_imm(1, reg_size)}, reg_size);
        } else if (id == ARM64_INS_CINV) {
            t = make_op(LlilOp::kNot, {src}, reg_size);
        } else if (id == ARM64_INS_CNEG) {
            t = make_op(LlilOp::kNeg, {src}, reg_size);
        }
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = make_select_expr(std::move(cond), std::move(t), std::move(src), reg_size);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_CSET || id == ARM64_INS_CSETM) && arm.op_count >= 1 &&
        arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr cond = make_cmp_cond_expr(arm.cc);
        LlilExpr t = make_imm(1, reg_size);
        LlilExpr f = make_imm(0, reg_size);
        if (id == ARM64_INS_CSETM) {
            t = make_imm(~static_cast<std::uint64_t>(0), reg_size);
        }
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = make_select_expr(std::move(cond), std::move(t), std::move(f), reg_size);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_BFI || id == ARM64_INS_BFXIL || id == ARM64_INS_UBFX || id == ARM64_INS_SBFX) {
        if (arm.op_count >= 4 && arm.operands[0].type == ARM64_OP_REG) {
            const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
            LlilExpr dst = make_reg(handle, arm.operands[0].reg, reg_size);
            LlilExpr src = operand_to_expr(handle, arm.operands[1], reg_size);
            std::uint64_t lsb = static_cast<std::uint64_t>(arm.operands[2].imm);
            std::uint64_t width = static_cast<std::uint64_t>(arm.operands[3].imm);
            const std::size_t total_bits = (reg_size == 0) ? 64 : (reg_size * 8);
            if (lsb >= total_bits) {
                LlilStmt stmt;
                stmt.kind = LlilStmtKind::kSetReg;
                stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
                if (id == ARM64_INS_UBFX || id == ARM64_INS_SBFX) {
                    stmt.expr = make_imm(0, reg_size);
                } else {
                    stmt.expr = dst;
                }
                out.llil.push_back(std::move(stmt));
                return;
            }
            if (width > (total_bits - lsb)) {
                width = static_cast<std::uint64_t>(total_bits - lsb);
            }
            if (width == 0) {
                LlilStmt stmt;
                stmt.kind = LlilStmtKind::kSetReg;
                stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
                if (id == ARM64_INS_UBFX || id == ARM64_INS_SBFX) {
                    stmt.expr = make_imm(0, reg_size);
                } else {
                    stmt.expr = dst;
                }
                out.llil.push_back(std::move(stmt));
                return;
            }
            const std::uint64_t mask = (width >= 64) ? ~static_cast<std::uint64_t>(0)
                                                     : ((static_cast<std::uint64_t>(1) << width) - 1);
            if (id == ARM64_INS_UBFX || id == ARM64_INS_SBFX) {
                std::vector<LlilExpr> shift_args;
                shift_args.push_back(std::move(src));
                shift_args.push_back(make_imm(lsb, 8));
                LlilExpr shifted = make_op(LlilOp::kShr, std::move(shift_args), reg_size);
                LlilExpr masked = make_zero_extend(std::move(shifted), static_cast<std::size_t>(width), reg_size);
                if (id == ARM64_INS_SBFX) {
                    masked = make_sign_extend(std::move(masked), static_cast<std::size_t>(width), reg_size);
                }
                LlilStmt stmt;
                stmt.kind = LlilStmtKind::kSetReg;
                stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
                stmt.expr = std::move(masked);
                out.llil.push_back(std::move(stmt));
                return;
            }
            std::vector<LlilExpr> shift_args;
            shift_args.push_back(std::move(src));
            shift_args.push_back(make_imm(lsb, 8));
            LlilExpr shifted = make_op(LlilOp::kShl, std::move(shift_args), reg_size);

            std::vector<LlilExpr> mask_args;
            mask_args.push_back(std::move(shifted));
            mask_args.push_back(make_imm(mask << lsb, reg_size));
            LlilExpr masked = make_op(LlilOp::kAnd, std::move(mask_args), reg_size);

            std::vector<LlilExpr> clear_args;
            clear_args.push_back(std::move(dst));
            clear_args.push_back(make_imm(~(mask << lsb), reg_size));
            LlilExpr cleared = make_op(LlilOp::kAnd, std::move(clear_args), reg_size);

            std::vector<LlilExpr> or_args;
            or_args.push_back(std::move(cleared));
            or_args.push_back(std::move(masked));
            LlilExpr expr = make_op(LlilOp::kOr, std::move(or_args), reg_size);

            LlilStmt stmt;
            stmt.kind = LlilStmtKind::kSetReg;
            stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
            stmt.expr = std::move(expr);
            out.llil.push_back(std::move(stmt));
            return;
        }
    }

    if (id == ARM64_INS_EXTR && arm.op_count >= 4 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr src1 = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilExpr src2 = operand_to_expr(handle, arm.operands[2], reg_size);
        std::uint64_t lsb = static_cast<std::uint64_t>(arm.operands[3].imm);
        std::uint64_t width = reg_size * 8;
        if (width == 0) {
            width = 64;
        }
        if (lsb >= width) {
            lsb = width - 1;
        }
        std::vector<LlilExpr> right_args;
        right_args.push_back(std::move(src2));
        right_args.push_back(make_imm(lsb, 8));
        LlilExpr right = make_op(LlilOp::kShr, std::move(right_args), reg_size);

        std::vector<LlilExpr> left_args;
        left_args.push_back(std::move(src1));
        LlilExpr left;
        if (lsb == 0) {
            left = make_imm(0, reg_size);
        } else {
            left_args.push_back(make_imm(width - lsb, 8));
            left = make_op(LlilOp::kShl, std::move(left_args), reg_size);
        }

        std::vector<LlilExpr> or_args;
        or_args.push_back(std::move(left));
        or_args.push_back(std::move(right));
        LlilExpr expr = make_op(LlilOp::kOr, std::move(or_args), reg_size);

        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_RBIT && arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        std::vector<LlilExpr> args;
        args.push_back(operand_to_expr(handle, arm.operands[1], reg_size));
        LlilExpr expr = make_op(LlilOp::kRbit, std::move(args), reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_CLZ && arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        std::vector<LlilExpr> args;
        args.push_back(operand_to_expr(handle, arm.operands[1], reg_size));
        LlilExpr expr = make_op(LlilOp::kClz, std::move(args), reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_REV || id == ARM64_INS_REV16 || id == ARM64_INS_REV32 || id == ARM64_INS_REV64) &&
        arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        std::vector<LlilExpr> args;
        args.push_back(operand_to_expr(handle, arm.operands[1], reg_size));
        LlilExpr expr = make_op(LlilOp::kBswap, std::move(args), reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_FMOV && arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = operand_to_expr(handle, arm.operands[1], reg_size);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_FADD || id == ARM64_INS_FSUB || id == ARM64_INS_FMUL || id == ARM64_INS_FDIV ||
         id == ARM64_INS_FMAX || id == ARM64_INS_FMAXNM || id == ARM64_INS_FMIN || id == ARM64_INS_FMINNM) &&
        arm.op_count >= 3 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilOp op = LlilOp::kAdd;
        if (id == ARM64_INS_FSUB) {
            op = LlilOp::kSub;
        } else if (id == ARM64_INS_FMUL) {
            op = LlilOp::kMul;
        } else if (id == ARM64_INS_FDIV) {
            op = LlilOp::kDiv;
        } else if (id == ARM64_INS_FMIN || id == ARM64_INS_FMINNM) {
            op = LlilOp::kMin;
        } else if (id == ARM64_INS_FMAX || id == ARM64_INS_FMAXNM) {
            op = LlilOp::kMax;
        }
        LlilExpr lhs = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilExpr rhs = operand_to_expr(handle, arm.operands[2], reg_size);
        std::vector<LlilExpr> args;
        args.push_back(std::move(lhs));
        args.push_back(std::move(rhs));
        LlilExpr expr = make_op(op, std::move(args), reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_FABS || id == ARM64_INS_FNEG) && arm.op_count >= 2 &&
        arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr src = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilOp op = (id == ARM64_INS_FABS) ? LlilOp::kAbs : LlilOp::kNeg;
        std::vector<LlilExpr> args;
        args.push_back(std::move(src));
        LlilExpr expr = make_op(op, std::move(args), reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_FSQRT && arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        std::vector<LlilExpr> args;
        args.push_back(operand_to_expr(handle, arm.operands[1], reg_size));
        LlilExpr expr = make_op(LlilOp::kSqrt, std::move(args), reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_FCVT || id == ARM64_INS_FCVTZS || id == ARM64_INS_FCVTZU || id == ARM64_INS_FCVTAS ||
         id == ARM64_INS_FCVTAU || id == ARM64_INS_SCVTF || id == ARM64_INS_UCVTF || id == ARM64_INS_FCVTN ||
         id == ARM64_INS_FCVTNS || id == ARM64_INS_FCVTNU || id == ARM64_INS_FCVTMS || id == ARM64_INS_FCVTMU ||
         id == ARM64_INS_FCVTPS || id == ARM64_INS_FCVTPU) &&
        arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr src = operand_to_expr(handle, arm.operands[1], reg_size);
        std::vector<LlilExpr> args;
        args.push_back(std::move(src));
        LlilExpr expr = make_op(LlilOp::kCast, std::move(args), reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_FCMP || id == ARM64_INS_FCMPE) && arm.op_count >= 2) {
        std::size_t cmp_size = 8;
        if (arm.operands[0].type == ARM64_OP_REG) {
            cmp_size = reg_size_from_name(handle, arm.operands[0].reg);
        }
        LlilExpr lhs = operand_to_expr(handle, arm.operands[0], cmp_size);
        LlilExpr rhs = operand_to_expr(handle, arm.operands[1], cmp_size);
        LlilExpr result = make_op(LlilOp::kSub, {lhs, rhs}, cmp_size);
        emit_nzcv_sub(out, lhs, rhs, result, cmp_size);
        return;
    }

    if ((id == ARM64_INS_FCCMP || id == ARM64_INS_FCCMPE) && arm.op_count >= 2) {
        std::size_t cmp_size = 8;
        if (arm.operands[0].type == ARM64_OP_REG) {
            cmp_size = reg_size_from_name(handle, arm.operands[0].reg);
        }
        LlilExpr lhs = operand_to_expr(handle, arm.operands[0], cmp_size);
        LlilExpr rhs = operand_to_expr(handle, arm.operands[1], cmp_size);
        LlilExpr result = make_op(LlilOp::kSub, {lhs, rhs}, cmp_size);
        FlagExpr cmp_flags = make_flags_from_sub(lhs, rhs, result, cmp_size);
        std::uint8_t nzcv = 0;
        FlagExpr imm_flags = make_flags_from_nzcv(0);
        if (extract_nzcv_imm(arm, nzcv)) {
            imm_flags = make_flags_from_nzcv(nzcv);
        }
        LlilExpr cond = (arm.cc == ARM64_CC_INVALID) ? make_imm(1, 1) : make_cmp_cond_expr(arm.cc);
        emit_flag_set(out, kFlagN, make_select_expr(cond, cmp_flags.n, imm_flags.n, 1));
        emit_flag_set(out, kFlagZ, make_select_expr(cond, cmp_flags.z, imm_flags.z, 1));
        emit_flag_set(out, kFlagC, make_select_expr(cond, cmp_flags.c, imm_flags.c, 1));
        emit_flag_set(out, kFlagV, make_select_expr(cond, cmp_flags.v, imm_flags.v, 1));
        return;
    }

    if (id == ARM64_INS_FMLA || id == ARM64_INS_FMLS || id == ARM64_INS_FMADD || id == ARM64_INS_FNMADD ||
        id == ARM64_INS_FMSUB || id == ARM64_INS_FNMSUB) {
        if (arm.op_count >= 4 && arm.operands[0].type == ARM64_OP_REG) {
            const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
            LlilExpr lhs = operand_to_expr(handle, arm.operands[1], reg_size);
            LlilExpr rhs = operand_to_expr(handle, arm.operands[2], reg_size);
            LlilExpr acc = operand_to_expr(handle, arm.operands[3], reg_size);
            std::vector<LlilExpr> mul_args;
            mul_args.push_back(std::move(lhs));
            mul_args.push_back(std::move(rhs));
            LlilExpr mul_expr = make_op(LlilOp::kMul, std::move(mul_args), reg_size);

            LlilOp op = LlilOp::kAdd;
            if (id == ARM64_INS_FMLS || id == ARM64_INS_FMSUB || id == ARM64_INS_FNMADD) {
                op = LlilOp::kSub;
            }
            std::vector<LlilExpr> args;
            args.push_back(std::move(mul_expr));
            args.push_back(std::move(acc));
            LlilExpr expr = make_op(op, std::move(args), reg_size);
            if (id == ARM64_INS_FNMADD || id == ARM64_INS_FNMSUB) {
                std::vector<LlilExpr> neg_args;
                neg_args.push_back(std::move(expr));
                expr = make_op(LlilOp::kNeg, std::move(neg_args), reg_size);
            }
            LlilStmt stmt;
            stmt.kind = LlilStmtKind::kSetReg;
            stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
            stmt.expr = std::move(expr);
            out.llil.push_back(std::move(stmt));
            return;
        }
    }

    if (is_atomic_load(id) && arm.op_count >= 2 &&
        arm.operands[0].type == ARM64_OP_REG && arm.operands[1].type == ARM64_OP_MEM) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        const std::size_t mem_size = atomic_mem_size(id, reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = operand_to_expr(handle, arm.operands[1], mem_size);
        stmt.comment = mnemonic;
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (is_atomic_store(id) && arm.op_count >= 3 &&
        arm.operands[0].type == ARM64_OP_REG && arm.operands[1].type == ARM64_OP_REG &&
        arm.operands[2].type == ARM64_OP_MEM) {
        const std::size_t value_size = reg_size_from_name(handle, arm.operands[1].reg);
        const std::size_t mem_size = atomic_mem_size(id, value_size);
        LlilStmt store;
        store.kind = LlilStmtKind::kStore;
        store.target = build_mem_address(handle, arm.operands[2].mem);
        store.expr = make_reg(handle, arm.operands[1].reg, mem_size);
        store.comment = mnemonic;
        out.llil.push_back(std::move(store));

        const std::size_t status_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilStmt status;
        status.kind = LlilStmtKind::kSetReg;
        status.reg = make_reg(handle, arm.operands[0].reg, status_size).reg;
        status.expr = make_imm(0, status_size);
        status.comment = mnemonic;
        out.llil.push_back(std::move(status));
        return;
    }

    if (is_atomic_swap(id) && arm.op_count >= 3 && arm.operands[0].type == ARM64_OP_REG &&
        arm.operands[1].type == ARM64_OP_REG && arm.operands[2].type == ARM64_OP_MEM) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        const std::size_t mem_size = atomic_mem_size(id, reg_size);
        LlilExpr addr = build_mem_address(handle, arm.operands[2].mem);
        LlilExpr loaded = make_load(addr, mem_size);

        LlilStmt store;
        store.kind = LlilStmtKind::kStore;
        store.target = addr;
        store.expr = make_reg(handle, arm.operands[1].reg, mem_size);
        store.comment = mnemonic;
        out.llil.push_back(std::move(store));

        LlilStmt set;
        set.kind = LlilStmtKind::kSetReg;
        set.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        set.expr = loaded;
        set.comment = mnemonic;
        out.llil.push_back(std::move(set));
        return;
    }

    if (is_atomic_compare_swap(id) && arm.op_count >= 3 && arm.operands[0].type == ARM64_OP_REG &&
        arm.operands[1].type == ARM64_OP_REG && arm.operands[2].type == ARM64_OP_MEM) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        const std::size_t mem_size = atomic_mem_size(id, reg_size);
        LlilExpr addr = build_mem_address(handle, arm.operands[2].mem);
        LlilExpr loaded = make_load(addr, mem_size);

        LlilStmt store;
        store.kind = LlilStmtKind::kStore;
        store.target = addr;
        store.expr = make_reg(handle, arm.operands[1].reg, mem_size);
        store.comment = mnemonic;
        out.llil.push_back(std::move(store));

        LlilStmt set;
        set.kind = LlilStmtKind::kSetReg;
        set.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        set.expr = loaded;
        set.comment = mnemonic;
        out.llil.push_back(std::move(set));
        return;
    }

    if ((id == ARM64_INS_LDR || id == ARM64_INS_LDRB || id == ARM64_INS_LDRH || id == ARM64_INS_LDRSB ||
         id == ARM64_INS_LDRSH || id == ARM64_INS_LDRSW || id == ARM64_INS_LDUR || id == ARM64_INS_LDURB ||
         id == ARM64_INS_LDURH || id == ARM64_INS_LDURSB || id == ARM64_INS_LDURSH || id == ARM64_INS_LDURSW) &&
        arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        const std::size_t mem_size = mem_access_size(id, reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = operand_to_expr(handle, arm.operands[1], mem_size);
        out.llil.push_back(std::move(stmt));
        if (arm.writeback && arm.operands[1].type == ARM64_OP_MEM && arm.operands[1].mem.base != ARM64_REG_INVALID) {
            LlilStmt wb;
            wb.kind = LlilStmtKind::kSetReg;
            wb.reg = make_reg(handle, arm.operands[1].mem.base, 8).reg;
            std::vector<LlilExpr> args;
            args.push_back(make_reg(handle, arm.operands[1].mem.base, 8));
            args.push_back(make_imm(static_cast<std::uint64_t>(arm.operands[1].mem.disp), 8));
            wb.expr = make_op(LlilOp::kAdd, std::move(args), 8);
            out.llil.push_back(std::move(wb));
        }
        return;
    }

    if ((id == ARM64_INS_STR || id == ARM64_INS_STRB || id == ARM64_INS_STRH || id == ARM64_INS_STUR ||
         id == ARM64_INS_STURB || id == ARM64_INS_STURH) &&
        arm.op_count >= 2 && arm.operands[1].type == ARM64_OP_MEM) {
        std::size_t reg_size = 8;
        if (arm.operands[0].type == ARM64_OP_REG) {
            reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        }
        const std::size_t mem_size = mem_access_size(id, reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kStore;
        stmt.target = build_mem_address(handle, arm.operands[1].mem);
        stmt.expr = operand_to_expr(handle, arm.operands[0], mem_size);
        out.llil.push_back(std::move(stmt));
        if (arm.writeback && arm.operands[1].mem.base != ARM64_REG_INVALID) {
            LlilStmt wb;
            wb.kind = LlilStmtKind::kSetReg;
            wb.reg = make_reg(handle, arm.operands[1].mem.base, 8).reg;
            std::vector<LlilExpr> args;
            args.push_back(make_reg(handle, arm.operands[1].mem.base, 8));
            args.push_back(make_imm(static_cast<std::uint64_t>(arm.operands[1].mem.disp), 8));
            wb.expr = make_op(LlilOp::kAdd, std::move(args), 8);
            out.llil.push_back(std::move(wb));
        }
        return;
    }

    if (id == ARM64_INS_SVC || id == ARM64_INS_HVC || id == ARM64_INS_SMC) {
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kCall;
        if (arm.op_count >= 1) {
            stmt.target = operand_to_expr(handle, arm.operands[0], 8);
        }
        stmt.comment = mnemonic;
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_BRK || id == ARM64_INS_HLT || id == ARM64_INS_ERET || id == ARM64_INS_ERETAB ||
        id == ARM64_INS_RETAB || id == ARM64_INS_BTI || id == ARM64_INS_HINT) {
        LlilStmt stmt;
        stmt.kind = (id == ARM64_INS_ERET || id == ARM64_INS_ERETAB || id == ARM64_INS_RETAB) ? LlilStmtKind::kRet
                                                                                              : LlilStmtKind::kNop;
        stmt.comment = mnemonic;
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_MRS || id == ARM64_INS_SYSL) && arm.op_count >= 1 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        std::string sys_name = sysreg_from_op_str(insn, true);
        if (id == ARM64_INS_SYSL) {
            sys_name = std::string("sysl.").append(sys_name.empty() ? "unknown" : sys_name);
        } else {
            sys_name = std::string("sys.").append(sys_name.empty() ? "unknown" : sys_name);
        }
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = make_pseudo_reg(sys_name, reg_size);
        stmt.comment = mnemonic;
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_MSR || id == ARM64_INS_SYS) {
        std::string sys_name;
        if (id == ARM64_INS_SYS) {
            sys_name = sysreg_from_sys_op_str(insn);
            sys_name = std::string("sys.").append(sys_name.empty() ? "unknown" : sys_name);
        } else {
            sys_name = sysreg_from_op_str(insn, false);
            const bool is_pstate = (arm.op_count >= 1 && arm.operands[0].type == ARM64_OP_PSTATE);
            const std::string prefix = is_pstate ? "pstate." : "sys.";
            sys_name = prefix + (sys_name.empty() ? "unknown" : sys_name);
        }
        LlilExpr value = {};
        if (arm.op_count >= 2) {
            value = operand_to_expr(handle, arm.operands[arm.op_count - 1], 8);
            if (value.kind == LlilExprKind::kInvalid) {
                value = make_imm(0, 8);
            }
        } else {
            value = make_imm(0, 8);
        }
        const std::size_t value_size = value.size ? value.size : 8;
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_pseudo_reg(sys_name, value_size).reg;
        stmt.expr = std::move(value);
        stmt.comment = mnemonic;
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_DMB || id == ARM64_INS_DSB || id == ARM64_INS_ISB || id == ARM64_INS_CLREX ||
        id == ARM64_INS_SEV || id == ARM64_INS_WFE || id == ARM64_INS_WFI) {
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kNop;
        stmt.comment = mnemonic;
        out.llil.push_back(std::move(stmt));
        return;
    }

    if ((id == ARM64_INS_LDP || id == ARM64_INS_LDNP || id == ARM64_INS_STP || id == ARM64_INS_STNP) &&
        arm.op_count >= 3 && arm.operands[2].type == ARM64_OP_MEM) {
        const bool is_load = (id == ARM64_INS_LDP || id == ARM64_INS_LDNP);
        const std::size_t reg0_size = arm.operands[0].type == ARM64_OP_REG
                                          ? reg_size_from_name(handle, arm.operands[0].reg)
                                          : 8;
        const std::size_t reg1_size = arm.operands[1].type == ARM64_OP_REG
                                          ? reg_size_from_name(handle, arm.operands[1].reg)
                                          : 8;
        LlilExpr base_addr = build_mem_address(handle, arm.operands[2].mem);
        LlilExpr second_addr;
        {
            std::vector<LlilExpr> args;
            args.push_back(base_addr);
            args.push_back(make_imm(reg0_size, 8));
            second_addr = make_op(LlilOp::kAdd, std::move(args), 8);
        }
        if (is_load) {
            if (arm.operands[0].type == ARM64_OP_REG) {
                LlilStmt stmt;
                stmt.kind = LlilStmtKind::kSetReg;
                stmt.reg = make_reg(handle, arm.operands[0].reg, reg0_size).reg;
                stmt.expr = make_load(base_addr, reg0_size);
                out.llil.push_back(std::move(stmt));
            }
            if (arm.operands[1].type == ARM64_OP_REG) {
                LlilStmt stmt;
                stmt.kind = LlilStmtKind::kSetReg;
                stmt.reg = make_reg(handle, arm.operands[1].reg, reg1_size).reg;
                stmt.expr = make_load(second_addr, reg1_size);
                out.llil.push_back(std::move(stmt));
            }
        } else {
            if (arm.operands[0].type == ARM64_OP_REG) {
                LlilStmt stmt;
                stmt.kind = LlilStmtKind::kStore;
                stmt.target = base_addr;
                stmt.expr = make_reg(handle, arm.operands[0].reg, reg0_size);
                out.llil.push_back(std::move(stmt));
            }
            if (arm.operands[1].type == ARM64_OP_REG) {
                LlilStmt stmt;
                stmt.kind = LlilStmtKind::kStore;
                stmt.target = second_addr;
                stmt.expr = make_reg(handle, arm.operands[1].reg, reg1_size);
                out.llil.push_back(std::move(stmt));
            }
        }
        if (arm.writeback && arm.operands[2].mem.base != ARM64_REG_INVALID) {
            LlilStmt wb;
            wb.kind = LlilStmtKind::kSetReg;
            wb.reg = make_reg(handle, arm.operands[2].mem.base, 8).reg;
            std::vector<LlilExpr> args;
            args.push_back(make_reg(handle, arm.operands[2].mem.base, 8));
            args.push_back(make_imm(static_cast<std::uint64_t>(arm.operands[2].mem.disp), 8));
            wb.expr = make_op(LlilOp::kAdd, std::move(args), 8);
            out.llil.push_back(std::move(wb));
        }
        return;
    }

    if ((is_vector_load(id) || is_vector_store(id)) && arm.op_count >= 2) {
        const bool is_load = is_vector_load(id);
        int mem_index = -1;
        for (std::uint8_t i = 0; i < arm.op_count; ++i) {
            if (arm.operands[i].type == ARM64_OP_MEM) {
                mem_index = i;
                break;
            }
        }
        if (mem_index >= 0) {
            LlilExpr base_addr = build_mem_address(handle, arm.operands[mem_index].mem);
            std::uint64_t offset = 0;
            for (std::uint8_t i = 0; i < arm.op_count; ++i) {
                if (i == mem_index || arm.operands[i].type != ARM64_OP_REG) {
                    continue;
                }
                const std::size_t reg_size = reg_size_from_name(handle, arm.operands[i].reg);
                const std::size_t mem_size = vector_mem_size(id, reg_size);
                LlilExpr addr = base_addr;
                if (offset != 0) {
                    addr = make_op(LlilOp::kAdd, {base_addr, make_imm(offset, 8)}, 8);
                }
                if (is_load) {
                    LlilStmt stmt;
                    stmt.kind = LlilStmtKind::kSetReg;
                    stmt.reg = make_reg(handle, arm.operands[i].reg, reg_size).reg;
                    stmt.expr = make_load(addr, mem_size);
                    out.llil.push_back(std::move(stmt));
                } else {
                    LlilStmt stmt;
                    stmt.kind = LlilStmtKind::kStore;
                    stmt.target = addr;
                    stmt.expr = make_reg(handle, arm.operands[i].reg, mem_size);
                    out.llil.push_back(std::move(stmt));
                }
                offset += mem_size;
            }
            if (arm.writeback && arm.operands[mem_index].mem.base != ARM64_REG_INVALID) {
                LlilStmt wb;
                wb.kind = LlilStmtKind::kSetReg;
                wb.reg = make_reg(handle, arm.operands[mem_index].mem.base, 8).reg;
                std::vector<LlilExpr> args;
                args.push_back(make_reg(handle, arm.operands[mem_index].mem.base, 8));
                args.push_back(make_imm(static_cast<std::uint64_t>(arm.operands[mem_index].mem.disp), 8));
                wb.expr = make_op(LlilOp::kAdd, std::move(args), 8);
                out.llil.push_back(std::move(wb));
            }
            return;
        }
    }

    if ((id == ARM64_INS_EXT || id == ARM64_INS_ZIP1 || id == ARM64_INS_ZIP2 || id == ARM64_INS_UZP1 ||
         id == ARM64_INS_UZP2 || id == ARM64_INS_TRN1 || id == ARM64_INS_TRN2 || id == ARM64_INS_TBL) &&
        arm.op_count >= 3 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr lhs = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilExpr rhs = operand_to_expr(handle, arm.operands[2], reg_size);
        LlilExpr expr = make_op(LlilOp::kOr, {lhs, rhs}, reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    if (id == ARM64_INS_ADDV && arm.op_count >= 2 && arm.operands[0].type == ARM64_OP_REG) {
        const std::size_t reg_size = reg_size_from_name(handle, arm.operands[0].reg);
        LlilExpr src = operand_to_expr(handle, arm.operands[1], reg_size);
        LlilExpr expr = make_op(LlilOp::kCast, {src}, reg_size);
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kSetReg;
        stmt.reg = make_reg(handle, arm.operands[0].reg, reg_size).reg;
        stmt.expr = std::move(expr);
        out.llil.push_back(std::move(stmt));
        return;
    }

    push_unknown_effects(handle, arm, out, mnemonic);
}

}  // namespace engine::llir::arm64
