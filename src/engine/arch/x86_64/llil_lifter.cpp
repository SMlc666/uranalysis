#include "llil_lifter.h"

#include <utility>

namespace engine::llir::x86_64 {

namespace {

LlilExpr make_reg(csh handle, x86_reg reg, std::size_t size) {
    LlilExpr expr;
    expr.kind = LlilExprKind::kReg;
    expr.size = size;
    const char* name = cs_reg_name(handle, reg);
    expr.reg.name = name ? name : "reg";
    return expr;
}

LlilExpr make_imm_zero(std::size_t size) {
    LlilExpr expr;
    expr.kind = LlilExprKind::kImm;
    expr.size = size ? size : 8;
    expr.imm = 0;
    return expr;
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

LlilExpr make_select_expr(LlilExpr cond, LlilExpr t, LlilExpr f, std::size_t size) {
    std::vector<LlilExpr> args;
    args.push_back(std::move(cond));
    args.push_back(std::move(t));
    args.push_back(std::move(f));
    return make_op(LlilOp::kSelect, std::move(args), size);
}

std::size_t op_size(const cs_x86_op& op, std::size_t fallback = 8) {
    if (op.size != 0) {
        return static_cast<std::size_t>(op.size);
    }
    return fallback;
}

LlilExpr build_mem_address(csh handle, const x86_op_mem& mem) {
    LlilExpr addr;
    if (mem.base != X86_REG_INVALID) {
        addr = make_reg(handle, mem.base, 8);
    } else {
        addr = make_imm(0, 8);
    }
    if (mem.index != X86_REG_INVALID) {
        LlilExpr index = make_reg(handle, mem.index, 8);
        if (mem.scale > 1) {
            std::vector<LlilExpr> scale_args;
            scale_args.push_back(std::move(index));
            scale_args.push_back(make_imm(static_cast<std::uint64_t>(mem.scale), 8));
            index = make_op(LlilOp::kMul, std::move(scale_args), 8);
        }
        std::vector<LlilExpr> args;
        args.push_back(std::move(addr));
        args.push_back(std::move(index));
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

LlilExpr operand_value(csh handle, const cs_x86_op& op, std::size_t size) {
    switch (op.type) {
        case X86_OP_REG:
            return make_reg(handle, op.reg, size);
        case X86_OP_IMM:
            return make_imm(static_cast<std::uint64_t>(op.imm), size);
        case X86_OP_MEM: {
            LlilExpr addr = build_mem_address(handle, op.mem);
            return make_load(std::move(addr), size);
        }
        default:
            break;
    }
    return make_imm_zero(size);
}

LlilExpr flag_reg(const char* name) {
    LlilExpr expr;
    expr.kind = LlilExprKind::kReg;
    expr.size = 1;
    expr.reg.name = name;
    return expr;
}

void emit_flag_set(Instruction& out, const char* name, LlilExpr expr) {
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kSetReg;
    stmt.reg.name = name;
    stmt.expr = std::move(expr);
    out.llil.push_back(std::move(stmt));
}

LlilExpr make_bool_op(LlilOp op, LlilExpr lhs, LlilExpr rhs) {
    std::vector<LlilExpr> args;
    args.push_back(std::move(lhs));
    args.push_back(std::move(rhs));
    return make_op(op, std::move(args), 1);
}

LlilExpr make_msb_expr(const LlilExpr& value, std::size_t size) {
    std::size_t width = size;
    if (width == 0) {
        width = value.size;
    }
    if (width == 0) {
        width = 8;
    }
    const std::size_t shift = (width * 8) - 1;
    std::vector<LlilExpr> shift_args;
    shift_args.push_back(value);
    shift_args.push_back(make_imm(shift, 8));
    LlilExpr shifted = make_op(LlilOp::kShr, std::move(shift_args), width);
    std::vector<LlilExpr> and_args;
    and_args.push_back(std::move(shifted));
    and_args.push_back(make_imm(1, 1));
    return make_op(LlilOp::kAnd, std::move(and_args), 1);
}

// Emit ZF and SF flags based on result
void emit_zs_flags(Instruction& out, const LlilExpr& result, std::size_t size) {
    // ZF = (result == 0)
    emit_flag_set(out, "flag_z", make_bool_op(LlilOp::kEq, result, make_imm(0, size)));
    // SF = MSB(result)
    emit_flag_set(out, "flag_s", make_msb_expr(result, size));
}

// Emit flags for SUB/CMP: result = lhs - rhs
void emit_flags_sub(Instruction& out,
                    const LlilExpr& lhs,
                    const LlilExpr& rhs,
                    const LlilExpr& result,
                    std::size_t size) {
    emit_zs_flags(out, result, size);
    // CF = (lhs < rhs) for unsigned subtraction (borrow)
    // Note: Using kLt here; proper unsigned semantics handled at higher IR levels
    emit_flag_set(out, "flag_c", make_bool_op(LlilOp::kLt, lhs, rhs));
    // OF = signed overflow: (lhs_sign != rhs_sign) && (result_sign != lhs_sign)
    LlilExpr n_l = make_msb_expr(lhs, size);
    LlilExpr n_r = make_msb_expr(rhs, size);
    LlilExpr n_res = make_msb_expr(result, size);
    LlilExpr diff_sign = make_bool_op(LlilOp::kNe, n_l, n_r);
    LlilExpr diff_res = make_bool_op(LlilOp::kNe, n_res, n_l);
    emit_flag_set(out, "flag_o", make_bool_op(LlilOp::kAnd, diff_sign, diff_res));
}

// Emit flags for AND/TEST: result = lhs & rhs
void emit_flags_logic(Instruction& out, const LlilExpr& result, std::size_t size) {
    emit_zs_flags(out, result, size);
    // CF = 0, OF = 0 for logical operations
    emit_flag_set(out, "flag_c", make_imm(0, 1));
    emit_flag_set(out, "flag_o", make_imm(0, 1));
}

LlilExpr condition_from_jcc(unsigned int id) {
    // Helper to get flag registers
    auto zf = []() { return flag_reg("flag_z"); };
    auto sf = []() { return flag_reg("flag_s"); };
    auto cf = []() { return flag_reg("flag_c"); };
    auto of = []() { return flag_reg("flag_o"); };
    auto one = []() { return make_imm(1, 1); };

    switch (id) {
        // Zero flag conditions
        case X86_INS_JE:   // ZF == 1
        case X86_INS_SETE:
        case X86_INS_CMOVE:
            return make_op(LlilOp::kEq, {zf(), one()}, 1);
        case X86_INS_JNE:  // ZF == 0
        case X86_INS_SETNE:
        case X86_INS_CMOVNE:
            return make_op(LlilOp::kNe, {zf(), one()}, 1);

        // Sign flag conditions
        case X86_INS_JS:   // SF == 1
        case X86_INS_SETS:
        case X86_INS_CMOVS:
            return make_op(LlilOp::kEq, {sf(), one()}, 1);
        case X86_INS_JNS:  // SF == 0
        case X86_INS_SETNS:
        case X86_INS_CMOVNS:
            return make_op(LlilOp::kNe, {sf(), one()}, 1);

        // Overflow flag conditions
        case X86_INS_JO:   // OF == 1
        case X86_INS_SETO:
        case X86_INS_CMOVO:
            return make_op(LlilOp::kEq, {of(), one()}, 1);
        case X86_INS_JNO:  // OF == 0
        case X86_INS_SETNO:
        case X86_INS_CMOVNO:
            return make_op(LlilOp::kNe, {of(), one()}, 1);

        // Unsigned comparisons (using CF)
        case X86_INS_JB:   // CF == 1 (below, unsigned <)
        case X86_INS_SETB:
        case X86_INS_CMOVB:
            return make_op(LlilOp::kEq, {cf(), one()}, 1);
        case X86_INS_JAE:  // CF == 0 (above or equal, unsigned >=)
        case X86_INS_SETAE:
        case X86_INS_CMOVAE:
            return make_op(LlilOp::kNe, {cf(), one()}, 1);
        case X86_INS_JBE:  // CF == 1 OR ZF == 1 (below or equal, unsigned <=)
        case X86_INS_SETBE:
        case X86_INS_CMOVBE:
            return make_op(LlilOp::kOr, {
                make_op(LlilOp::kEq, {cf(), one()}, 1),
                make_op(LlilOp::kEq, {zf(), one()}, 1)
            }, 1);
        case X86_INS_JA:   // CF == 0 AND ZF == 0 (above, unsigned >)
        case X86_INS_SETA:
        case X86_INS_CMOVA:
            return make_op(LlilOp::kAnd, {
                make_op(LlilOp::kNe, {cf(), one()}, 1),
                make_op(LlilOp::kNe, {zf(), one()}, 1)
            }, 1);

        // Signed comparisons (using SF, OF, ZF)
        case X86_INS_JL:   // SF != OF (less, signed <)
        case X86_INS_SETL:
        case X86_INS_CMOVL:
            return make_op(LlilOp::kNe, {sf(), of()}, 1);
        case X86_INS_JGE:  // SF == OF (greater or equal, signed >=)
        case X86_INS_SETGE:
        case X86_INS_CMOVGE:
            return make_op(LlilOp::kEq, {sf(), of()}, 1);
        case X86_INS_JLE:  // ZF == 1 OR SF != OF (less or equal, signed <=)
        case X86_INS_SETLE:
        case X86_INS_CMOVLE:
            return make_op(LlilOp::kOr, {
                make_op(LlilOp::kEq, {zf(), one()}, 1),
                make_op(LlilOp::kNe, {sf(), of()}, 1)
            }, 1);
        case X86_INS_JG:   // ZF == 0 AND SF == OF (greater, signed >)
        case X86_INS_SETG:
        case X86_INS_CMOVG:
            return make_op(LlilOp::kAnd, {
                make_op(LlilOp::kNe, {zf(), one()}, 1),
                make_op(LlilOp::kEq, {sf(), of()}, 1)
            }, 1);

        default:
            break;
    }
    return make_imm(0, 1);
}

void emit_set_reg(Instruction& out, LlilExpr dst, LlilExpr value) {
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kSetReg;
    stmt.reg = dst.reg;
    stmt.expr = std::move(value);
    out.llil.push_back(std::move(stmt));
}

void emit_store(Instruction& out, LlilExpr addr, LlilExpr value) {
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kStore;
    stmt.target = std::move(addr);
    stmt.expr = std::move(value);
    out.llil.push_back(std::move(stmt));
}

void lift_mov(csh handle, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 2) {
        return;
    }
    const auto& dst = x86.operands[0];
    const auto& src = x86.operands[1];
    if (dst.type == X86_OP_REG) {
        const std::size_t size = op_size(dst);
        LlilExpr dst_reg = make_reg(handle, dst.reg, size);
        LlilExpr src_val = operand_value(handle, src, size);
        emit_set_reg(out, std::move(dst_reg), std::move(src_val));
    } else if (dst.type == X86_OP_MEM) {
        const std::size_t size = op_size(dst);
        LlilExpr addr = build_mem_address(handle, dst.mem);
        LlilExpr src_val = operand_value(handle, src, size);
        emit_store(out, std::move(addr), std::move(src_val));
    }
}

void lift_mov_extend(csh handle, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 2) {
        return;
    }
    const auto& dst = x86.operands[0];
    const auto& src = x86.operands[1];
    if (dst.type != X86_OP_REG) {
        return;
    }
    const std::size_t dst_size = op_size(dst);
    const std::size_t src_size = op_size(src);
    LlilExpr dst_reg = make_reg(handle, dst.reg, dst_size);
    LlilExpr src_val = operand_value(handle, src, src_size);
    LlilExpr cast = make_op(LlilOp::kCast, {std::move(src_val)}, dst_size);
    emit_set_reg(out, std::move(dst_reg), std::move(cast));
}

void lift_lea(csh handle, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 2) {
        return;
    }
    const auto& dst = x86.operands[0];
    const auto& src = x86.operands[1];
    if (dst.type != X86_OP_REG || src.type != X86_OP_MEM) {
        return;
    }
    const std::size_t size = op_size(dst);
    LlilExpr dst_reg = make_reg(handle, dst.reg, size);
    LlilExpr addr = build_mem_address(handle, src.mem);
    emit_set_reg(out, std::move(dst_reg), std::move(addr));
}

void lift_binop(csh handle, LlilOp op_kind, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 2) {
        return;
    }
    const auto& dst = x86.operands[0];
    const auto& src = x86.operands[1];
    if (dst.type != X86_OP_REG) {
        return;
    }
    const std::size_t size = op_size(dst);
    LlilExpr dst_reg = make_reg(handle, dst.reg, size);
    LlilExpr lhs = make_reg(handle, dst.reg, size);
    LlilExpr rhs = operand_value(handle, src, size);
    std::vector<LlilExpr> args;
    args.push_back(std::move(lhs));
    args.push_back(std::move(rhs));
    LlilExpr value = make_op(op_kind, std::move(args), size);
    emit_set_reg(out, std::move(dst_reg), std::move(value));
}

void lift_shift(csh handle, LlilOp op_kind, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 2) {
        return;
    }
    const auto& dst = x86.operands[0];
    const auto& src = x86.operands[1];
    if (dst.type != X86_OP_REG) {
        return;
    }
    const std::size_t size = op_size(dst);
    LlilExpr dst_reg = make_reg(handle, dst.reg, size);
    LlilExpr lhs = make_reg(handle, dst.reg, size);
    LlilExpr rhs = operand_value(handle, src, size);
    std::vector<LlilExpr> args;
    args.push_back(std::move(lhs));
    args.push_back(std::move(rhs));
    LlilExpr value = make_op(op_kind, std::move(args), size);
    emit_set_reg(out, std::move(dst_reg), std::move(value));
}

void lift_cmp(csh handle, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 2) {
        return;
    }
    const auto& op0 = x86.operands[0];
    const auto& op1 = x86.operands[1];
    const std::size_t size = op_size(op0);
    LlilExpr lhs = operand_value(handle, op0, size);
    LlilExpr rhs = operand_value(handle, op1, size);
    // CMP computes lhs - rhs and sets flags (discards result)
    LlilExpr result = make_op(LlilOp::kSub, {lhs, rhs}, size);
    emit_flags_sub(out, lhs, rhs, result, size);
}

void lift_test(csh handle, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 2) {
        return;
    }
    const auto& op0 = x86.operands[0];
    const auto& op1 = x86.operands[1];
    const std::size_t size = op_size(op0);
    LlilExpr lhs = operand_value(handle, op0, size);
    LlilExpr rhs = operand_value(handle, op1, size);
    // TEST computes lhs & rhs and sets flags (discards result)
    LlilExpr result = make_op(LlilOp::kAnd, {lhs, rhs}, size);
    emit_flags_logic(out, result, size);
}

void lift_setcc(csh handle, unsigned int id, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 1) {
        return;
    }
    const auto& dst = x86.operands[0];
    if (dst.type != X86_OP_REG && dst.type != X86_OP_MEM) {
        return;
    }
    LlilExpr cond = condition_from_jcc(id);
    LlilExpr value = make_op(LlilOp::kCast, {std::move(cond)}, 1);
    if (dst.type == X86_OP_REG) {
        emit_set_reg(out, make_reg(handle, dst.reg, 1), std::move(value));
    } else {
        LlilExpr addr = build_mem_address(handle, dst.mem);
        emit_store(out, std::move(addr), std::move(value));
    }
}

void lift_cmovcc(csh handle, unsigned int id, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 2) {
        return;
    }
    const auto& dst = x86.operands[0];
    const auto& src = x86.operands[1];
    if (dst.type != X86_OP_REG) {
        return;
    }
    const std::size_t size = op_size(dst);
    LlilExpr cond = condition_from_jcc(id);
    LlilExpr t = operand_value(handle, src, size);
    LlilExpr f = make_reg(handle, dst.reg, size);
    LlilExpr value = make_select_expr(std::move(cond), std::move(t), std::move(f), size);
    emit_set_reg(out, make_reg(handle, dst.reg, size), std::move(value));
}

void lift_push(csh handle, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 1) {
        return;
    }
    const auto& src = x86.operands[0];
    const std::size_t size = op_size(src, 8);
    LlilExpr rsp = make_reg(handle, X86_REG_RSP, 8);
    std::vector<LlilExpr> sub_args;
    sub_args.push_back(rsp);
    sub_args.push_back(make_imm(size, 8));
    LlilExpr new_rsp = make_op(LlilOp::kSub, std::move(sub_args), 8);
    emit_set_reg(out, make_reg(handle, X86_REG_RSP, 8), new_rsp);
    LlilExpr addr = make_reg(handle, X86_REG_RSP, 8);
    LlilExpr value = operand_value(handle, src, size);
    emit_store(out, std::move(addr), std::move(value));
}

void lift_pop(csh handle, const cs_x86& x86, Instruction& out) {
    if (x86.op_count < 1) {
        return;
    }
    const auto& dst = x86.operands[0];
    const std::size_t size = op_size(dst, 8);
    LlilExpr addr = make_reg(handle, X86_REG_RSP, 8);
    LlilExpr value = make_load(addr, size);
    if (dst.type == X86_OP_REG) {
        emit_set_reg(out, make_reg(handle, dst.reg, size), std::move(value));
    } else if (dst.type == X86_OP_MEM) {
        LlilExpr dst_addr = build_mem_address(handle, dst.mem);
        emit_store(out, std::move(dst_addr), std::move(value));
    }
    LlilExpr rsp = make_reg(handle, X86_REG_RSP, 8);
    std::vector<LlilExpr> add_args;
    add_args.push_back(rsp);
    add_args.push_back(make_imm(size, 8));
    LlilExpr new_rsp = make_op(LlilOp::kAdd, std::move(add_args), 8);
    emit_set_reg(out, make_reg(handle, X86_REG_RSP, 8), std::move(new_rsp));
}

void lift_call(csh handle, const cs_x86& x86, Instruction& out) {
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kCall;
    if (x86.op_count > 0) {
        const auto& op = x86.operands[0];
        if (op.type == X86_OP_IMM) {
            stmt.target = make_imm(static_cast<std::uint64_t>(op.imm), 8);
        } else if (op.type == X86_OP_REG) {
            stmt.target = make_reg(handle, op.reg, 8);
        } else if (op.type == X86_OP_MEM) {
            stmt.target = build_mem_address(handle, op.mem);
        } else {
            stmt.target = make_imm(0, 8);
        }
    }
    out.llil.push_back(std::move(stmt));
}

void lift_jump(csh handle, const cs_insn& insn, const cs_x86& x86, Instruction& out) {
    LlilStmt stmt;
    const bool is_unconditional = (insn.id == X86_INS_JMP || insn.id == X86_INS_LJMP);
    stmt.kind = is_unconditional ? LlilStmtKind::kJump : LlilStmtKind::kCJump;
    if (x86.op_count > 0) {
        const auto& op = x86.operands[0];
        if (op.type == X86_OP_IMM) {
            stmt.target = make_imm(static_cast<std::uint64_t>(op.imm), 8);
        } else if (op.type == X86_OP_REG) {
            stmt.target = make_reg(handle, op.reg, 8);
        } else if (op.type == X86_OP_MEM) {
            stmt.target = build_mem_address(handle, op.mem);
        } else {
            stmt.target = make_imm(0, 8);
        }
    }
    if (!is_unconditional) {
        stmt.condition = condition_from_jcc(insn.id);
    }
    out.llil.push_back(std::move(stmt));
}

void lift_ret(Instruction& out) {
    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kRet;
    out.llil.push_back(std::move(stmt));
}

}  // namespace

void lift_instruction(csh handle, const cs_insn& insn, Instruction& out) {
    if (!insn.detail) {
        LlilStmt stmt;
        stmt.kind = LlilStmtKind::kUnimpl;
        out.llil.push_back(std::move(stmt));
        return;
    }

    const cs_x86& x86 = insn.detail->x86;
    switch (insn.id) {
        case X86_INS_MOV:
            lift_mov(handle, x86, out);
            return;
        case X86_INS_MOVZX:
        case X86_INS_MOVSXD:
        case X86_INS_MOVSX:
            lift_mov_extend(handle, x86, out);
            return;
        case X86_INS_LEA:
            lift_lea(handle, x86, out);
            return;
        case X86_INS_ADD:
            lift_binop(handle, LlilOp::kAdd, x86, out);
            return;
        case X86_INS_SUB:
            lift_binop(handle, LlilOp::kSub, x86, out);
            return;
        case X86_INS_IMUL:
            lift_binop(handle, LlilOp::kMul, x86, out);
            return;
        case X86_INS_XOR:
            lift_binop(handle, LlilOp::kXor, x86, out);
            return;
        case X86_INS_AND:
            lift_binop(handle, LlilOp::kAnd, x86, out);
            return;
        case X86_INS_OR:
            lift_binop(handle, LlilOp::kOr, x86, out);
            return;
        case X86_INS_SHL:
        case X86_INS_SAL:
            lift_shift(handle, LlilOp::kShl, x86, out);
            return;
        case X86_INS_SHR:
            lift_shift(handle, LlilOp::kShr, x86, out);
            return;
        case X86_INS_SAR:
            lift_shift(handle, LlilOp::kSar, x86, out);
            return;
        case X86_INS_PUSH:
            lift_push(handle, x86, out);
            return;
        case X86_INS_POP:
            lift_pop(handle, x86, out);
            return;
        case X86_INS_CMP:
            lift_cmp(handle, x86, out);
            return;
        case X86_INS_TEST:
            lift_test(handle, x86, out);
            return;
        case X86_INS_SETNE:
        case X86_INS_SETE:
        case X86_INS_SETL:
        case X86_INS_SETLE:
        case X86_INS_SETG:
        case X86_INS_SETGE:
        case X86_INS_SETA:
        case X86_INS_SETAE:
        case X86_INS_SETB:
        case X86_INS_SETBE:
        case X86_INS_SETS:
        case X86_INS_SETNS:
        case X86_INS_SETO:
        case X86_INS_SETNO:
            lift_setcc(handle, insn.id, x86, out);
            return;
        case X86_INS_CMOVNE:
        case X86_INS_CMOVE:
        case X86_INS_CMOVL:
        case X86_INS_CMOVLE:
        case X86_INS_CMOVG:
        case X86_INS_CMOVGE:
        case X86_INS_CMOVA:
        case X86_INS_CMOVAE:
        case X86_INS_CMOVB:
        case X86_INS_CMOVBE:
        case X86_INS_CMOVS:
        case X86_INS_CMOVNS:
        case X86_INS_CMOVO:
        case X86_INS_CMOVNO:
            lift_cmovcc(handle, insn.id, x86, out);
            return;
        case X86_INS_CALL:
            lift_call(handle, x86, out);
            return;
        case X86_INS_LEAVE: {
            LlilExpr rbp = make_reg(handle, X86_REG_RBP, 8);
            emit_set_reg(out, make_reg(handle, X86_REG_RSP, 8), std::move(rbp));
            LlilExpr addr = make_reg(handle, X86_REG_RSP, 8);
            LlilExpr value = make_load(addr, 8);
            emit_set_reg(out, make_reg(handle, X86_REG_RBP, 8), std::move(value));
            std::vector<LlilExpr> add_args;
            add_args.push_back(make_reg(handle, X86_REG_RSP, 8));
            add_args.push_back(make_imm(8, 8));
            LlilExpr new_rsp = make_op(LlilOp::kAdd, std::move(add_args), 8);
            emit_set_reg(out, make_reg(handle, X86_REG_RSP, 8), std::move(new_rsp));
            return;
        }
        case X86_INS_JMP:
        case X86_INS_LJMP:
        case X86_INS_JAE:
        case X86_INS_JA:
        case X86_INS_JBE:
        case X86_INS_JB:
        case X86_INS_JCXZ:
        case X86_INS_JECXZ:
        case X86_INS_JE:
        case X86_INS_JGE:
        case X86_INS_JG:
        case X86_INS_JLE:
        case X86_INS_JL:
        case X86_INS_JNE:
        case X86_INS_JNO:
        case X86_INS_JNP:
        case X86_INS_JNS:
        case X86_INS_JO:
        case X86_INS_JP:
        case X86_INS_JRCXZ:
        case X86_INS_JS:
            lift_jump(handle, insn, x86, out);
            return;
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
            lift_ret(out);
            return;
        default:
            break;
    }

    LlilStmt stmt;
    stmt.kind = LlilStmtKind::kUnimpl;
    out.llil.push_back(std::move(stmt));
}

}  // namespace engine::llir::x86_64
