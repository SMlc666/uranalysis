use crate::{
    lifter::unsupported_instruction,
    model::{IlExpr, IlFlag, IlInstruction, IlStmt, IlTerminator},
    operand::{const_expr, memory_address, reg_expr, reg_location},
    Result,
};

const ARCH: urcodec::Architecture = urcodec::Architecture::Aarch64;

pub(crate) fn lift(instruction: &urcodec::Instruction) -> Result<IlInstruction> {
    let mut statements = Vec::new();
    let mut terminator = None;
    match instruction.mnemonic.as_str() {
        "nop" => {
            terminator = Some(fallthrough(instruction));
        }
        "ldr" => {
            if let [urcodec::Operand::Register(dst), urcodec::Operand::Memory(mem)] =
                instruction.operands.as_slice()
            {
                statements.push(IlStmt::Load {
                    dst: reg_location(ARCH, &dst.name, 64),
                    address: memory_address(ARCH, mem),
                    size: mem.width_bits.unwrap_or(64),
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "str" => {
            if let [urcodec::Operand::Register(src), urcodec::Operand::Memory(mem)] =
                instruction.operands.as_slice()
            {
                statements.push(IlStmt::Store {
                    address: memory_address(ARCH, mem),
                    value: reg_expr(ARCH, &src.name, 64),
                    size: mem.width_bits.unwrap_or(64),
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "add" | "sub" | "and" | "orr" | "eor" => {
            if let [urcodec::Operand::Register(dst), urcodec::Operand::Register(lhs), rhs] =
                instruction.operands.as_slice()
            {
                let rhs_expr = operand_expr(rhs);
                let lhs_expr = reg_expr(ARCH, &lhs.name, 64);
                let src = match instruction.mnemonic.as_str() {
                    "add" => IlExpr::Add(Box::new(lhs_expr), Box::new(rhs_expr)),
                    "sub" => IlExpr::Sub(Box::new(lhs_expr), Box::new(rhs_expr)),
                    "and" => IlExpr::And(Box::new(lhs_expr), Box::new(rhs_expr)),
                    "orr" => IlExpr::Or(Box::new(lhs_expr), Box::new(rhs_expr)),
                    _ => IlExpr::Xor(Box::new(lhs_expr), Box::new(rhs_expr)),
                };
                statements.push(IlStmt::Assign {
                    dst: reg_location(ARCH, &dst.name, 64),
                    src,
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "mov" | "movk" | "movn" => {
            if let [urcodec::Operand::Register(dst), src] = instruction.operands.as_slice() {
                statements.push(IlStmt::Assign {
                    dst: reg_location(ARCH, &dst.name, 64),
                    src: operand_expr(src),
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "adr" | "adrp" => {
            if let [urcodec::Operand::Register(dst), urcodec::Operand::AbsoluteAddress(addr)] =
                instruction.operands.as_slice()
            {
                statements.push(IlStmt::Assign {
                    dst: reg_location(ARCH, &dst.name, 64),
                    src: const_expr(*addr, 64),
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "cmp" | "cmn" => {
            statements.push(IlStmt::Intrinsic {
                name: if instruction.mnemonic == "cmp" {
                    "aarch64_sub_flags".to_string()
                } else {
                    "aarch64_add_flags".to_string()
                },
                inputs: instruction.operands.iter().map(operand_expr).collect(),
                outputs: ["n", "z", "c", "v"]
                    .iter()
                    .map(|name| crate::model::IlLocation::Flag(flag(name)))
                    .collect(),
            });
            terminator = Some(fallthrough(instruction));
        }
        "b" => {
            if let Some(target) = instruction.branch_target {
                terminator = Some(IlTerminator::Jump {
                    target: const_expr(target, 64),
                });
            }
        }
        "bl" | "blr" => {
            terminator = Some(IlTerminator::Call {
                target: target_expr(instruction),
                return_address: Some(instruction.address + u64::from(instruction.size)),
            });
        }
        "ret" => {
            terminator = Some(IlTerminator::Return);
        }
        mnemonic if mnemonic.starts_with("b.") => {
            if let Some(target) = instruction.branch_target {
                terminator = Some(IlTerminator::Branch {
                    condition: condition_expr(mnemonic.trim_start_matches("b.")),
                    true_target: const_expr(target, 64),
                    false_target: const_expr(instruction.address + u64::from(instruction.size), 64),
                });
            }
        }
        _ => {
            return Ok(unsupported_instruction(
                instruction,
                "aarch64 lifting rule not implemented for mnemonic",
            ));
        }
    }

    if terminator.is_none() && statements.is_empty() {
        return Ok(unsupported_instruction(
            instruction,
            "aarch64 operands did not match lifting rule",
        ));
    }

    Ok(IlInstruction {
        address: instruction.address,
        size: instruction.size,
        statements,
        terminator,
    })
}

fn operand_expr(operand: &urcodec::Operand) -> IlExpr {
    match operand {
        urcodec::Operand::Register(reg) => reg_expr(ARCH, &reg.name, 64),
        urcodec::Operand::ShiftedRegister(reg) => {
            let value = reg_expr(ARCH, &reg.register.name, 64);
            let amount = const_expr(u64::from(reg.amount), 8);
            match reg.shift.as_str() {
                "lsl" => IlExpr::Shl(Box::new(value), Box::new(amount)),
                "lsr" | "asr" => IlExpr::Shr(Box::new(value), Box::new(amount)),
                _ => value,
            }
        }
        urcodec::Operand::Immediate(value) => const_expr(*value as u64, 64),
        urcodec::Operand::AbsoluteAddress(addr) => const_expr(*addr, 64),
        urcodec::Operand::Memory(mem) => memory_address(ARCH, mem),
        urcodec::Operand::Condition(cond) => const_expr(condition_code(cond), 4),
    }
}

fn target_expr(instruction: &urcodec::Instruction) -> IlExpr {
    instruction
        .branch_target
        .map(|target| const_expr(target, 64))
        .unwrap_or(IlExpr::Reg(crate::model::IlReg {
            arch: ARCH,
            name: "unknown_target".to_string(),
            width_bits: 64,
        }))
}

fn fallthrough(instruction: &urcodec::Instruction) -> IlTerminator {
    IlTerminator::Fallthrough {
        target: instruction.address + u64::from(instruction.size),
    }
}

fn flag(name: &str) -> IlFlag {
    IlFlag {
        arch: ARCH,
        name: name.to_string(),
    }
}

fn condition_expr(cond: &str) -> IlExpr {
    match cond {
        "eq" => IlExpr::Eq(
            Box::new(IlExpr::Flag(flag("z"))),
            Box::new(const_expr(1, 1)),
        ),
        "ne" => IlExpr::Eq(
            Box::new(IlExpr::Flag(flag("z"))),
            Box::new(const_expr(0, 1)),
        ),
        _ => IlExpr::Flag(flag(cond)),
    }
}

fn condition_code(cond: &str) -> u64 {
    match cond {
        "eq" => 0,
        "ne" => 1,
        "cs" => 2,
        "cc" => 3,
        "mi" => 4,
        "pl" => 5,
        "vs" => 6,
        "vc" => 7,
        "hi" => 8,
        "ls" => 9,
        "ge" => 10,
        "lt" => 11,
        "gt" => 12,
        "le" => 13,
        _ => 14,
    }
}
