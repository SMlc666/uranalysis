use crate::{
    lifter::unsupported_instruction,
    model::{IlExpr, IlFlag, IlInstruction, IlLocation, IlStmt, IlTerminator},
    operand::{const_expr, memory_address, reg_expr, reg_location},
    Result,
};

const ARCH: urdisassembly::Architecture = urdisassembly::Architecture::X86_64;

pub(crate) fn lift(instruction: &urdisassembly::Instruction) -> Result<IlInstruction> {
    let mut statements = Vec::new();
    let mut terminator = None;
    match instruction.mnemonic.as_str() {
        "mov" => lift_mov(instruction, &mut statements),
        "lea" => lift_lea(instruction, &mut statements),
        "add" | "sub" | "and" | "or" | "xor" => {
            lift_assignment_op(instruction, &mut statements);
            lift_flags(instruction, &mut statements);
        }
        "cmp" | "test" => lift_flags(instruction, &mut statements),
        "push" => lift_push(instruction, &mut statements),
        "pop" => lift_pop(instruction, &mut statements),
        "jmp" => {
            terminator = Some(IlTerminator::Jump {
                target: target_expr(instruction),
            });
        }
        "call" => {
            terminator = Some(IlTerminator::Call {
                target: target_expr(instruction),
                return_address: Some(instruction.address + u64::from(instruction.size)),
            });
        }
        "ret" => {
            terminator = Some(IlTerminator::Return);
        }
        mnemonic if is_jcc(mnemonic) => {
            if let Some(target) = instruction.branch_target {
                terminator = Some(IlTerminator::Branch {
                    condition: condition_expr(mnemonic),
                    true_target: const_expr(target, 64),
                    false_target: const_expr(instruction.address + u64::from(instruction.size), 64),
                });
            }
        }
        _ => {
            return Ok(unsupported_instruction(
                instruction,
                "x86-64 lifting rule not implemented for mnemonic",
            ));
        }
    }

    if terminator.is_none() {
        terminator = Some(IlTerminator::Fallthrough {
            target: instruction.address + u64::from(instruction.size),
        });
    }

    Ok(IlInstruction {
        address: instruction.address,
        size: instruction.size,
        statements,
        terminator,
    })
}

fn lift_mov(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    if let [dst, src] = instruction.operands.as_slice() {
        match (dst, src) {
            (urdisassembly::Operand::Register(dst), urdisassembly::Operand::Memory(mem)) => {
                statements.push(IlStmt::Load {
                    dst: reg_location(ARCH, &dst.name, 64),
                    address: memory_address(ARCH, mem),
                    size: mem.width_bits.unwrap_or(64),
                });
            }
            (urdisassembly::Operand::Memory(mem), urdisassembly::Operand::Register(src)) => {
                statements.push(IlStmt::Store {
                    address: memory_address(ARCH, mem),
                    value: reg_expr(ARCH, &src.name, 64),
                    size: mem.width_bits.unwrap_or(64),
                });
            }
            (urdisassembly::Operand::Register(dst), src) => {
                statements.push(IlStmt::Assign {
                    dst: reg_location(ARCH, &dst.name, 64),
                    src: operand_expr(src),
                });
            }
            _ => {}
        }
    }
}

fn lift_lea(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    if let [urdisassembly::Operand::Register(dst), urdisassembly::Operand::Memory(mem)] =
        instruction.operands.as_slice()
    {
        statements.push(IlStmt::Assign {
            dst: reg_location(ARCH, &dst.name, 64),
            src: memory_address(ARCH, mem),
        });
    }
}

fn lift_assignment_op(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    if let [urdisassembly::Operand::Register(dst), src] = instruction.operands.as_slice() {
        let lhs = reg_expr(ARCH, &dst.name, 64);
        let rhs = operand_expr(src);
        let expr = match instruction.mnemonic.as_str() {
            "add" => IlExpr::Add(Box::new(lhs), Box::new(rhs)),
            "sub" => IlExpr::Sub(Box::new(lhs), Box::new(rhs)),
            "and" => IlExpr::And(Box::new(lhs), Box::new(rhs)),
            "or" => IlExpr::Or(Box::new(lhs), Box::new(rhs)),
            _ => IlExpr::Xor(Box::new(lhs), Box::new(rhs)),
        };
        statements.push(IlStmt::Assign {
            dst: reg_location(ARCH, &dst.name, 64),
            src: expr,
        });
    }
}

fn lift_flags(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    let name = match instruction.mnemonic.as_str() {
        "add" => "x86_add_flags",
        "sub" | "cmp" => "x86_sub_flags",
        _ => "x86_logic_flags",
    };
    statements.push(IlStmt::Intrinsic {
        name: name.to_string(),
        inputs: instruction.operands.iter().map(operand_expr).collect(),
        outputs: ["zf", "cf", "of", "sf", "pf"]
            .iter()
            .map(|name| IlLocation::Flag(flag(name)))
            .collect(),
    });
}

fn lift_push(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    let rsp = reg_expr(ARCH, "rsp", 64);
    let new_rsp = IlExpr::Sub(Box::new(rsp), Box::new(const_expr(8, 64)));
    statements.push(IlStmt::Assign {
        dst: reg_location(ARCH, "rsp", 64),
        src: new_rsp.clone(),
    });
    if let Some(value) = instruction.operands.first() {
        statements.push(IlStmt::Store {
            address: new_rsp,
            value: operand_expr(value),
            size: 64,
        });
    }
}

fn lift_pop(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    if let Some(urdisassembly::Operand::Register(dst)) = instruction.operands.first() {
        statements.push(IlStmt::Load {
            dst: reg_location(ARCH, &dst.name, 64),
            address: reg_expr(ARCH, "rsp", 64),
            size: 64,
        });
        statements.push(IlStmt::Assign {
            dst: reg_location(ARCH, "rsp", 64),
            src: IlExpr::Add(
                Box::new(reg_expr(ARCH, "rsp", 64)),
                Box::new(const_expr(8, 64)),
            ),
        });
    }
}

fn operand_expr(operand: &urdisassembly::Operand) -> IlExpr {
    match operand {
        urdisassembly::Operand::Register(reg) => reg_expr(ARCH, &reg.name, 64),
        urdisassembly::Operand::Immediate(value) => const_expr(*value as u64, 64),
        urdisassembly::Operand::AbsoluteAddress(addr) => const_expr(*addr, 64),
        urdisassembly::Operand::Memory(mem) => memory_address(ARCH, mem),
        urdisassembly::Operand::Condition(cond) => const_expr(condition_code(cond), 8),
    }
}

fn target_expr(instruction: &urdisassembly::Instruction) -> IlExpr {
    instruction
        .branch_target
        .map(|target| const_expr(target, 64))
        .unwrap_or_else(|| reg_expr(ARCH, "unknown_target", 64))
}

fn is_jcc(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "jo" | "jno"
            | "jb"
            | "jae"
            | "je"
            | "jne"
            | "jbe"
            | "ja"
            | "js"
            | "jns"
            | "jp"
            | "jnp"
            | "jl"
            | "jge"
            | "jle"
            | "jg"
    )
}

fn condition_expr(mnemonic: &str) -> IlExpr {
    match mnemonic {
        "je" => IlExpr::Eq(
            Box::new(IlExpr::Flag(flag("zf"))),
            Box::new(const_expr(1, 1)),
        ),
        "jne" => IlExpr::Eq(
            Box::new(IlExpr::Flag(flag("zf"))),
            Box::new(const_expr(0, 1)),
        ),
        _ => IlExpr::Flag(flag(mnemonic)),
    }
}

fn flag(name: &str) -> IlFlag {
    IlFlag {
        arch: ARCH,
        name: name.to_string(),
    }
}

fn condition_code(cond: &str) -> u64 {
    cond.bytes().fold(0u64, |acc, byte| acc + u64::from(byte))
}
