use urcodec::{Architecture, DecodeOptions, Decoder};
use urdis2il::{IlExpr, IlFlag, IlLocation, IlReg, IlStmt, IlTerminator, Lifter};

fn decode(word: u32, address: u64) -> urcodec::Instruction {
    Decoder::new(Architecture::Aarch64, DecodeOptions::default())
        .unwrap()
        .decode_one(&word.to_le_bytes(), address)
        .unwrap()
}

fn lift(word: u32, address: u64) -> urdis2il::IlInstruction {
    let insn = decode(word, address);
    Lifter::new(Architecture::Aarch64)
        .lift_instruction(&insn)
        .unwrap()
}

fn reg(name: &str) -> IlLocation {
    IlLocation::Reg(IlReg {
        arch: Architecture::Aarch64,
        name: name.to_string(),
        width_bits: 64,
    })
}

fn reg_expr(name: &str) -> IlExpr {
    IlExpr::Reg(IlReg {
        arch: Architecture::Aarch64,
        name: name.to_string(),
        width_bits: 64,
    })
}

#[test]
fn lifts_aarch64_load_store_and_add() {
    let load = lift(0xf9400420, 0x400100);
    assert_eq!(
        load.statements[0],
        IlStmt::Load {
            dst: reg("x0"),
            address: IlExpr::Add(
                Box::new(reg_expr("x1")),
                Box::new(IlExpr::Const {
                    value: 8,
                    width_bits: 64,
                }),
            ),
            size: 64,
        }
    );

    let store = lift(0xf9000822, 0x400100);
    assert_eq!(
        store.statements[0],
        IlStmt::Store {
            address: IlExpr::Add(
                Box::new(reg_expr("x1")),
                Box::new(IlExpr::Const {
                    value: 0x10,
                    width_bits: 64,
                }),
            ),
            value: reg_expr("x2"),
            size: 64,
        }
    );

    let add = lift(0x91002000, 0x400100);
    assert_eq!(
        add.statements[0],
        IlStmt::Assign {
            dst: reg("x0"),
            src: IlExpr::Add(
                Box::new(reg_expr("x0")),
                Box::new(IlExpr::Const {
                    value: 8,
                    width_bits: 64,
                }),
            ),
        }
    );
}

#[test]
fn lifts_aarch64_compare_and_conditional_branch() {
    let cmp = lift(0xf100001f, 0x400100);
    assert!(cmp.statements.iter().any(|stmt| matches!(
        stmt,
        IlStmt::Intrinsic { name, .. } if name == "aarch64_sub_flags"
    )));

    let branch = lift(0x54000080, 0x400100);
    assert_eq!(
        branch.terminator,
        Some(IlTerminator::Branch {
            condition: IlExpr::Eq(
                Box::new(IlExpr::Flag(IlFlag {
                    arch: Architecture::Aarch64,
                    name: "z".to_string(),
                })),
                Box::new(IlExpr::Const {
                    value: 1,
                    width_bits: 1,
                }),
            ),
            true_target: IlExpr::Const {
                value: 0x400110,
                width_bits: 64,
            },
            false_target: IlExpr::Const {
                value: 0x400104,
                width_bits: 64,
            },
        })
    );
}

#[test]
fn lifts_aarch64_call_return_and_nop() {
    let call = lift(0x94000002, 0x400100);
    assert_eq!(
        call.terminator,
        Some(IlTerminator::Call {
            target: IlExpr::Const {
                value: 0x400108,
                width_bits: 64,
            },
            return_address: Some(0x400104),
        })
    );

    let ret = lift(0xd65f03c0, 0x400100);
    assert_eq!(ret.terminator, Some(IlTerminator::Return));

    let nop = lift(0xd503201f, 0x400100);
    assert!(nop.statements.is_empty());
    assert_eq!(
        nop.terminator,
        Some(IlTerminator::Fallthrough { target: 0x400104 })
    );
}
