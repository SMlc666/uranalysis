use urcodec::{Architecture, DecodeOptions, Decoder};
use urdis2il::{IlExpr, IlFlag, IlLocation, IlReg, IlStmt, IlTerminator, Lifter};

fn decode(bytes: &[u8], address: u64) -> urcodec::Instruction {
    Decoder::new(Architecture::X86_64, DecodeOptions::default())
        .unwrap()
        .decode_one(bytes, address)
        .unwrap()
}

fn lift(bytes: &[u8], address: u64) -> urdis2il::IlInstruction {
    let insn = decode(bytes, address);
    Lifter::new(Architecture::X86_64)
        .lift_instruction(&insn)
        .unwrap()
}

fn reg(name: &str) -> IlLocation {
    IlLocation::Reg(IlReg {
        arch: Architecture::X86_64,
        name: name.to_string(),
        width_bits: 64,
    })
}

fn reg_expr(name: &str) -> IlExpr {
    IlExpr::Reg(IlReg {
        arch: Architecture::X86_64,
        name: name.to_string(),
        width_bits: 64,
    })
}

#[test]
fn lifts_x86_64_mov_load_store_and_lea() {
    let load = lift(&[0x48, 0x8b, 0x43, 0x08], 0x401000);
    assert_eq!(
        load.statements[0],
        IlStmt::Load {
            dst: reg("rax"),
            address: IlExpr::Add(
                Box::new(reg_expr("rbx")),
                Box::new(IlExpr::Const {
                    value: 8,
                    width_bits: 64,
                }),
            ),
            size: 64,
        }
    );

    let store = lift(&[0x48, 0x89, 0x43, 0x08], 0x401000);
    assert_eq!(
        store.statements[0],
        IlStmt::Store {
            address: IlExpr::Add(
                Box::new(reg_expr("rbx")),
                Box::new(IlExpr::Const {
                    value: 8,
                    width_bits: 64,
                }),
            ),
            value: reg_expr("rax"),
            size: 64,
        }
    );

    let lea = lift(&[0x48, 0x8d, 0x44, 0x8b, 0x10], 0x401000);
    assert!(matches!(lea.statements[0], IlStmt::Assign { .. }));
}

#[test]
fn lifts_x86_64_cmp_and_conditional_jump() {
    let cmp = lift(&[0x48, 0x83, 0xf8, 0x00], 0x401000);
    assert!(cmp.statements.iter().any(|stmt| matches!(
        stmt,
        IlStmt::Intrinsic { name, .. } if name == "x86_sub_flags"
    )));

    let je = lift(&[0x74, 0x05], 0x401004);
    assert_eq!(
        je.terminator,
        Some(IlTerminator::Branch {
            condition: IlExpr::Eq(
                Box::new(IlExpr::Flag(IlFlag {
                    arch: Architecture::X86_64,
                    name: "zf".to_string(),
                })),
                Box::new(IlExpr::Const {
                    value: 1,
                    width_bits: 1,
                }),
            ),
            true_target: IlExpr::Const {
                value: 0x40100b,
                width_bits: 64,
            },
            false_target: IlExpr::Const {
                value: 0x401006,
                width_bits: 64,
            },
        })
    );
}

#[test]
fn lifts_x86_64_call_return_push_and_pop() {
    let call = lift(&[0xe8, 0x05, 0x00, 0x00, 0x00], 0x401000);
    assert_eq!(
        call.terminator,
        Some(IlTerminator::Call {
            target: IlExpr::Const {
                value: 0x40100a,
                width_bits: 64,
            },
            return_address: Some(0x401005),
        })
    );

    let ret = lift(&[0xc3], 0x401000);
    assert_eq!(ret.terminator, Some(IlTerminator::Return));

    let push = lift(&[0x50], 0x401000);
    assert!(push
        .statements
        .iter()
        .any(|stmt| matches!(stmt, IlStmt::Store { .. })));

    let pop = lift(&[0x58], 0x401000);
    assert!(pop
        .statements
        .iter()
        .any(|stmt| matches!(stmt, IlStmt::Load { .. })));
}
