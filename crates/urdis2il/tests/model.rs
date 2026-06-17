use urdis2il::{IlExpr, IlLocation, IlReg, IlStmt, Lifter};
use urdisassembly::{
    Architecture, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind,
};

#[test]
fn il_registers_are_scoped_by_architecture_and_width() {
    let aarch64_x0 = IlReg {
        arch: Architecture::Aarch64,
        name: "x0".to_string(),
        width_bits: 64,
    };
    let x86_rax = IlReg {
        arch: Architecture::X86_64,
        name: "rax".to_string(),
        width_bits: 64,
    };

    assert_ne!(aarch64_x0, x86_rax);
    assert_eq!(IlExpr::Reg(aarch64_x0.clone()), IlExpr::Reg(aarch64_x0));
}

#[test]
fn unknown_instruction_lifts_to_unsupported_statement() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let insn = decoder.decode_one(&[0xcc], 0x401000).unwrap();
    assert_eq!(insn.status, DecodeStatus::Unknown);
    assert_eq!(insn.kind, InstructionKind::Unknown);
    assert_eq!(insn.flow, FlowKind::Fallthrough);

    let lifter = Lifter::new(Architecture::X86_64);
    let lifted = lifter.lift_instruction(&insn).unwrap();

    assert_eq!(lifted.address, 0x401000);
    assert_eq!(lifted.size, 1);
    assert_eq!(lifted.terminator, None);
    assert_eq!(lifted.statements.len(), 1);
    match &lifted.statements[0] {
        IlStmt::Unsupported {
            address,
            mnemonic,
            reason,
        } => {
            assert_eq!(*address, 0x401000);
            assert_eq!(mnemonic, ".byte");
            assert!(reason.contains("unknown decode status"));
        }
        other => panic!("expected unsupported statement, got {other:?}"),
    }
}

#[test]
fn il_locations_can_target_registers() {
    let reg = IlReg {
        arch: Architecture::X86_64,
        name: "rax".to_string(),
        width_bits: 64,
    };
    let location = IlLocation::Reg(reg.clone());

    assert_eq!(location, IlLocation::Reg(reg));
}
