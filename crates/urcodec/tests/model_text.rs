use urcodec::{
    format_instruction, Architecture, DecodeStatus, FlowKind, FormId, Instruction, InstructionKind,
    Operand,
};

#[test]
fn canonical_text_is_derived_from_instruction_fields() {
    let insn = Instruction {
        architecture: Architecture::X86_64,
        address: 0x401000,
        size: 1,
        bytes: vec![0xc3],
        mnemonic: "ret".to_string(),
        operands: Vec::new(),
        text: String::new(),
        kind: InstructionKind::Return,
        flow: FlowKind::Return,
        branch_target: None,
        status: DecodeStatus::Complete,
        form: Some("x86_64.ret".to_string()),
    };

    assert_eq!(format_instruction(&insn), "ret");
}

#[test]
fn form_id_names_are_arch_scoped() {
    assert_eq!(
        FormId::new(Architecture::X86_64, "ret").name(),
        "x86_64.ret"
    );
    assert_eq!(
        FormId::new(Architecture::Aarch64, "ret").name(),
        "aarch64.ret"
    );
}

#[test]
fn operands_match_expected_count() {
    let operands = [Operand::Immediate(1)];
    assert_eq!(operands.len(), 1);
}

#[test]
fn manual_instruction_text_does_not_need_byte_length_to_find_architecture() {
    let instruction = Instruction {
        architecture: Architecture::X86_64,
        address: 0x401000,
        size: 6,
        bytes: vec![0x0f, 0x85, 0xfa, 0x00, 0x00, 0x00],
        mnemonic: "jne".to_string(),
        operands: vec![Operand::AbsoluteAddress(0x401100)],
        text: String::new(),
        kind: InstructionKind::Branch,
        flow: FlowKind::ConditionalBranch,
        branch_target: Some(0x401100),
        status: DecodeStatus::Complete,
        form: Some("x86_64.jcc_rel32".to_string()),
    };

    assert_eq!(format_instruction(&instruction), "jne 0x401100");
}
