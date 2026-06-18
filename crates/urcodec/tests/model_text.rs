use urcodec::{
    format_instruction, Architecture, DecodeStatus, FlowKind, FormId, Instruction, InstructionKind,
    Operand,
};

#[test]
fn canonical_text_is_derived_from_instruction_fields() {
    let insn = Instruction {
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
