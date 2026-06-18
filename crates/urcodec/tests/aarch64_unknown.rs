use urcodec::{Architecture, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind};

#[test]
fn unknown_word_decodes_as_word_directive() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let insn = decoder
        .decode_one(&0xffff_ffffu32.to_le_bytes(), 0x400080)
        .unwrap();

    assert_eq!(insn.address, 0x400080);
    assert_eq!(insn.size, 4);
    assert_eq!(insn.mnemonic, ".word");
    assert_eq!(insn.operand_text(), "0xffffffff");
    assert_eq!(insn.text, ".word 0xffffffff");
    assert_eq!(insn.kind, InstructionKind::Unknown);
    assert_eq!(insn.flow, FlowKind::Fallthrough);
    assert_eq!(insn.branch_target, None);
    assert_eq!(insn.status, DecodeStatus::Unknown);
}

#[test]
fn truncated_input_is_a_hard_error() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let err = decoder
        .decode_one(&[0xc0, 0x03, 0x5f], 0x400080)
        .unwrap_err();

    assert_eq!(err.to_string(), "expected at least 4 bytes, got 3");
}
