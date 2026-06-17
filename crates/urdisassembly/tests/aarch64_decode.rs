use urdisassembly::{
    Architecture, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind,
};

fn decode(word: u32, address: u64) -> urdisassembly::Instruction {
    Decoder::new(Architecture::Aarch64, DecodeOptions::default())
        .unwrap()
        .decode_one(&word.to_le_bytes(), address)
        .unwrap()
}

#[test]
fn decodes_return_and_indirect_branches() {
    let ret = decode(0xd65f03c0, 0x400080);
    assert_eq!(ret.mnemonic, "ret");
    assert_eq!(ret.operand_text(), "");
    assert_eq!(ret.flow, FlowKind::Return);
    assert_eq!(ret.kind, InstructionKind::Return);
    assert_eq!(ret.status, DecodeStatus::Complete);

    let br = decode(0xd61f0000, 0x400084);
    assert_eq!(br.text, "br x0");
    assert_eq!(br.flow, FlowKind::IndirectBranch);

    let blr = decode(0xd63f0020, 0x400088);
    assert_eq!(blr.text, "blr x1");
    assert_eq!(blr.flow, FlowKind::IndirectCall);
}

#[test]
fn decodes_unconditional_branch_immediates() {
    let b = decode(0x14000004, 0x400100);
    assert_eq!(b.text, "b 0x400110");
    assert_eq!(b.branch_target, Some(0x400110));
    assert_eq!(b.flow, FlowKind::Branch);

    let bl = decode(0x97fffffc, 0x400100);
    assert_eq!(bl.text, "bl 0x4000f0");
    assert_eq!(bl.branch_target, Some(0x4000f0));
    assert_eq!(bl.flow, FlowKind::Call);
    assert_eq!(bl.kind, InstructionKind::Call);
}
