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

#[test]
fn decodes_conditional_compare_and_test_branches() {
    let b_eq = decode(0x54000080, 0x400100);
    assert_eq!(b_eq.text, "b.eq 0x400110");
    assert_eq!(b_eq.flow, FlowKind::ConditionalBranch);
    assert_eq!(b_eq.branch_target, Some(0x400110));

    let cbz = decode(0xb4000080, 0x400100);
    assert_eq!(cbz.text, "cbz x0, 0x400110");
    assert_eq!(cbz.flow, FlowKind::ConditionalBranch);

    let cbnz = decode(0xb50000a1, 0x400100);
    assert_eq!(cbnz.text, "cbnz x1, 0x400114");
    assert_eq!(cbnz.flow, FlowKind::ConditionalBranch);

    let tbz = decode(0x36000082, 0x400100);
    assert_eq!(tbz.text, "tbz w2, #0x0, 0x400110");
    assert_eq!(tbz.flow, FlowKind::ConditionalBranch);

    let tbnz = decode(0x370000a3, 0x400100);
    assert_eq!(tbnz.text, "tbnz w3, #0x0, 0x400114");
    assert_eq!(tbnz.flow, FlowKind::ConditionalBranch);
}

#[test]
fn decodes_pc_relative_addressing() {
    let adr = decode(0x10000080, 0x400100);
    assert_eq!(adr.text, "adr x0, 0x400110");
    assert_eq!(adr.kind, InstructionKind::Address);
    assert_eq!(adr.flow, FlowKind::Fallthrough);

    let adrp = decode(0xb0000000, 0x400100);
    assert_eq!(adrp.text, "adrp x0, 0x401000");
    assert_eq!(adrp.kind, InstructionKind::Address);
}
