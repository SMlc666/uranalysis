use urdisassembly::{
    Architecture, DecodeError, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind,
};

fn decode(bytes: &[u8], address: u64) -> urdisassembly::Instruction {
    Decoder::new(Architecture::X86_64, DecodeOptions::default())
        .unwrap()
        .decode_one(bytes, address)
        .unwrap()
}

#[test]
fn constructs_x86_64_decoder_and_decodes_unknown_byte() {
    let insn = decode(&[0xcc], 0x401000);

    assert_eq!(insn.address, 0x401000);
    assert_eq!(insn.size, 1);
    assert_eq!(insn.bytes, vec![0xcc]);
    assert_eq!(insn.mnemonic, ".byte");
    assert_eq!(insn.text, ".byte 0xcc");
    assert_eq!(insn.kind, InstructionKind::Unknown);
    assert_eq!(insn.flow, FlowKind::Fallthrough);
    assert_eq!(insn.branch_target, None);
    assert_eq!(insn.status, DecodeStatus::Unknown);
}

#[test]
fn empty_x86_64_input_is_truncated() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();

    let err = decoder.decode_one(&[], 0x401000).unwrap_err();

    assert_eq!(
        err,
        DecodeError::TruncatedInstruction {
            expected: 1,
            actual: 0,
        }
    );
}

#[test]
fn decodes_x86_64_returns_calls_and_jumps() {
    let ret = decode(&[0xc3], 0x401000);
    assert_eq!(ret.text, "ret");
    assert_eq!(ret.size, 1);
    assert_eq!(ret.kind, InstructionKind::Return);
    assert_eq!(ret.flow, FlowKind::Return);

    let call = decode(&[0xe8, 0x05, 0x00, 0x00, 0x00], 0x401000);
    assert_eq!(call.text, "call 0x40100a");
    assert_eq!(call.size, 5);
    assert_eq!(call.branch_target, Some(0x40100a));
    assert_eq!(call.flow, FlowKind::Call);

    let jmp_rel8 = decode(&[0xeb, 0x06], 0x401000);
    assert_eq!(jmp_rel8.text, "jmp 0x401008");
    assert_eq!(jmp_rel8.size, 2);
    assert_eq!(jmp_rel8.branch_target, Some(0x401008));
    assert_eq!(jmp_rel8.flow, FlowKind::Branch);

    let jmp_rel32 = decode(&[0xe9, 0xfb, 0xff, 0xff, 0xff], 0x401010);
    assert_eq!(jmp_rel32.text, "jmp 0x401010");
    assert_eq!(jmp_rel32.branch_target, Some(0x401010));
}

#[test]
fn decodes_x86_64_conditional_jumps() {
    let je = decode(&[0x74, 0x05], 0x401000);
    assert_eq!(je.text, "je 0x401007");
    assert_eq!(je.flow, FlowKind::ConditionalBranch);
    assert_eq!(je.branch_target, Some(0x401007));

    let jne = decode(&[0x0f, 0x85, 0x05, 0x00, 0x00, 0x00], 0x401000);
    assert_eq!(jne.text, "jne 0x40100b");
    assert_eq!(jne.size, 6);
    assert_eq!(jne.flow, FlowKind::ConditionalBranch);
    assert_eq!(jne.branch_target, Some(0x40100b));
}

#[test]
fn truncated_x86_64_relative_control_flow_is_an_error() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let err = decoder.decode_one(&[0xe8, 0x00], 0x401000).unwrap_err();
    assert_eq!(
        err,
        DecodeError::TruncatedInstruction {
            expected: 5,
            actual: 2,
        }
    );
}
