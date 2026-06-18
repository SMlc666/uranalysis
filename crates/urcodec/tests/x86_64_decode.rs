use urcodec::{
    Architecture, DecodeError, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind,
    MemoryOperand, Operand,
};

fn decode(bytes: &[u8], address: u64) -> urcodec::Instruction {
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

fn register_name(operand: &Operand) -> &str {
    match operand {
        Operand::Register(reg) => &reg.name,
        other => panic!("expected register operand, got {other:?}"),
    }
}

fn memory_operand(operand: &Operand) -> &MemoryOperand {
    match operand {
        Operand::Memory(mem) => mem,
        other => panic!("expected memory operand, got {other:?}"),
    }
}

#[test]
fn decodes_x86_64_mov_register_forms() {
    let mov_imm = decode(
        &[0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        0x401000,
    );
    assert_eq!(mov_imm.text, "mov rax, 0x1122334455667788");
    assert_eq!(mov_imm.size, 10);
    assert_eq!(mov_imm.kind, InstructionKind::Move);
    assert_eq!(register_name(&mov_imm.operands[0]), "rax");

    let mov_ecx = decode(&[0xb9, 0x78, 0x56, 0x34, 0x12], 0x401000);
    assert_eq!(mov_ecx.text, "mov ecx, 0x12345678");
    assert_eq!(mov_ecx.size, 5);
    assert_eq!(mov_ecx.kind, InstructionKind::Move);
    assert_eq!(register_name(&mov_ecx.operands[0]), "ecx");

    let mov_edi = decode(&[0xbf, 0xef, 0xcd, 0xab, 0x90], 0x401000);
    assert_eq!(mov_edi.text, "mov edi, 0x90abcdef");
    assert_eq!(mov_edi.size, 5);
    assert_eq!(mov_edi.kind, InstructionKind::Move);
    assert_eq!(register_name(&mov_edi.operands[0]), "edi");

    let mov_reg = decode(&[0x48, 0x89, 0xd8], 0x401000);
    assert_eq!(mov_reg.text, "mov rax, rbx");
    assert_eq!(mov_reg.size, 3);
    assert_eq!(register_name(&mov_reg.operands[0]), "rax");
    assert_eq!(register_name(&mov_reg.operands[1]), "rbx");

    let mov_r8 = decode(&[0x4d, 0x89, 0xc8], 0x401000);
    assert_eq!(mov_r8.text, "mov r8, r9");
    assert_eq!(register_name(&mov_r8.operands[0]), "r8");
    assert_eq!(register_name(&mov_r8.operands[1]), "r9");

    let movsx = decode(&[0x0f, 0xbe, 0x00], 0x401000);
    assert_eq!(movsx.text, "movsx eax, [rax]");
    assert_eq!(movsx.size, 3);
    assert_eq!(movsx.kind, InstructionKind::Load);
    assert_eq!(register_name(&movsx.operands[0]), "eax");

    let movzx = decode(&[0x0f, 0xb6, 0x40, 0x01], 0x401000);
    assert_eq!(movzx.text, "movzx eax, [rax+0x1]");
    assert_eq!(movzx.size, 4);
    assert_eq!(movzx.kind, InstructionKind::Load);
    assert_eq!(register_name(&movzx.operands[0]), "eax");
}

#[test]
fn decodes_x86_64_memory_moves_and_lea() {
    let load = decode(&[0x48, 0x8b, 0x43, 0x08], 0x401000);
    assert_eq!(load.text, "mov rax, [rbx+0x8]");
    assert_eq!(load.kind, InstructionKind::Load);
    let mem = memory_operand(&load.operands[1]);
    assert_eq!(mem.base.as_ref().unwrap().name, "rbx");
    assert_eq!(mem.offset, 8);
    assert_eq!(mem.width_bits, Some(64));

    let store = decode(&[0x48, 0x89, 0x43, 0x08], 0x401000);
    assert_eq!(store.text, "mov [rbx+0x8], rax");
    assert_eq!(store.kind, InstructionKind::Store);

    let lea = decode(&[0x48, 0x8d, 0x44, 0x8b, 0x10], 0x401000);
    assert_eq!(lea.text, "lea rax, [rbx+rcx*4+0x10]");
    let mem = memory_operand(&lea.operands[1]);
    assert_eq!(mem.base.as_ref().unwrap().name, "rbx");
    assert_eq!(mem.index.as_ref().unwrap().name, "rcx");
    assert_eq!(mem.scale, 4);
    assert_eq!(mem.offset, 0x10);

    let rip = decode(&[0x48, 0x8b, 0x05, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(rip.text, "mov rax, [rip+0x1234]");
    let mem = memory_operand(&rip.operands[1]);
    assert!(mem.relative);
    assert_eq!(mem.offset, 0x1234);
}

#[test]
fn decodes_x86_64_arithmetic_and_logical_forms() {
    let add_imm = decode(&[0x48, 0x83, 0xc0, 0x08], 0x401000);
    assert_eq!(add_imm.text, "add rax, 0x8");
    assert_eq!(add_imm.kind, InstructionKind::Arithmetic);

    let or_imm = decode(&[0x48, 0x83, 0xc8, 0x01], 0x401000);
    assert_eq!(or_imm.text, "or rax, 0x1");
    assert_eq!(or_imm.kind, InstructionKind::Logical);

    let adc_imm = decode(&[0x48, 0x83, 0xd0, 0x02], 0x401000);
    assert_eq!(adc_imm.text, "adc rax, 0x2");
    assert_eq!(adc_imm.kind, InstructionKind::Arithmetic);

    let sbb_imm = decode(&[0x48, 0x83, 0xd8, 0x03], 0x401000);
    assert_eq!(sbb_imm.text, "sbb rax, 0x3");
    assert_eq!(sbb_imm.kind, InstructionKind::Arithmetic);

    let and_imm = decode(&[0x48, 0x83, 0xe0, 0x0f], 0x401000);
    assert_eq!(and_imm.text, "and rax, 0xf");
    assert_eq!(and_imm.kind, InstructionKind::Logical);

    let xor_imm = decode(&[0x48, 0x83, 0xf0, 0x7f], 0x401000);
    assert_eq!(xor_imm.text, "xor rax, 0x7f");
    assert_eq!(xor_imm.kind, InstructionKind::Logical);

    let sub_reg = decode(&[0x48, 0x29, 0xd8], 0x401000);
    assert_eq!(sub_reg.text, "sub rax, rbx");
    assert_eq!(sub_reg.kind, InstructionKind::Arithmetic);

    let cmp_reg = decode(&[0x48, 0x39, 0xd8], 0x401000);
    assert_eq!(cmp_reg.text, "cmp rax, rbx");
    assert_eq!(cmp_reg.kind, InstructionKind::Compare);

    let test_reg = decode(&[0x48, 0x85, 0xc0], 0x401000);
    assert_eq!(test_reg.text, "test rax, rax");
    assert_eq!(test_reg.kind, InstructionKind::Compare);

    let xor_reg = decode(&[0x48, 0x31, 0xc0], 0x401000);
    assert_eq!(xor_reg.text, "xor rax, rax");
    assert_eq!(xor_reg.kind, InstructionKind::Logical);
}

#[test]
fn decodes_x86_64_group_f7_forms() {
    let test = decode(&[0x48, 0xf7, 0xc0, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(test.text, "test rax, 0x1234");
    assert_eq!(test.size, 7);
    assert_eq!(test.kind, InstructionKind::Compare);

    let not = decode(&[0x48, 0xf7, 0xd0], 0x401000);
    assert_eq!(not.text, "not rax");
    assert_eq!(not.size, 3);
    assert_eq!(not.kind, InstructionKind::Logical);

    let neg = decode(&[0x48, 0xf7, 0xd8], 0x401000);
    assert_eq!(neg.text, "neg rax");
    assert_eq!(neg.size, 3);
    assert_eq!(neg.kind, InstructionKind::Arithmetic);

    let imul = decode(&[0x48, 0xf7, 0x6b, 0x08], 0x401000);
    assert_eq!(imul.text, "imul [rbx+0x8]");
    assert_eq!(imul.size, 4);
    assert_eq!(imul.kind, InstructionKind::Arithmetic);

    let idiv = decode(&[0x48, 0xf7, 0xf8], 0x401000);
    assert_eq!(idiv.text, "idiv rax");
    assert_eq!(idiv.kind, InstructionKind::Arithmetic);
}

#[test]
fn decodes_x86_64_push_and_pop() {
    let push = decode(&[0x50], 0x401000);
    assert_eq!(push.text, "push rax");
    assert_eq!(push.kind, InstructionKind::Store);

    let pop = decode(&[0x58], 0x401000);
    assert_eq!(pop.text, "pop rax");
    assert_eq!(pop.kind, InstructionKind::Load);

    let push_r8 = decode(&[0x41, 0x50], 0x401000);
    assert_eq!(push_r8.text, "push r8");
    assert_eq!(push_r8.size, 2);
}

#[test]
fn decodes_x86_64_multibyte_nops() {
    let nop = decode(&[0x0f, 0x1f, 0x40, 0x00], 0x401000);
    assert_eq!(nop.text, "nop");
    assert_eq!(nop.size, 4);
    assert_eq!(nop.kind, InstructionKind::System);
    assert_eq!(nop.flow, FlowKind::Fallthrough);

    let indexed_nop = decode(&[0x0f, 0x1f, 0x44, 0x00, 0x00], 0x401000);
    assert_eq!(indexed_nop.text, "nop");
    assert_eq!(indexed_nop.size, 5);
    assert_eq!(indexed_nop.kind, InstructionKind::System);
    assert_eq!(indexed_nop.flow, FlowKind::Fallthrough);
}
