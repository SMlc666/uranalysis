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
    let insn = decode(&[0xd6], 0x401000);

    assert_eq!(insn.address, 0x401000);
    assert_eq!(insn.size, 1);
    assert_eq!(insn.bytes, vec![0xd6]);
    assert_eq!(insn.mnemonic, ".byte");
    assert_eq!(insn.text, ".byte 0xd6");
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
fn decodes_x86_64_int3() {
    let int3 = decode(&[0xcc], 0x401000);

    assert_eq!(int3.text, "int3");
    assert_eq!(int3.size, 1);
    assert_eq!(int3.kind, InstructionKind::System);
    assert_eq!(int3.flow, FlowKind::Fallthrough);
    assert_eq!(int3.status, DecodeStatus::Complete);
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
fn decodes_x86_64_byte_mov_forms() {
    let mov_al_imm = decode(&[0xb0, 0x01], 0x401000);
    assert_eq!(mov_al_imm.text, "mov al, 0x1");
    assert_eq!(mov_al_imm.size, 2);
    assert_eq!(mov_al_imm.kind, InstructionKind::Move);
    assert_eq!(register_name(&mov_al_imm.operands[0]), "al");

    let mov_store = decode(&[0x88, 0x84, 0x24, 0x97, 0x00, 0x00, 0x00], 0x401000);
    assert_eq!(mov_store.text, "mov [rsp+0x97], al");
    assert_eq!(mov_store.size, 7);
    assert_eq!(mov_store.kind, InstructionKind::Store);
    let mem = memory_operand(&mov_store.operands[0]);
    assert_eq!(mem.width_bits, Some(8));

    let mov_load = decode(&[0x8a, 0x44, 0x24, 0x10], 0x401000);
    assert_eq!(mov_load.text, "mov al, [rsp+0x10]");
    assert_eq!(mov_load.size, 4);
    assert_eq!(mov_load.kind, InstructionKind::Load);

    let mov_imm = decode(&[0xc6, 0x84, 0x24, 0x92, 0x00, 0x00, 0x00, 0x01], 0x401000);
    assert_eq!(mov_imm.text, "mov [rsp+0x92], 0x1");
    assert_eq!(mov_imm.size, 8);
    assert_eq!(mov_imm.kind, InstructionKind::Store);
    let mem = memory_operand(&mov_imm.operands[0]);
    assert_eq!(mem.width_bits, Some(8));
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

    let cmp_byte_imm = decode(&[0x80, 0x7b, 0x2f, 0x01], 0x401000);
    assert_eq!(cmp_byte_imm.text, "cmp [rbx+0x2f], 0x1");
    assert_eq!(cmp_byte_imm.kind, InstructionKind::Compare);
    let mem = memory_operand(&cmp_byte_imm.operands[0]);
    assert_eq!(mem.width_bits, Some(8));

    let cmp_al_imm = decode(&[0x3c, 0x02], 0x401000);
    assert_eq!(cmp_al_imm.text, "cmp al, 0x2");
    assert_eq!(cmp_al_imm.size, 2);
    assert_eq!(cmp_al_imm.kind, InstructionKind::Compare);

    let add_byte_reg = decode(&[0x02, 0xc1], 0x401000);
    assert_eq!(add_byte_reg.text, "add al, cl");
    assert_eq!(add_byte_reg.size, 2);
    assert_eq!(add_byte_reg.kind, InstructionKind::Arithmetic);

    let or_byte_reg = decode(&[0x08, 0xc8], 0x401000);
    assert_eq!(or_byte_reg.text, "or al, cl");
    assert_eq!(or_byte_reg.size, 2);
    assert_eq!(or_byte_reg.kind, InstructionKind::Logical);

    let cmp_byte_reg = decode(&[0x38, 0xc8], 0x401000);
    assert_eq!(cmp_byte_reg.text, "cmp al, cl");
    assert_eq!(cmp_byte_reg.size, 2);
    assert_eq!(cmp_byte_reg.kind, InstructionKind::Compare);

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

    let test_byte = decode(&[0x84, 0x24, 0x24], 0x401000);
    assert_eq!(test_byte.text, "test [rsp], ah");
    assert_eq!(test_byte.kind, InstructionKind::Compare);
    let mem = memory_operand(&test_byte.operands[0]);
    assert_eq!(mem.width_bits, Some(8));

    let test_byte_imm = decode(&[0xf6, 0xc1, 0x01], 0x401000);
    assert_eq!(test_byte_imm.text, "test cl, 0x1");
    assert_eq!(test_byte_imm.kind, InstructionKind::Compare);

    let test_al_imm = decode(&[0xa8, 0x01], 0x401000);
    assert_eq!(test_al_imm.text, "test al, 0x1");
    assert_eq!(test_al_imm.size, 2);
    assert_eq!(test_al_imm.kind, InstructionKind::Compare);

    let xor_reg = decode(&[0x48, 0x31, 0xc0], 0x401000);
    assert_eq!(xor_reg.text, "xor rax, rax");
    assert_eq!(xor_reg.kind, InstructionKind::Logical);
}

#[test]
fn decodes_x86_64_shift_groups() {
    let shr_al = decode(&[0xc0, 0xe8, 0x06], 0x401000);
    assert_eq!(shr_al.text, "shr al, 0x6");
    assert_eq!(shr_al.size, 3);
    assert_eq!(shr_al.kind, InstructionKind::Logical);

    let rol_mem32 = decode(&[0xc1, 0x01, 0x01], 0x401000);
    assert_eq!(rol_mem32.text, "rol [rcx], 0x1");
    assert_eq!(rol_mem32.size, 3);
    assert_eq!(rol_mem32.kind, InstructionKind::Logical);
    let mem = memory_operand(&rol_mem32.operands[0]);
    assert_eq!(mem.width_bits, Some(32));

    let sar_rax = decode(&[0x48, 0xc1, 0xf8, 0x03], 0x401000);
    assert_eq!(sar_rax.text, "sar rax, 0x3");
    assert_eq!(sar_rax.size, 4);
    assert_eq!(sar_rax.kind, InstructionKind::Logical);

    let shl_eax_one = decode(&[0xd1, 0xe0], 0x401000);
    assert_eq!(shl_eax_one.text, "shl eax, 0x1");
    assert_eq!(shl_eax_one.size, 2);
    assert_eq!(shl_eax_one.kind, InstructionKind::Logical);

    let shr_rax_one = decode(&[0x48, 0xd1, 0xe8], 0x401000);
    assert_eq!(shr_rax_one.text, "shr rax, 0x1");
    assert_eq!(shr_rax_one.size, 3);
    assert_eq!(shr_rax_one.kind, InstructionKind::Logical);
}

#[test]
fn decodes_x86_64_group_81_imm32_forms() {
    let add = decode(&[0x48, 0x81, 0xc0, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(add.text, "add rax, 0x1234");
    assert_eq!(add.size, 7);
    assert_eq!(add.kind, InstructionKind::Arithmetic);

    let xor = decode(&[0x48, 0x81, 0xf0, 0x78, 0x56, 0x34, 0x12], 0x401000);
    assert_eq!(xor.text, "xor rax, 0x12345678");
    assert_eq!(xor.kind, InstructionKind::Logical);

    let cmp_mem = decode(&[0x48, 0x81, 0x7b, 0x08, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(cmp_mem.text, "cmp [rbx+0x8], 0x1234");
    assert_eq!(cmp_mem.size, 8);
    assert_eq!(cmp_mem.kind, InstructionKind::Compare);
}

#[test]
fn decodes_x86_64_c7_mov_imm32_forms() {
    let mov_reg = decode(&[0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(mov_reg.text, "mov rax, 0x1234");
    assert_eq!(mov_reg.size, 7);
    assert_eq!(mov_reg.kind, InstructionKind::Move);

    let mov_mem = decode(&[0x48, 0xc7, 0x43, 0x08, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(mov_mem.text, "mov [rbx+0x8], 0x1234");
    assert_eq!(mov_mem.size, 8);
    assert_eq!(mov_mem.kind, InstructionKind::Store);
}

#[test]
fn decodes_x86_64_operand_size_prefixed_c7_mov_imm16_forms() {
    let mov_mem = decode(
        &[0x66, 0xc7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x34, 0x12],
        0x401000,
    );
    assert_eq!(mov_mem.text, "mov [rsp+0x90], 0x1234");
    assert_eq!(mov_mem.size, 10);
    assert_eq!(mov_mem.kind, InstructionKind::Store);

    let mem = memory_operand(&mov_mem.operands[0]);
    assert_eq!(mem.base.as_ref().unwrap().name, "rsp");
    assert_eq!(mem.offset, 0x90);
    assert_eq!(mem.width_bits, Some(16));
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
fn decodes_x86_64_group_ff_forms() {
    let inc = decode(&[0x48, 0xff, 0xc0], 0x401000);
    assert_eq!(inc.text, "inc rax");
    assert_eq!(inc.size, 3);
    assert_eq!(inc.kind, InstructionKind::Arithmetic);
    assert_eq!(inc.flow, FlowKind::Fallthrough);

    let dec = decode(&[0x48, 0xff, 0xc8], 0x401000);
    assert_eq!(dec.text, "dec rax");
    assert_eq!(dec.kind, InstructionKind::Arithmetic);

    let call = decode(&[0x48, 0xff, 0xd0], 0x401000);
    assert_eq!(call.text, "call rax");
    assert_eq!(call.kind, InstructionKind::Call);
    assert_eq!(call.flow, FlowKind::IndirectCall);
    assert_eq!(call.branch_target, None);

    let jmp = decode(&[0x48, 0xff, 0xe0], 0x401000);
    assert_eq!(jmp.text, "jmp rax");
    assert_eq!(jmp.kind, InstructionKind::Branch);
    assert_eq!(jmp.flow, FlowKind::IndirectBranch);
    assert_eq!(jmp.branch_target, None);

    let push = decode(&[0x48, 0xff, 0xf0], 0x401000);
    assert_eq!(push.text, "push rax");
    assert_eq!(push.kind, InstructionKind::Store);
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
    let single_byte_nop = decode(&[0x90], 0x401000);
    assert_eq!(single_byte_nop.text, "nop");
    assert_eq!(single_byte_nop.size, 1);
    assert_eq!(single_byte_nop.kind, InstructionKind::System);
    assert_eq!(single_byte_nop.flow, FlowKind::Fallthrough);

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

    let prefixed_nop = decode(
        &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        0x401000,
    );
    assert_eq!(prefixed_nop.text, "nop");
    assert_eq!(prefixed_nop.size, 9);
    assert_eq!(prefixed_nop.kind, InstructionKind::System);
    assert_eq!(prefixed_nop.flow, FlowKind::Fallthrough);
}

#[test]
fn decodes_x86_64_sse_move_and_xor_forms() {
    let movups_store = decode(&[0x0f, 0x11, 0x24, 0x24], 0x401000);
    assert_eq!(movups_store.text, "movups [rsp], xmm4");
    assert_eq!(movups_store.size, 4);
    assert_eq!(movups_store.kind, InstructionKind::Store);

    let movups_load = decode(&[0x0f, 0x10, 0x44, 0x24, 0x40], 0x401000);
    assert_eq!(movups_load.text, "movups xmm0, [rsp+0x40]");
    assert_eq!(movups_load.size, 5);
    assert_eq!(movups_load.kind, InstructionKind::Load);

    let movaps_load = decode(&[0x0f, 0x28, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00], 0x401000);
    assert_eq!(movaps_load.text, "movaps xmm0, [rsp+0x80]");
    assert_eq!(movaps_load.size, 8);
    assert_eq!(movaps_load.kind, InstructionKind::Load);

    let movaps_store = decode(&[0x0f, 0x29, 0x44, 0x24, 0x20], 0x401000);
    assert_eq!(movaps_store.text, "movaps [rsp+0x20], xmm0");
    assert_eq!(movaps_store.size, 5);
    assert_eq!(movaps_store.kind, InstructionKind::Store);

    let xorps = decode(&[0x0f, 0x57, 0xc0], 0x401000);
    assert_eq!(xorps.text, "xorps xmm0, xmm0");
    assert_eq!(xorps.size, 3);
    assert_eq!(xorps.kind, InstructionKind::Logical);

    let cmpps_reg = decode(&[0x0f, 0xc2, 0xc2, 0x00], 0x401000);
    assert_eq!(cmpps_reg.text, "cmpps xmm0, xmm2, 0x0");
    assert_eq!(cmpps_reg.size, 4);
    assert_eq!(cmpps_reg.kind, InstructionKind::Compare);

    let cmpps_mem = decode(&[0x0f, 0xc2, 0x44, 0x24, 0x20, 0x06], 0x401000);
    assert_eq!(cmpps_mem.text, "cmpps xmm0, [rsp+0x20], 0x6");
    assert_eq!(cmpps_mem.size, 6);
    assert_eq!(cmpps_mem.kind, InstructionKind::Compare);
}

#[test]
fn decodes_x86_64_ud2() {
    let ud2 = decode(&[0x0f, 0x0b], 0x401000);

    assert_eq!(ud2.text, "ud2");
    assert_eq!(ud2.size, 2);
    assert_eq!(ud2.kind, InstructionKind::System);
    assert_eq!(ud2.flow, FlowKind::Fallthrough);
}

#[test]
fn decodes_x86_64_setcc_forms() {
    let sete = decode(&[0x0f, 0x94, 0xc2], 0x401000);
    assert_eq!(sete.text, "sete dl");
    assert_eq!(sete.size, 3);
    assert_eq!(sete.kind, InstructionKind::Move);
    assert_eq!(sete.flow, FlowKind::Fallthrough);

    let setne_mem = decode(&[0x0f, 0x95, 0x44, 0x24, 0x08], 0x401000);
    assert_eq!(setne_mem.text, "setne [rsp+0x8]");
    assert_eq!(setne_mem.size, 5);
    assert_eq!(setne_mem.kind, InstructionKind::Store);
}
