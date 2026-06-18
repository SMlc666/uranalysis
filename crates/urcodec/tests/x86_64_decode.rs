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

    let ret_imm = decode(&[0xc2, 0xc2, 0x00], 0x401000);
    assert_eq!(ret_imm.text, "ret 0xc2");
    assert_eq!(ret_imm.size, 3);
    assert_eq!(ret_imm.kind, InstructionKind::Return);
    assert_eq!(ret_imm.flow, FlowKind::Return);

    let retf_imm = decode(&[0xca, 0x10, 0x00], 0x401000);
    assert_eq!(retf_imm.text, "retf 0x10");
    assert_eq!(retf_imm.size, 3);
    assert_eq!(retf_imm.kind, InstructionKind::Return);
    assert_eq!(retf_imm.flow, FlowKind::Return);

    let retf = decode(&[0xcb], 0x401000);
    assert_eq!(retf.text, "retf");
    assert_eq!(retf.size, 1);
    assert_eq!(retf.kind, InstructionKind::Return);
    assert_eq!(retf.flow, FlowKind::Return);

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
fn decodes_x86_64_int_imm8() {
    let int = decode(&[0xcd, 0x29], 0x401000);

    assert_eq!(int.text, "int 0x29");
    assert_eq!(int.size, 2);
    assert_eq!(int.kind, InstructionKind::System);
    assert_eq!(int.flow, FlowKind::Fallthrough);
}

#[test]
fn decodes_x86_64_system_0f_forms() {
    let xgetbv = decode(&[0x0f, 0x01, 0xd0], 0x401000);
    assert_eq!(xgetbv.text, "xgetbv");
    assert_eq!(xgetbv.size, 3);
    assert_eq!(xgetbv.kind, InstructionKind::System);

    let sfence = decode(&[0x0f, 0xae, 0xf8], 0x401000);
    assert_eq!(sfence.text, "sfence");
    assert_eq!(sfence.size, 3);
    assert_eq!(sfence.kind, InstructionKind::System);

    let stmxcsr = decode(&[0x0f, 0xae, 0x1c, 0x24], 0x401000);
    assert_eq!(stmxcsr.text, "stmxcsr [rsp]");
    assert_eq!(stmxcsr.size, 4);
    assert_eq!(stmxcsr.kind, InstructionKind::System);

    let ldmxcsr = decode(&[0x0f, 0xae, 0x54, 0x24, 0x08], 0x401000);
    assert_eq!(ldmxcsr.text, "ldmxcsr [rsp+0x8]");
    assert_eq!(ldmxcsr.size, 5);
    assert_eq!(ldmxcsr.kind, InstructionKind::System);

    let cpuid = decode(&[0x0f, 0xa2], 0x401000);
    assert_eq!(cpuid.text, "cpuid");
    assert_eq!(cpuid.size, 2);
    assert_eq!(cpuid.kind, InstructionKind::System);

    let iretd = decode(&[0xcf], 0x401000);
    assert_eq!(iretd.text, "iretd");
    assert_eq!(iretd.size, 1);
    assert_eq!(iretd.kind, InstructionKind::System);

    let iretq = decode(&[0x48, 0xcf], 0x401000);
    assert_eq!(iretq.text, "iretq");
    assert_eq!(iretq.size, 2);
    assert_eq!(iretq.kind, InstructionKind::System);
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
fn decodes_x86_64_conditional_moves() {
    let cmovb = decode(&[0x0f, 0x42, 0xf7], 0x401000);
    assert_eq!(cmovb.text, "cmovb esi, edi");
    assert_eq!(cmovb.size, 3);
    assert_eq!(cmovb.kind, InstructionKind::Move);

    let cmovae = decode(&[0x48, 0x0f, 0x43, 0xc7], 0x401000);
    assert_eq!(cmovae.text, "cmovae rax, rdi");
    assert_eq!(cmovae.size, 4);
    assert_eq!(cmovae.kind, InstructionKind::Move);
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

    let movsxd = decode(&[0x63, 0x4e, 0x08], 0x401000);
    assert_eq!(movsxd.text, "movsxd ecx, [rsi+0x8]");
    assert_eq!(movsxd.size, 3);
    assert_eq!(movsxd.kind, InstructionKind::Load);

    let movsxd_64 = decode(&[0x48, 0x63, 0xc1], 0x401000);
    assert_eq!(movsxd_64.text, "movsxd rax, ecx");
    assert_eq!(movsxd_64.size, 3);
    assert_eq!(movsxd_64.kind, InstructionKind::Move);

    let bswap = decode(&[0x0f, 0xc8], 0x401000);
    assert_eq!(bswap.text, "bswap eax");
    assert_eq!(bswap.size, 2);
    assert_eq!(bswap.kind, InstructionKind::Move);
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

    let or_al_imm = decode(&[0x0c, 0x7c], 0x401000);
    assert_eq!(or_al_imm.text, "or al, 0x7c");
    assert_eq!(or_al_imm.size, 2);
    assert_eq!(or_al_imm.kind, InstructionKind::Logical);

    let adc_al_imm = decode(&[0x14, 0x14], 0x401000);
    assert_eq!(adc_al_imm.text, "adc al, 0x14");
    assert_eq!(adc_al_imm.size, 2);
    assert_eq!(adc_al_imm.kind, InstructionKind::Arithmetic);

    let sbb_al_imm = decode(&[0x1c, 0x05], 0x401000);
    assert_eq!(sbb_al_imm.text, "sbb al, 0x5");
    assert_eq!(sbb_al_imm.size, 2);
    assert_eq!(sbb_al_imm.kind, InstructionKind::Arithmetic);

    let and_al_imm = decode(&[0x24, 0xf0], 0x401000);
    assert_eq!(and_al_imm.text, "and al, 0xf0");
    assert_eq!(and_al_imm.size, 2);
    assert_eq!(and_al_imm.kind, InstructionKind::Logical);

    let sub_al_imm = decode(&[0x2c, 0x20], 0x401000);
    assert_eq!(sub_al_imm.text, "sub al, 0x20");
    assert_eq!(sub_al_imm.size, 2);
    assert_eq!(sub_al_imm.kind, InstructionKind::Arithmetic);

    let cmp_eax_imm = decode(&[0x3d, 0x00, 0x01, 0x00, 0x00], 0x401000);
    assert_eq!(cmp_eax_imm.text, "cmp eax, 0x100");
    assert_eq!(cmp_eax_imm.size, 5);
    assert_eq!(cmp_eax_imm.kind, InstructionKind::Compare);

    let cmp_rax_imm = decode(&[0x48, 0x3d, 0x00, 0x01, 0x00, 0x00], 0x401000);
    assert_eq!(cmp_rax_imm.text, "cmp rax, 0x100");
    assert_eq!(cmp_rax_imm.size, 6);
    assert_eq!(cmp_rax_imm.kind, InstructionKind::Compare);

    let test_eax_imm = decode(&[0xa9, 0x00, 0x01, 0x00, 0x00], 0x401000);
    assert_eq!(test_eax_imm.text, "test eax, 0x100");
    assert_eq!(test_eax_imm.size, 5);
    assert_eq!(test_eax_imm.kind, InstructionKind::Compare);

    let test_rax_imm = decode(&[0x48, 0xa9, 0x00, 0x01, 0x00, 0x00], 0x401000);
    assert_eq!(test_rax_imm.text, "test rax, 0x100");
    assert_eq!(test_rax_imm.size, 6);
    assert_eq!(test_rax_imm.kind, InstructionKind::Compare);

    let add_byte_reg = decode(&[0x02, 0xc1], 0x401000);
    assert_eq!(add_byte_reg.text, "add al, cl");
    assert_eq!(add_byte_reg.size, 2);
    assert_eq!(add_byte_reg.kind, InstructionKind::Arithmetic);

    let or_byte_reg = decode(&[0x08, 0xc8], 0x401000);
    assert_eq!(or_byte_reg.text, "or al, cl");
    assert_eq!(or_byte_reg.size, 2);
    assert_eq!(or_byte_reg.kind, InstructionKind::Logical);

    let and_eax_imm = decode(&[0x25, 0xff, 0xff, 0xff, 0x1f], 0x401000);
    assert_eq!(and_eax_imm.text, "and eax, 0x1fffffff");
    assert_eq!(and_eax_imm.size, 5);
    assert_eq!(and_eax_imm.kind, InstructionKind::Logical);

    let add_eax_imm = decode(&[0x05, 0x19, 0x01, 0x00, 0x00], 0x401000);
    assert_eq!(add_eax_imm.text, "add eax, 0x119");
    assert_eq!(add_eax_imm.size, 5);
    assert_eq!(add_eax_imm.kind, InstructionKind::Arithmetic);

    let or_eax_imm = decode(&[0x0d, 0x7c, 0x92, 0x14, 0x00], 0x401000);
    assert_eq!(or_eax_imm.text, "or eax, 0x14927c");
    assert_eq!(or_eax_imm.size, 5);
    assert_eq!(or_eax_imm.kind, InstructionKind::Logical);

    let adc_eax_imm = decode(&[0x15, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(adc_eax_imm.text, "adc eax, 0x1234");
    assert_eq!(adc_eax_imm.size, 5);
    assert_eq!(adc_eax_imm.kind, InstructionKind::Arithmetic);

    let sbb_eax_imm = decode(&[0x1d, 0x05, 0x93, 0x14, 0x00], 0x401000);
    assert_eq!(sbb_eax_imm.text, "sbb eax, 0x149305");
    assert_eq!(sbb_eax_imm.size, 5);
    assert_eq!(sbb_eax_imm.kind, InstructionKind::Arithmetic);

    let sub_eax_imm = decode(&[0x2d, 0x20, 0x05, 0x93, 0x19], 0x401000);
    assert_eq!(sub_eax_imm.text, "sub eax, 0x19930520");
    assert_eq!(sub_eax_imm.size, 5);
    assert_eq!(sub_eax_imm.kind, InstructionKind::Arithmetic);

    let xor_eax_imm = decode(&[0x35, 0x1b, 0x94, 0x14, 0x00], 0x401000);
    assert_eq!(xor_eax_imm.text, "xor eax, 0x14941b");
    assert_eq!(xor_eax_imm.size, 5);
    assert_eq!(xor_eax_imm.kind, InstructionKind::Logical);

    let adc_reg = decode(&[0x13, 0xd1], 0x401000);
    assert_eq!(adc_reg.text, "adc edx, ecx");
    assert_eq!(adc_reg.size, 2);
    assert_eq!(adc_reg.kind, InstructionKind::Arithmetic);

    let sbb_reg = decode(&[0x1b, 0xc9], 0x401000);
    assert_eq!(sbb_reg.text, "sbb ecx, ecx");
    assert_eq!(sbb_reg.size, 2);
    assert_eq!(sbb_reg.kind, InstructionKind::Arithmetic);

    let cmpxchg = decode(&[0xf0, 0x0f, 0xb0, 0x0c, 0x13], 0x401000);
    assert_eq!(cmpxchg.text, "cmpxchg [rbx+rdx], cl");
    assert_eq!(cmpxchg.size, 5);
    assert_eq!(cmpxchg.kind, InstructionKind::Compare);

    let cmpxchg_word = decode(&[0x66, 0x0f, 0xb1, 0xc8], 0x401000);
    assert_eq!(cmpxchg_word.text, "cmpxchg ax, cx");
    assert_eq!(cmpxchg_word.size, 4);
    assert_eq!(cmpxchg_word.kind, InstructionKind::Compare);

    let cmpxchg_dword = decode(&[0x0f, 0xb1, 0xc8], 0x401000);
    assert_eq!(cmpxchg_dword.text, "cmpxchg eax, ecx");
    assert_eq!(cmpxchg_dword.size, 3);
    assert_eq!(cmpxchg_dword.kind, InstructionKind::Compare);

    let cmpxchg_qword = decode(&[0x48, 0x0f, 0xb1, 0x10], 0x401000);
    assert_eq!(cmpxchg_qword.text, "cmpxchg [rax], rdx");
    assert_eq!(cmpxchg_qword.size, 4);
    assert_eq!(cmpxchg_qword.kind, InstructionKind::Compare);

    let xadd = decode(&[0xf0, 0x0f, 0xc1, 0x81, 0x5c, 0x01, 0x00, 0x00], 0x401000);
    assert_eq!(xadd.text, "xadd [rcx+0x15c], eax");
    assert_eq!(xadd.size, 8);
    assert_eq!(xadd.kind, InstructionKind::Arithmetic);

    let imul_reg = decode(&[0x0f, 0xaf, 0xd0], 0x401000);
    assert_eq!(imul_reg.text, "imul edx, eax");
    assert_eq!(imul_reg.size, 3);
    assert_eq!(imul_reg.kind, InstructionKind::Arithmetic);

    let imul_mem = decode(&[0x48, 0x0f, 0xaf, 0x08], 0x401000);
    assert_eq!(imul_mem.text, "imul rcx, [rax]");
    assert_eq!(imul_mem.size, 4);
    assert_eq!(imul_mem.kind, InstructionKind::Arithmetic);

    let imul_imm32 = decode(&[0x69, 0xde, 0xc8, 0x03, 0x00, 0x00], 0x401000);
    assert_eq!(imul_imm32.text, "imul ebx, esi, 0x3c8");
    assert_eq!(imul_imm32.size, 6);
    assert_eq!(imul_imm32.kind, InstructionKind::Arithmetic);

    let imul_imm8 = decode(&[0x48, 0x6b, 0xc0, 0x01], 0x401000);
    assert_eq!(imul_imm8.text, "imul rax, rax, 0x1");
    assert_eq!(imul_imm8.size, 4);
    assert_eq!(imul_imm8.kind, InstructionKind::Arithmetic);

    let cmp_byte_reg = decode(&[0x38, 0xc8], 0x401000);
    assert_eq!(cmp_byte_reg.text, "cmp al, cl");
    assert_eq!(cmp_byte_reg.size, 2);
    assert_eq!(cmp_byte_reg.kind, InstructionKind::Compare);

    let bt_reg = decode(&[0x0f, 0xa3, 0xc8], 0x401000);
    assert_eq!(bt_reg.text, "bt eax, ecx");
    assert_eq!(bt_reg.size, 3);
    assert_eq!(bt_reg.kind, InstructionKind::Compare);

    let bsf_reg = decode(&[0x0f, 0xbc, 0xc8], 0x401000);
    assert_eq!(bsf_reg.text, "bsf ecx, eax");
    assert_eq!(bsf_reg.size, 3);
    assert_eq!(bsf_reg.kind, InstructionKind::Logical);

    let bsf_mem = decode(&[0x48, 0x0f, 0xbc, 0x08], 0x401000);
    assert_eq!(bsf_mem.text, "bsf rcx, [rax]");
    assert_eq!(bsf_mem.size, 4);
    assert_eq!(bsf_mem.kind, InstructionKind::Logical);

    let bsr_reg = decode(&[0x0f, 0xbd, 0xc9], 0x401000);
    assert_eq!(bsr_reg.text, "bsr ecx, ecx");
    assert_eq!(bsr_reg.size, 3);
    assert_eq!(bsr_reg.kind, InstructionKind::Logical);

    let movzx_word = decode(&[0x0f, 0xb7, 0x07], 0x401000);
    assert_eq!(movzx_word.text, "movzx eax, [rdi]");
    assert_eq!(movzx_word.size, 3);
    assert_eq!(movzx_word.kind, InstructionKind::Load);

    let movzx_word_64 = decode(&[0x48, 0x0f, 0xb7, 0x07], 0x401000);
    assert_eq!(movzx_word_64.text, "movzx rax, [rdi]");
    assert_eq!(movzx_word_64.size, 4);
    assert_eq!(movzx_word_64.kind, InstructionKind::Load);

    let bt_imm = decode(&[0x0f, 0xba, 0xe0, 0x09], 0x401000);
    assert_eq!(bt_imm.text, "bt eax, 0x9");
    assert_eq!(bt_imm.size, 4);
    assert_eq!(bt_imm.kind, InstructionKind::Compare);

    let bts_imm = decode(&[0x0f, 0xba, 0x2b, 0x08], 0x401000);
    assert_eq!(bts_imm.text, "bts [rbx], 0x8");
    assert_eq!(bts_imm.size, 4);
    assert_eq!(bts_imm.kind, InstructionKind::Logical);

    let bts_reg = decode(&[0x0f, 0xab, 0xc1], 0x401000);
    assert_eq!(bts_reg.text, "bts ecx, eax");
    assert_eq!(bts_reg.size, 3);
    assert_eq!(bts_reg.kind, InstructionKind::Logical);

    let btr_imm = decode(&[0x0f, 0xba, 0x33, 0x07], 0x401000);
    assert_eq!(btr_imm.text, "btr [rbx], 0x7");
    assert_eq!(btr_imm.size, 4);
    assert_eq!(btr_imm.kind, InstructionKind::Logical);

    let btc_imm = decode(&[0x0f, 0xba, 0x3b, 0x0c], 0x401000);
    assert_eq!(btc_imm.text, "btc [rbx], 0xc");
    assert_eq!(btc_imm.size, 4);
    assert_eq!(btc_imm.kind, InstructionKind::Logical);

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

    let rcl_dl_cl = decode(&[0xd2, 0xd2], 0x401000);
    assert_eq!(rcl_dl_cl.text, "rcl dl, cl");
    assert_eq!(rcl_dl_cl.size, 2);
    assert_eq!(rcl_dl_cl.kind, InstructionKind::Logical);

    let rcl_mem8_cl = decode(&[0xd2, 0x12], 0x401000);
    assert_eq!(rcl_mem8_cl.text, "rcl [rdx], cl");
    assert_eq!(rcl_mem8_cl.size, 2);
    assert_eq!(rcl_mem8_cl.kind, InstructionKind::Logical);
    let mem = memory_operand(&rcl_mem8_cl.operands[0]);
    assert_eq!(mem.width_bits, Some(8));

    let ror_eax_cl = decode(&[0xd3, 0xc8], 0x401000);
    assert_eq!(ror_eax_cl.text, "ror eax, cl");
    assert_eq!(ror_eax_cl.size, 2);
    assert_eq!(ror_eax_cl.kind, InstructionKind::Logical);

    let rcl_ebx_cl = decode(&[0xd3, 0xd3], 0x401000);
    assert_eq!(rcl_ebx_cl.text, "rcl ebx, cl");
    assert_eq!(rcl_ebx_cl.size, 2);
    assert_eq!(rcl_ebx_cl.kind, InstructionKind::Logical);

    let shr_rax_cl = decode(&[0x48, 0xd3, 0xe8], 0x401000);
    assert_eq!(shr_rax_cl.text, "shr rax, cl");
    assert_eq!(shr_rax_cl.size, 3);
    assert_eq!(shr_rax_cl.kind, InstructionKind::Logical);
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
fn decodes_x86_64_xchg_forms() {
    let xchg_reg = decode(&[0x87, 0xc8], 0x401000);
    assert_eq!(xchg_reg.text, "xchg eax, ecx");
    assert_eq!(xchg_reg.size, 2);
    assert_eq!(xchg_reg.kind, InstructionKind::Move);

    let xchg_byte_mem = decode(&[0x86, 0x03], 0x401000);
    assert_eq!(xchg_byte_mem.text, "xchg [rbx], al");
    assert_eq!(xchg_byte_mem.size, 2);
    assert_eq!(xchg_byte_mem.kind, InstructionKind::Move);
    let mem = memory_operand(&xchg_byte_mem.operands[0]);
    assert_eq!(mem.width_bits, Some(8));

    let xchg_eax_ecx = decode(&[0x91], 0x401000);
    assert_eq!(xchg_eax_ecx.text, "xchg ecx, eax");
    assert_eq!(xchg_eax_ecx.size, 1);
    assert_eq!(xchg_eax_ecx.kind, InstructionKind::Move);

    let xchg_rax_rcx = decode(&[0x48, 0x91], 0x401000);
    assert_eq!(xchg_rax_rcx.text, "xchg rcx, rax");
    assert_eq!(xchg_rax_rcx.size, 2);
    assert_eq!(xchg_rax_rcx.kind, InstructionKind::Move);

    let xchg_mem = decode(&[0x87, 0x84, 0xf6, 0xf0, 0xff, 0x4f, 0x00], 0x401000);
    assert_eq!(xchg_mem.text, "xchg [rsi+rsi*8+0x4ffff0], eax");
    assert_eq!(xchg_mem.size, 7);
    assert_eq!(xchg_mem.kind, InstructionKind::Move);
}

#[test]
fn decodes_x86_64_accumulator_and_string_unary_forms() {
    let cwde = decode(&[0x98], 0x401000);
    assert_eq!(cwde.text, "cwde");
    assert_eq!(cwde.size, 1);
    assert_eq!(cwde.kind, InstructionKind::Arithmetic);

    let cdqe = decode(&[0x48, 0x98], 0x401000);
    assert_eq!(cdqe.text, "cdqe");
    assert_eq!(cdqe.size, 2);
    assert_eq!(cdqe.kind, InstructionKind::Arithmetic);

    let cdq = decode(&[0x99], 0x401000);
    assert_eq!(cdq.text, "cdq");
    assert_eq!(cdq.size, 1);
    assert_eq!(cdq.kind, InstructionKind::Arithmetic);

    let cqo = decode(&[0x48, 0x99], 0x401000);
    assert_eq!(cqo.text, "cqo");
    assert_eq!(cqo.size, 2);
    assert_eq!(cqo.kind, InstructionKind::Arithmetic);

    let pushfq = decode(&[0x9c], 0x401000);
    assert_eq!(pushfq.text, "pushfq");
    assert_eq!(pushfq.size, 1);
    assert_eq!(pushfq.kind, InstructionKind::Store);

    let popfq = decode(&[0x9d], 0x401000);
    assert_eq!(popfq.text, "popfq");
    assert_eq!(popfq.size, 1);
    assert_eq!(popfq.kind, InstructionKind::Load);

    let sahf = decode(&[0x9e], 0x401000);
    assert_eq!(sahf.text, "sahf");
    assert_eq!(sahf.size, 1);
    assert_eq!(sahf.kind, InstructionKind::Move);

    let lahf = decode(&[0x9f], 0x401000);
    assert_eq!(lahf.text, "lahf");
    assert_eq!(lahf.size, 1);
    assert_eq!(lahf.kind, InstructionKind::Move);

    let movsb = decode(&[0xa4], 0x401000);
    assert_eq!(movsb.text, "movsb [rdi], [rsi]");
    assert_eq!(movsb.size, 1);
    assert_eq!(movsb.kind, InstructionKind::Move);

    let movsd = decode(&[0xa5], 0x401000);
    assert_eq!(movsd.text, "movsd [rdi], [rsi]");
    assert_eq!(movsd.size, 1);
    assert_eq!(movsd.kind, InstructionKind::Move);

    let movsq = decode(&[0x48, 0xa5], 0x401000);
    assert_eq!(movsq.text, "movsq [rdi], [rsi]");
    assert_eq!(movsq.size, 2);
    assert_eq!(movsq.kind, InstructionKind::Move);

    let cmpsb = decode(&[0xa6], 0x401000);
    assert_eq!(cmpsb.text, "cmpsb [rsi], [rdi]");
    assert_eq!(cmpsb.size, 1);
    assert_eq!(cmpsb.kind, InstructionKind::Compare);

    let cmpsd = decode(&[0xa7], 0x401000);
    assert_eq!(cmpsd.text, "cmpsd [rsi], [rdi]");
    assert_eq!(cmpsd.size, 1);
    assert_eq!(cmpsd.kind, InstructionKind::Compare);

    let stosb = decode(&[0xaa], 0x401000);
    assert_eq!(stosb.text, "stosb [rdi], al");
    assert_eq!(stosb.size, 1);
    assert_eq!(stosb.kind, InstructionKind::Store);

    let stosd = decode(&[0xab], 0x401000);
    assert_eq!(stosd.text, "stosd [rdi], eax");
    assert_eq!(stosd.size, 1);
    assert_eq!(stosd.kind, InstructionKind::Store);

    let lodsb = decode(&[0xac], 0x401000);
    assert_eq!(lodsb.text, "lodsb al, [rsi]");
    assert_eq!(lodsb.size, 1);
    assert_eq!(lodsb.kind, InstructionKind::Load);

    let lodsd = decode(&[0xad], 0x401000);
    assert_eq!(lodsd.text, "lodsd eax, [rsi]");
    assert_eq!(lodsd.size, 1);
    assert_eq!(lodsd.kind, InstructionKind::Load);

    let scasb = decode(&[0xae], 0x401000);
    assert_eq!(scasb.text, "scasb al, [rdi]");
    assert_eq!(scasb.size, 1);
    assert_eq!(scasb.kind, InstructionKind::Compare);

    let scasd = decode(&[0xaf], 0x401000);
    assert_eq!(scasd.text, "scasd eax, [rdi]");
    assert_eq!(scasd.size, 1);
    assert_eq!(scasd.kind, InstructionKind::Compare);
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
fn decodes_x86_64_stack_frame_forms() {
    let enter = decode(&[0xc8, 0x3c, 0x01, 0x01], 0x401000);
    assert_eq!(enter.text, "enter 0x13c, 0x1");
    assert_eq!(enter.size, 4);
    assert_eq!(enter.kind, InstructionKind::Store);

    let leave = decode(&[0xc9], 0x401000);
    assert_eq!(leave.text, "leave");
    assert_eq!(leave.size, 1);
    assert_eq!(leave.kind, InstructionKind::Load);
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

    let orps = decode(&[0x0f, 0x56, 0xc8], 0x401000);
    assert_eq!(orps.text, "orps xmm1, xmm0");
    assert_eq!(orps.size, 3);
    assert_eq!(orps.kind, InstructionKind::Logical);

    let orpd = decode(&[0x66, 0x0f, 0x56, 0xc8], 0x401000);
    assert_eq!(orpd.text, "orpd xmm1, xmm0");
    assert_eq!(orpd.size, 4);
    assert_eq!(orpd.kind, InstructionKind::Logical);

    let cmpps_reg = decode(&[0x0f, 0xc2, 0xc2, 0x00], 0x401000);
    assert_eq!(cmpps_reg.text, "cmpps xmm0, xmm2, 0x0");
    assert_eq!(cmpps_reg.size, 4);
    assert_eq!(cmpps_reg.kind, InstructionKind::Compare);

    let cmpps_mem = decode(&[0x0f, 0xc2, 0x44, 0x24, 0x20, 0x06], 0x401000);
    assert_eq!(cmpps_mem.text, "cmpps xmm0, [rsp+0x20], 0x6");
    assert_eq!(cmpps_mem.size, 6);
    assert_eq!(cmpps_mem.kind, InstructionKind::Compare);

    let mulps = decode(&[0x0f, 0x59, 0xd1], 0x401000);
    assert_eq!(mulps.text, "mulps xmm2, xmm1");
    assert_eq!(mulps.size, 3);
    assert_eq!(mulps.kind, InstructionKind::Arithmetic);

    let mulsd = decode(&[0xf2, 0x0f, 0x59, 0xe2], 0x401000);
    assert_eq!(mulsd.text, "mulsd xmm4, xmm2");
    assert_eq!(mulsd.size, 4);
    assert_eq!(mulsd.kind, InstructionKind::Arithmetic);

    let addps = decode(&[0x0f, 0x58, 0xc1], 0x401000);
    assert_eq!(addps.text, "addps xmm0, xmm1");
    assert_eq!(addps.size, 3);
    assert_eq!(addps.kind, InstructionKind::Arithmetic);

    let addsd = decode(&[0xf2, 0x0f, 0x58, 0xc3], 0x401000);
    assert_eq!(addsd.text, "addsd xmm0, xmm3");
    assert_eq!(addsd.size, 4);
    assert_eq!(addsd.kind, InstructionKind::Arithmetic);

    let subps = decode(&[0x0f, 0x5c, 0xe6], 0x401000);
    assert_eq!(subps.text, "subps xmm4, xmm6");
    assert_eq!(subps.size, 3);
    assert_eq!(subps.kind, InstructionKind::Arithmetic);

    let divps = decode(&[0x0f, 0x5e, 0xca], 0x401000);
    assert_eq!(divps.text, "divps xmm1, xmm2");
    assert_eq!(divps.size, 3);
    assert_eq!(divps.kind, InstructionKind::Arithmetic);

    let andps = decode(&[0x0f, 0x54, 0xc1], 0x401000);
    assert_eq!(andps.text, "andps xmm0, xmm1");
    assert_eq!(andps.size, 3);
    assert_eq!(andps.kind, InstructionKind::Logical);

    let ucomiss = decode(&[0x0f, 0x2e, 0xc1], 0x401000);
    assert_eq!(ucomiss.text, "ucomiss xmm0, xmm1");
    assert_eq!(ucomiss.size, 3);
    assert_eq!(ucomiss.kind, InstructionKind::Compare);

    let comisd = decode(&[0x66, 0x0f, 0x2f, 0xc1], 0x401000);
    assert_eq!(comisd.text, "comisd xmm0, xmm1");
    assert_eq!(comisd.size, 4);
    assert_eq!(comisd.kind, InstructionKind::Compare);
}

#[test]
fn decodes_x86_64_mmx_forms() {
    let movq_load = decode(&[0x0f, 0x6f, 0x74, 0x24, 0x20], 0x401000);
    assert_eq!(movq_load.text, "movq mm6, [rsp+0x20]");
    assert_eq!(movq_load.size, 5);
    assert_eq!(movq_load.kind, InstructionKind::Load);

    let pavgb = decode(&[0x0f, 0xe0, 0xe0], 0x401000);
    assert_eq!(pavgb.text, "pavgb mm4, mm0");
    assert_eq!(pavgb.size, 3);
    assert_eq!(pavgb.kind, InstructionKind::Arithmetic);

    let pmaddwd = decode(&[0x0f, 0xf5, 0xff], 0x401000);
    assert_eq!(pmaddwd.text, "pmaddwd mm7, mm7");
    assert_eq!(pmaddwd.size, 3);
    assert_eq!(pmaddwd.kind, InstructionKind::Arithmetic);

    let psllw = decode(&[0x0f, 0xf1, 0xf1], 0x401000);
    assert_eq!(psllw.text, "psllw mm6, mm1");
    assert_eq!(psllw.size, 3);
    assert_eq!(psllw.kind, InstructionKind::Logical);

    let paddw = decode(&[0x0f, 0xfd, 0xfd], 0x401000);
    assert_eq!(paddw.text, "paddw mm7, mm5");
    assert_eq!(paddw.size, 3);
    assert_eq!(paddw.kind, InstructionKind::Arithmetic);

    let pmovmskb = decode(&[0x0f, 0xd7, 0xd7], 0x401000);
    assert_eq!(pmovmskb.text, "pmovmskb edx, mm7");
    assert_eq!(pmovmskb.size, 3);
    assert_eq!(pmovmskb.kind, InstructionKind::Move);

    let movd = decode(&[0x0f, 0x7e, 0xc0], 0x401000);
    assert_eq!(movd.text, "movd eax, mm0");
    assert_eq!(movd.size, 3);
    assert_eq!(movd.kind, InstructionKind::Move);

    let movd_to_mmx = decode(&[0x0f, 0x6e, 0xc0], 0x401000);
    assert_eq!(movd_to_mmx.text, "movd mm0, eax");
    assert_eq!(movd_to_mmx.size, 3);
    assert_eq!(movd_to_mmx.kind, InstructionKind::Move);

    let movd_to_xmm = decode(&[0x66, 0x0f, 0x6e, 0xc0], 0x401000);
    assert_eq!(movd_to_xmm.text, "movd xmm0, eax");
    assert_eq!(movd_to_xmm.size, 4);
    assert_eq!(movd_to_xmm.kind, InstructionKind::Move);

    let movq = decode(&[0x66, 0x48, 0x0f, 0x7e, 0xc1], 0x401000);
    assert_eq!(movq.text, "movq rcx, xmm0");
    assert_eq!(movq.size, 5);
    assert_eq!(movq.kind, InstructionKind::Move);

    let pcmpeqb_mmx = decode(&[0x0f, 0x74, 0xc8], 0x401000);
    assert_eq!(pcmpeqb_mmx.text, "pcmpeqb mm1, mm0");
    assert_eq!(pcmpeqb_mmx.size, 3);
    assert_eq!(pcmpeqb_mmx.kind, InstructionKind::Compare);

    let pcmpeqb_xmm = decode(&[0x66, 0x0f, 0x74, 0xc1], 0x401000);
    assert_eq!(pcmpeqb_xmm.text, "pcmpeqb xmm0, xmm1");
    assert_eq!(pcmpeqb_xmm.size, 4);
    assert_eq!(pcmpeqb_xmm.kind, InstructionKind::Compare);

    let punpcklbw_mmx = decode(&[0x0f, 0x60, 0xc0], 0x401000);
    assert_eq!(punpcklbw_mmx.text, "punpcklbw mm0, mm0");
    assert_eq!(punpcklbw_mmx.size, 3);
    assert_eq!(punpcklbw_mmx.kind, InstructionKind::Move);

    let punpcklbw_xmm = decode(&[0x66, 0x0f, 0x60, 0xc0], 0x401000);
    assert_eq!(punpcklbw_xmm.text, "punpcklbw xmm0, xmm0");
    assert_eq!(punpcklbw_xmm.size, 4);
    assert_eq!(punpcklbw_xmm.kind, InstructionKind::Move);

    let pcmpgtb = decode(&[0x0f, 0x64, 0x0c, 0x0a], 0x401000);
    assert_eq!(pcmpgtb.text, "pcmpgtb mm1, [rdx+rcx]");
    assert_eq!(pcmpgtb.size, 4);
    assert_eq!(pcmpgtb.kind, InstructionKind::Compare);

    let pand = decode(&[0x66, 0x0f, 0xdb, 0x15, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(pand.text, "pand xmm2, [rip+0x1234]");
    assert_eq!(pand.size, 8);
    assert_eq!(pand.kind, InstructionKind::Logical);

    let psubd = decode(&[0x0f, 0xfa, 0x2d, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(psubd.text, "psubd mm5, [rip+0x1234]");
    assert_eq!(psubd.size, 7);
    assert_eq!(psubd.kind, InstructionKind::Arithmetic);

    let psubq = decode(&[0x0f, 0xfb, 0x1d, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(psubq.text, "psubq mm3, [rip+0x1234]");
    assert_eq!(psubq.size, 7);
    assert_eq!(psubq.kind, InstructionKind::Arithmetic);

    let psrlq = decode(&[0x0f, 0x73, 0xd0, 0x08], 0x401000);
    assert_eq!(psrlq.text, "psrlq mm0, 0x8");
    assert_eq!(psrlq.size, 4);
    assert_eq!(psrlq.kind, InstructionKind::Logical);

    let psllq = decode(&[0x0f, 0x73, 0xf2, 0x02], 0x401000);
    assert_eq!(psllq.text, "psllq mm2, 0x2");
    assert_eq!(psllq.size, 4);
    assert_eq!(psllq.kind, InstructionKind::Logical);

    let psrldq = decode(&[0x66, 0x0f, 0x73, 0xd9, 0x05], 0x401000);
    assert_eq!(psrldq.text, "psrldq xmm1, 0x5");
    assert_eq!(psrldq.size, 5);
    assert_eq!(psrldq.kind, InstructionKind::Logical);

    let pslldq = decode(&[0x66, 0x0f, 0x73, 0xfa, 0x0a], 0x401000);
    assert_eq!(pslldq.text, "pslldq xmm2, 0xa");
    assert_eq!(pslldq.size, 5);
    assert_eq!(pslldq.kind, InstructionKind::Logical);

    let por = decode(&[0x0f, 0xeb, 0xeb], 0x401000);
    assert_eq!(por.text, "por mm5, mm3");
    assert_eq!(por.size, 3);
    assert_eq!(por.kind, InstructionKind::Logical);

    let pxor = decode(&[0x66, 0x0f, 0xef, 0xc0], 0x401000);
    assert_eq!(pxor.text, "pxor xmm0, xmm0");
    assert_eq!(pxor.size, 4);
    assert_eq!(pxor.kind, InstructionKind::Logical);

    let pshufw = decode(&[0x0f, 0x70, 0xc1, 0x1b], 0x401000);
    assert_eq!(pshufw.text, "pshufw mm0, mm1, 0x1b");
    assert_eq!(pshufw.size, 4);
    assert_eq!(pshufw.kind, InstructionKind::Move);

    let pshufd = decode(&[0x66, 0x0f, 0x70, 0xc1, 0x1b], 0x401000);
    assert_eq!(pshufd.text, "pshufd xmm0, xmm1, 0x1b");
    assert_eq!(pshufd.size, 5);
    assert_eq!(pshufd.kind, InstructionKind::Move);
}

#[test]
fn decodes_x86_64_vex_avx_forms() {
    let vzeroupper = decode(&[0xc5, 0xf8, 0x77], 0x401000);
    assert_eq!(vzeroupper.text, "vzeroupper");
    assert_eq!(vzeroupper.size, 3);
    assert_eq!(vzeroupper.kind, InstructionKind::System);

    let vmovdqa_load = decode(&[0xc5, 0xf9, 0x6f, 0x74, 0x24, 0x20], 0x401000);
    assert_eq!(vmovdqa_load.text, "vmovdqa xmm6, [rsp+0x20]");
    assert_eq!(vmovdqa_load.size, 6);
    assert_eq!(vmovdqa_load.kind, InstructionKind::Load);

    let vmovdqu_load = decode(&[0xc5, 0xfe, 0x6f, 0x52, 0x20], 0x401000);
    assert_eq!(vmovdqu_load.text, "vmovdqu ymm2, [rdx+0x20]");
    assert_eq!(vmovdqu_load.size, 5);
    assert_eq!(vmovdqu_load.kind, InstructionKind::Load);

    let vmovdqu_indexed = decode(
        &[0xc4, 0xa1, 0x7e, 0x6f, 0x8c, 0x0a, 0x00, 0xff, 0xff, 0xff],
        0x401000,
    );
    assert_eq!(vmovdqu_indexed.text, "vmovdqu ymm1, [rdx+r9+-0x100]");
    assert_eq!(vmovdqu_indexed.size, 10);
    assert_eq!(vmovdqu_indexed.kind, InstructionKind::Load);

    let vmovdqu_store = decode(
        &[0xc4, 0xa1, 0x7e, 0x7f, 0x8c, 0x09, 0x00, 0xff, 0xff, 0xff],
        0x401000,
    );
    assert_eq!(vmovdqu_store.text, "vmovdqu [rcx+r9+-0x100], ymm1");
    assert_eq!(vmovdqu_store.size, 10);
    assert_eq!(vmovdqu_store.kind, InstructionKind::Store);

    let vmovntdq = decode(
        &[0xc4, 0xa1, 0x7d, 0xe7, 0x8c, 0x09, 0x00, 0xff, 0xff, 0xff],
        0x401000,
    );
    assert_eq!(vmovntdq.text, "vmovntdq [rcx+r9+-0x100], ymm1");
    assert_eq!(vmovntdq.size, 10);
    assert_eq!(vmovntdq.kind, InstructionKind::Store);

    let vpmovmskb = decode(&[0xc5, 0xf9, 0xd7, 0xc0], 0x401000);
    assert_eq!(vpmovmskb.text, "vpmovmskb eax, xmm0");
    assert_eq!(vpmovmskb.size, 4);
    assert_eq!(vpmovmskb.kind, InstructionKind::Move);

    let vmulps = decode(&[0xc5, 0xf8, 0x59, 0xd1], 0x401000);
    assert_eq!(vmulps.text, "vmulps xmm2, xmm0, xmm1");
    assert_eq!(vmulps.size, 4);
    assert_eq!(vmulps.kind, InstructionKind::Arithmetic);

    let vpand = decode(&[0xc5, 0xf9, 0xdb, 0x1d, 0x05, 0x93, 0x14, 0x00], 0x401000);
    assert_eq!(vpand.text, "vpand xmm3, xmm0, [rip+0x149305]");
    assert_eq!(vpand.size, 8);
    assert_eq!(vpand.kind, InstructionKind::Logical);

    let vpor = decode(&[0xc5, 0xf1, 0xeb, 0x0d, 0x93, 0x93, 0x14, 0x00], 0x401000);
    assert_eq!(vpor.text, "vpor xmm1, xmm1, [rip+0x149393]");
    assert_eq!(vpor.size, 8);
    assert_eq!(vpor.kind, InstructionKind::Logical);

    let vpaddq = decode(&[0xc5, 0xe1, 0xd4, 0xc9], 0x401000);
    assert_eq!(vpaddq.text, "vpaddq xmm1, xmm3, xmm1");
    assert_eq!(vpaddq.size, 4);
    assert_eq!(vpaddq.kind, InstructionKind::Arithmetic);

    let vsubsd = decode(&[0xc5, 0xfb, 0x5c, 0xc3], 0x401000);
    assert_eq!(vsubsd.text, "vsubsd xmm0, xmm0, xmm3");
    assert_eq!(vsubsd.size, 4);
    assert_eq!(vsubsd.kind, InstructionKind::Arithmetic);

    let vcomisd_reg = decode(&[0xc5, 0xf9, 0x2f, 0xc5], 0x401000);
    assert_eq!(vcomisd_reg.text, "vcomisd xmm0, xmm5");
    assert_eq!(vcomisd_reg.size, 4);
    assert_eq!(vcomisd_reg.kind, InstructionKind::Compare);

    let vcomisd_mem = decode(&[0xc5, 0xf9, 0x2f, 0x25, 0x07, 0x94, 0x14, 0x00], 0x401000);
    assert_eq!(vcomisd_mem.text, "vcomisd xmm4, [rip+0x149407]");
    assert_eq!(vcomisd_mem.size, 8);
    assert_eq!(vcomisd_mem.kind, InstructionKind::Compare);

    let vcvtdq2pd = decode(&[0xc5, 0xfa, 0xe6, 0xf3], 0x401000);
    assert_eq!(vcvtdq2pd.text, "vcvtdq2pd xmm6, xmm3");
    assert_eq!(vcvtdq2pd.size, 4);
    assert_eq!(vcvtdq2pd.kind, InstructionKind::Arithmetic);

    let vmovq_gpr = decode(&[0xc4, 0xe1, 0xf9, 0x7e, 0xc0], 0x401000);
    assert_eq!(vmovq_gpr.text, "vmovq rax, xmm0");
    assert_eq!(vmovq_gpr.size, 5);
    assert_eq!(vmovq_gpr.kind, InstructionKind::Move);

    let vfmsub213sd = decode(&[0xc4, 0xe2, 0xc9, 0xab, 0xe9], 0x401000);
    assert_eq!(vfmsub213sd.text, "vfmsub213sd xmm5, xmm6, xmm1");
    assert_eq!(vfmsub213sd.size, 5);
    assert_eq!(vfmsub213sd.kind, InstructionKind::Arithmetic);

    let vfmadd231sd = decode(&[0xc4, 0xe2, 0xd1, 0xb9, 0xc8], 0x401000);
    assert_eq!(vfmadd231sd.text, "vfmadd231sd xmm1, xmm5, xmm0");
    assert_eq!(vfmadd231sd.size, 5);
    assert_eq!(vfmadd231sd.kind, InstructionKind::Arithmetic);

    let vinsertf128 = decode(&[0xc4, 0xe3, 0x7d, 0x18, 0xc0, 0x01], 0x401000);
    assert_eq!(vinsertf128.text, "vinsertf128 ymm0, ymm0, xmm0, 0x1");
    assert_eq!(vinsertf128.size, 6);
    assert_eq!(vinsertf128.kind, InstructionKind::Move);

    let vmovsd = decode(&[0xc5, 0xfb, 0x10, 0x2d, 0xb4, 0x92, 0x14, 0x00], 0x401000);
    assert_eq!(vmovsd.text, "vmovsd xmm5, [rip+0x1492b4]");
    assert_eq!(vmovsd.size, 8);
    assert_eq!(vmovsd.kind, InstructionKind::Load);

    let vmovapd = decode(&[0xc5, 0xf9, 0x28, 0xc2], 0x401000);
    assert_eq!(vmovapd.text, "vmovapd xmm0, xmm2");
    assert_eq!(vmovapd.size, 4);
    assert_eq!(vmovapd.kind, InstructionKind::Move);

    let vaddsd = decode(&[0xc5, 0xfb, 0x58, 0xc1], 0x401000);
    assert_eq!(vaddsd.text, "vaddsd xmm0, xmm0, xmm1");
    assert_eq!(vaddsd.size, 4);
    assert_eq!(vaddsd.kind, InstructionKind::Arithmetic);

    let vdivsd = decode(&[0xc5, 0xfb, 0x5e, 0xca], 0x401000);
    assert_eq!(vdivsd.text, "vdivsd xmm1, xmm0, xmm2");
    assert_eq!(vdivsd.size, 4);
    assert_eq!(vdivsd.kind, InstructionKind::Arithmetic);

    let vpxor = decode(&[0xc5, 0xd1, 0xef, 0xed], 0x401000);
    assert_eq!(vpxor.text, "vpxor xmm5, xmm5, xmm5");
    assert_eq!(vpxor.size, 4);
    assert_eq!(vpxor.kind, InstructionKind::Logical);

    let vpsubd = decode(&[0xc5, 0xd1, 0xfa, 0x2d, 0x6e, 0x92, 0x14, 0x00], 0x401000);
    assert_eq!(vpsubd.text, "vpsubd xmm5, xmm5, [rip+0x14926e]");
    assert_eq!(vpsubd.size, 8);
    assert_eq!(vpsubd.kind, InstructionKind::Arithmetic);

    let vpsubq = decode(&[0xc5, 0xe1, 0xfb, 0x1d, 0x1b, 0x93, 0x14, 0x00], 0x401000);
    assert_eq!(vpsubq.text, "vpsubq xmm3, xmm3, [rip+0x14931b]");
    assert_eq!(vpsubq.size, 8);
    assert_eq!(vpsubq.kind, InstructionKind::Arithmetic);

    let vpsrlq = decode(&[0xc5, 0xe1, 0x73, 0xd2, 0x34], 0x401000);
    assert_eq!(vpsrlq.text, "vpsrlq xmm3, xmm2, 0x34");
    assert_eq!(vpsrlq.size, 5);
    assert_eq!(vpsrlq.kind, InstructionKind::Logical);

    let vpsllq = decode(&[0xc5, 0xe1, 0x73, 0xf3, 0x20], 0x401000);
    assert_eq!(vpsllq.text, "vpsllq xmm3, xmm3, 0x20");
    assert_eq!(vpsllq.size, 5);
    assert_eq!(vpsllq.kind, InstructionKind::Logical);
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
