use crate::{
    arch::{aarch64::adapters, x86_64::adapters as x86_adapters},
    error::{DecodeError, EncodeError, TextError},
    form::{FormSchema, MemorySpec},
    model::{Architecture, DecodeStatus, Instruction, MemoryOperand, Operand},
    runtime::{layout::LayoutView, ValueMap},
};

pub fn build_instruction(
    form: &FormSchema,
    layout: &LayoutView,
    values: &ValueMap,
) -> Result<Instruction, DecodeError> {
    let (architecture, address, bytes) = match layout {
        LayoutView::Aarch64Word { word, address } => {
            (Architecture::Aarch64, *address, word.to_le_bytes().to_vec())
        }
        LayoutView::X86ByteStream { bytes, address } => {
            (Architecture::X86_64, *address, bytes.clone())
        }
    };

    let mnemonic = decode_mnemonic(form, values)?;
    if matches!(
        form.id().name().as_str(),
        "aarch64.mov_wide" | "aarch64.movk" | "aarch64.movn"
    ) && get_u32(values, "sf").unwrap_or(1) == 0
        && get_u32(values, "hw").unwrap_or(0) > 1
    {
        return Err(DecodeError::UnsupportedTarget);
    }
    let operands = build_operands(form, Some(layout), values, address, bytes.len() as u8)?;
    let branch_target = operands.iter().find_map(|operand| match operand {
        Operand::AbsoluteAddress(target) => Some(*target),
        _ => None,
    });

    Ok(Instruction {
        architecture,
        address,
        size: bytes.len() as u8,
        bytes,
        mnemonic,
        operands,
        text: String::new(),
        kind: form.kind(),
        flow: form.flow(),
        branch_target,
        status: DecodeStatus::Complete,
        form: Some(form.id().name()),
    })
}

pub fn build_instruction_from_values(
    architecture: Architecture,
    form: &FormSchema,
    address: u64,
    values: &ValueMap,
) -> Result<Instruction, TextError> {
    let mnemonic = decode_mnemonic(form, values)
        .map_err(|_| TextError::InvalidOperand(form.text_rule().mnemonic.to_string()))?;
    let size = instruction_size_for_form(form);
    let operands = build_operands(form, None, values, address, size)
        .map_err(|_| TextError::InvalidOperand(form.text_rule().mnemonic.to_string()))?;
    let branch_target = operands.iter().find_map(|operand| match operand {
        Operand::AbsoluteAddress(target) => Some(*target),
        _ => None,
    });

    Ok(Instruction {
        architecture,
        address,
        size,
        bytes: Vec::new(),
        mnemonic,
        operands,
        text: String::new(),
        kind: form.kind(),
        flow: form.flow(),
        branch_target,
        status: DecodeStatus::Complete,
        form: Some(form.id().name()),
    })
}

pub fn match_instruction(
    form: &FormSchema,
    instruction: &Instruction,
) -> Result<ValueMap, EncodeError> {
    let mut values = ValueMap::new();

    match form.id().name().as_str() {
        "aarch64.nop" => {}
        "x86_64.ret" | "x86_64.retf" if !instruction.operands.is_empty() => {
            return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
        }
        "x86_64.ret_imm16" | "x86_64.retf_imm16" => {
            let [Operand::Immediate(imm)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xffff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.cmp_al_imm8" => {
            match_fixed_operands(form, instruction)?;
            let [_, Operand::Immediate(imm)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.or_al_imm8" | "x86_64.adc_al_imm8" | "x86_64.sbb_al_imm8"
        | "x86_64.and_al_imm8" | "x86_64.sub_al_imm8" => {
            match_fixed_operands(form, instruction)?;
            let [_, Operand::Immediate(imm)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.add_r8_r8" | "x86_64.or_r8_r8" => {
            let [Operand::Register(first), Operand::Register(second)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let first_index = x86_adapters::parse_r8_register(&first.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let second_index = x86_adapters::parse_r8_register(&second.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            match form.id().name().as_str() {
                "x86_64.add_r8_r8" => {
                    values.insert("reg", i64::from(first_index));
                    values.insert("rm", i64::from(second_index));
                }
                "x86_64.or_r8_r8" => {
                    values.insert("rm", i64::from(first_index));
                    values.insert("reg", i64::from(second_index));
                }
                _ => unreachable!(),
            }
        }
        "x86_64.call_rel32" | "x86_64.jmp_rel32" | "x86_64.jne_rel32" => {
            let target = extract_absolute_target(instruction)?;
            let size = i64::from(instruction_size_for_form(form));
            let delta = i64::try_from(target)
                .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                - i64::try_from(instruction.address)
                    .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                - size;
            if !((i32::MIN as i64)..=(i32::MAX as i64)).contains(&delta) {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            values.insert("disp", delta);
        }
        "x86_64.jmp_rel8" | "x86_64.je_rel8" | "x86_64.loopne" | "x86_64.loope" | "x86_64.loop"
        | "x86_64.jrcxz" => {
            let target = extract_absolute_target(instruction)?;
            let size = i64::from(instruction_size_for_form(form));
            let delta = i64::try_from(target)
                .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                - i64::try_from(instruction.address)
                    .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                - size;
            if !((i8::MIN as i64)..=(i8::MAX as i64)).contains(&delta) {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            values.insert("disp", delta);
        }
        "x86_64.call_rm64" | "x86_64.jmp_rm64" => {
            let [Operand::Register(register)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rm = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
        }
        "x86_64.push_r64" | "x86_64.push_r64_rex" | "x86_64.pop_r64" | "x86_64.pop_r64_rex" => {
            let [Operand::Register(register)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let reg = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.mov_r32_imm32" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xffff_ffff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rd = x86_adapters::parse_r32_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rd", i64::from(rd));
            values.insert("imm", *imm);
        }
        "x86_64.mov_r8_imm8" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rd = x86_adapters::parse_r8_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rd", i64::from(rd));
            values.insert("imm", *imm);
        }
        "x86_64.mov_m8_r8" => {
            let [Operand::Memory(memory), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 8, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r8_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.mov_r8_m8" => {
            let [Operand::Register(dst), Operand::Memory(memory)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 8, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r8_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.mov_m8_imm8" => {
            let [Operand::Memory(memory), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 8, &instruction.mnemonic)?;
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.movsx_r32_m8" | "x86_64.movzx_r32_m8" => {
            let [Operand::Register(dst), Operand::Memory(memory)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 8, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r32_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.mov_r64_imm64" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rd = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rd", i64::from(rd));
            values.insert("imm", *imm);
        }
        "x86_64.mov_r64_r64" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rm = x86_adapters::parse_r64_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let reg = x86_adapters::parse_r64_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
            values.insert("reg", i64::from(reg));
        }
        "x86_64.mov_m64_r64" => {
            let [Operand::Memory(memory), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 64, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r64_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.mov_r64_imm32_c7" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !((i32::MIN as i64)..=(u32::MAX as i64)).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
            values.insert("imm", *imm);
        }
        "x86_64.mov_m64_imm32_c7" | "x86_64.cmp_m64_imm32" => {
            let [Operand::Memory(memory), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 64, &instruction.mnemonic)?;
            if !((i32::MIN as i64)..=(u32::MAX as i64)).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.mov_m16_imm16_c7" => {
            let [Operand::Memory(memory), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 16, &instruction.mnemonic)?;
            if !(0..=0xffff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.mov_r64_m64" | "x86_64.lea_r64_m" => {
            let [Operand::Register(dst), Operand::Memory(memory)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 64, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r64_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.movsxd_r32_m32" => {
            let [Operand::Register(dst), Operand::Memory(memory)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 32, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r32_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.movsxd_r64_r32" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let reg = x86_adapters::parse_r64_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let rm = x86_adapters::parse_r32_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
            values.insert("rm", i64::from(rm));
        }
        "x86_64.add_r64_imm8"
        | "x86_64.or_r64_imm8"
        | "x86_64.adc_r64_imm8"
        | "x86_64.sbb_r64_imm8"
        | "x86_64.and_r64_imm8" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
            values.insert("imm", *imm);
        }
        "x86_64.cmp_m8_imm8" => {
            let [Operand::Memory(memory), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 8, &instruction.mnemonic)?;
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.cmp_eax_imm32"
        | "x86_64.cmp_rax_imm32"
        | "x86_64.test_eax_imm32"
        | "x86_64.test_rax_imm32"
        | "x86_64.and_eax_imm32"
        | "x86_64.add_eax_imm32"
        | "x86_64.or_eax_imm32"
        | "x86_64.adc_eax_imm32"
        | "x86_64.sbb_eax_imm32"
        | "x86_64.sub_eax_imm32"
        | "x86_64.xor_eax_imm32" => {
            match_fixed_operands(form, instruction)?;
            let [_, Operand::Immediate(imm)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xffff_ffff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.add_r64_imm32" | "x86_64.xor_r64_imm32" | "x86_64.test_r64_imm32" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xffff_ffff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
            values.insert("imm", *imm);
        }
        "x86_64.cmpxchg_r16_r16" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rm = x86_adapters::parse_r16_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let reg = x86_adapters::parse_r16_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
            values.insert("reg", i64::from(reg));
        }
        "x86_64.cmovb_r32_r32"
        | "x86_64.adc_r32_r32"
        | "x86_64.sbb_r32_r32"
        | "x86_64.cmpxchg_r32_r32" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (reg, rm) = if form.id().name() == "x86_64.cmpxchg_r32_r32" {
                (
                    x86_adapters::parse_r32_register(&src.name).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                    x86_adapters::parse_r32_register(&dst.name).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                )
            } else {
                (
                    x86_adapters::parse_r32_register(&dst.name).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                    x86_adapters::parse_r32_register(&src.name).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                )
            };
            if reg >= 8 || rm >= 8 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("reg", i64::from(reg));
            values.insert("rm", i64::from(rm));
        }
        "x86_64.cmpxchg_lock_m8_r8" => {
            let [Operand::Memory(memory), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 8, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r8_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.cmpxchg_m64_r64" => {
            let [Operand::Memory(memory), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 64, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r64_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.movq_mm_m64" => {
            let [Operand::Register(dst), Operand::Memory(memory)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 64, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_mm_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.movups_xmm_m128" | "x86_64.movaps_xmm_m128" | "x86_64.vmovdqa_xmm_m128" => {
            let [Operand::Register(dst), Operand::Memory(memory)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 128, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_xmm_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.movups_m128_xmm" | "x86_64.movaps_m128_xmm" => {
            let [Operand::Memory(memory), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 128, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_xmm_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.cmovae_r64_r64" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let reg = x86_adapters::parse_r64_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let rm = x86_adapters::parse_r64_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
            values.insert("rm", i64::from(rm));
        }
        "x86_64.bswap_r32" => {
            let [Operand::Register(register)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rd = x86_adapters::parse_r32_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if rd >= 8 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("rd", i64::from(rd));
        }
        "x86_64.not_r64"
        | "x86_64.neg_r64"
        | "x86_64.inc_r64_groupff"
        | "x86_64.dec_r64_groupff"
        | "x86_64.push_r64_groupff" => {
            let [Operand::Register(register)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rm = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
        }
        "x86_64.imul_m64" => {
            let [Operand::Memory(memory)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 64, &instruction.mnemonic)?;
        }
        "x86_64.imul_r32_r32" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let reg = x86_adapters::parse_r32_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let rm = x86_adapters::parse_r32_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if reg >= 8 || rm >= 8 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("reg", i64::from(reg));
            values.insert("rm", i64::from(rm));
        }
        "x86_64.imul_r64_m64" => {
            let [Operand::Register(dst), Operand::Memory(memory)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 64, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r64_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.idiv_r64" => {
            let [Operand::Register(register)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rm = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
        }
        "x86_64.inc_m8_groupfe" => {
            let [Operand::Memory(memory)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 8, &instruction.mnemonic)?;
        }
        "x86_64.dec_r8_groupfe" => {
            let [Operand::Register(register)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rm = x86_adapters::parse_r8_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
        }
        "x86_64.shr_r8_imm8" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r8_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
            values.insert("imm", *imm);
        }
        "x86_64.rol_m32_imm8" => {
            let [Operand::Memory(memory), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 32, &instruction.mnemonic)?;
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.sar_r64_imm8" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
            values.insert("imm", *imm);
        }
        "x86_64.shl_r32_one" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if *imm != 1 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r32_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
            values.insert("imm", 1);
        }
        "x86_64.shr_r64_one" => {
            let [Operand::Register(register), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if *imm != 1 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
            values.insert("imm", 1);
        }
        "x86_64.rcl_r8_cl" => {
            let [Operand::Register(register), Operand::Register(count)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if count.name != "cl" {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r8_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
        }
        "x86_64.rcl_m8_cl" => {
            let [Operand::Memory(memory), Operand::Register(count)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if count.name != "cl" {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            ensure_x86_memory_width(memory, 8, &instruction.mnemonic)?;
        }
        "x86_64.ror_r32_cl" | "x86_64.rcl_r32_cl" => {
            let [Operand::Register(register), Operand::Register(count)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if count.name != "cl" {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r32_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
        }
        "x86_64.shr_r64_cl" => {
            let [Operand::Register(register), Operand::Register(count)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if count.name != "cl" {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rm = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rm", i64::from(rm));
        }
        "x86_64.xchg_r32_r32" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rm = x86_adapters::parse_r32_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let reg = x86_adapters::parse_r32_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if rm >= 8 || reg >= 8 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("rm", i64::from(rm));
            values.insert("reg", i64::from(reg));
        }
        "x86_64.xchg_m8_r8" => {
            let [Operand::Memory(memory), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 8, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r8_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.xchg_m32_r32" => {
            let [Operand::Memory(memory), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 32, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r32_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.xadd_lock_m32_r32" => {
            let [Operand::Memory(memory), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 32, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_r32_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.xchg_eax_r32" => {
            let [Operand::Register(register), Operand::Register(fixed)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if fixed.name != "eax" {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let reg = x86_adapters::parse_r32_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if reg >= 8 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("reg", i64::from(reg));
        }
        "x86_64.xchg_rax_r64" => {
            let [Operand::Register(register), Operand::Register(fixed)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if fixed.name != "rax" {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let reg = x86_adapters::parse_r64_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.pavgb_mm_mm" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let reg = x86_adapters::parse_mm_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let rm = x86_adapters::parse_mm_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
            values.insert("rm", i64::from(rm));
        }
        "x86_64.vmovdqu_ymm_m256_c5" | "x86_64.vmovdqu_ymm_m256_c4" => {
            let [Operand::Register(dst), Operand::Memory(memory)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 256, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_ymm_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if form.id().name() == "x86_64.vmovdqu_ymm_m256_c5" {
                let encoded = x86_adapters::encode_modrm_memory(memory)?;
                if encoded.rex_x != 0 || encoded.rex_b != 0 {
                    return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
                }
            }
            values.insert("reg", i64::from(reg));
        }
        "x86_64.vmovdqu_m256_ymm_c4" | "x86_64.vmovntdq_m256_ymm_c4" => {
            let [Operand::Memory(memory), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            ensure_x86_memory_width(memory, 256, &instruction.mnemonic)?;
            let reg = x86_adapters::parse_ymm_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("reg", i64::from(reg));
        }
        "x86_64.vpmovmskb_r32_xmm" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let reg = x86_adapters::parse_r32_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let rm = x86_adapters::parse_xmm_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if rm >= 8 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("reg", i64::from(reg));
            values.insert("rm", i64::from(rm));
        }
        "x86_64.sete_r8" => {
            let [Operand::Register(register)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rm = x86_adapters::parse_r8_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if rm >= 8 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("rm", i64::from(rm));
        }
        "x86_64.setne_m8" | "x86_64.stmxcsr_m32" | "x86_64.ldmxcsr_m32" | "x86_64.fimul_m32"
        | "x86_64.fistp_m32" | "x86_64.fstp_m64" | "x86_64.fisttp_m64" => {
            let [Operand::Memory(memory)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let width = match form.id().name().as_str() {
                "x86_64.setne_m8" => 8,
                "x86_64.fstp_m64" | "x86_64.fisttp_m64" => 64,
                _ => 32,
            };
            ensure_x86_memory_width(memory, width, &instruction.mnemonic)?;
        }
        "x86_64.int3" | "x86_64.int1" | "x86_64.cmc" | "x86_64.sti" | "x86_64.leave"
        | "x86_64.cwde" | "x86_64.cdqe" | "x86_64.cdq" | "x86_64.cqo" | "x86_64.pushfq"
        | "x86_64.popfq" | "x86_64.sahf" | "x86_64.lahf" | "x86_64.xgetbv" | "x86_64.cpuid"
        | "x86_64.iretd" | "x86_64.iretq" | "x86_64.nop" | "x86_64.nop_4" | "x86_64.nop_5"
        | "x86_64.nop_9" | "x86_64.ud2"
            if !instruction.operands.is_empty() =>
        {
            return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
        }
        "x86_64.sfence" | "x86_64.vzeroupper" if !instruction.operands.is_empty() => {
            return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
        }
        "x86_64.int_imm8" => {
            let [Operand::Immediate(imm)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "x86_64.enter" => {
            let [Operand::Immediate(frame), Operand::Immediate(nesting)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xffff).contains(frame) || !(0..=0xff).contains(nesting) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("frame", *frame);
            values.insert("nesting", *nesting);
        }
        "x86_64.movsb" | "x86_64.movsd" | "x86_64.movsq" | "x86_64.cmpsb" | "x86_64.cmpsd"
        | "x86_64.stosb" | "x86_64.stosd" | "x86_64.lodsb" | "x86_64.lodsd" | "x86_64.scasb"
        | "x86_64.scasd" | "x86_64.insb" | "x86_64.outsd" => {
            match_fixed_operands(form, instruction)?;
        }
        "x86_64.in_al_imm8" | "x86_64.in_eax_imm8" | "x86_64.out_imm8_al" => {
            let imm = instruction
                .operands
                .iter()
                .find_map(|operand| match operand {
                    Operand::Immediate(value) => Some(*value),
                    _ => None,
                })
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if !(0..=0xff).contains(&imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            match_fixed_operands(form, instruction)?;
            values.insert("imm", imm);
        }
        "aarch64.ret" => {
            let rn = if instruction.operands.is_empty() {
                30
            } else {
                let [Operand::Register(register)] = instruction.operands.as_slice() else {
                    return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
                };
                adapters::parse_x_only_register(&register.name)
                    .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?
            };
            values.insert("rn", i64::from(rn));
        }
        "aarch64.br" | "aarch64.blr" => {
            let [Operand::Register(register)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rn = adapters::parse_x_only_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rn", i64::from(rn));
        }
        "aarch64.b" | "aarch64.bl" => {
            let target = extract_absolute_target(instruction)?;
            let delta = i64::try_from(target)
                .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                - i64::try_from(instruction.address)
                    .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?;
            if delta % 4 != 0 {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            let imm26 = delta / 4;
            if !(-(1i64 << 25)..(1i64 << 25)).contains(&imm26) {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            values.insert("imm26", imm26);
        }
        "aarch64.b_cond" => {
            let condition = instruction
                .mnemonic
                .strip_prefix("b.")
                .and_then(adapters::condition_bits)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let target = extract_absolute_target(instruction)?;
            let delta = i64::try_from(target)
                .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                - i64::try_from(instruction.address)
                    .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?;
            if delta % 4 != 0 {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            let imm19 = delta / 4;
            if !(-(1i64 << 18)..(1i64 << 18)).contains(&imm19) {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            values.insert("cond", i64::from(condition));
            values.insert("imm19", imm19);
        }
        "aarch64.cbz" | "aarch64.cbnz" => {
            let [Operand::Register(register), Operand::AbsoluteAddress(target)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rt) = adapters::parse_width_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let delta = i64::try_from(*target)
                .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                - i64::try_from(instruction.address)
                    .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?;
            if delta % 4 != 0 {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            let imm19 = delta / 4;
            if !(-(1i64 << 18)..(1i64 << 18)).contains(&imm19) {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rt", i64::from(rt));
            values.insert("imm19", imm19);
        }
        "aarch64.tbz" | "aarch64.tbnz" => {
            let [Operand::Register(register), Operand::Immediate(bit), Operand::AbsoluteAddress(target)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if *bit < 0 || *bit > 63 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let (is_64, rt) = adapters::parse_width_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if (is_64 && *bit < 32) || (!is_64 && *bit >= 32) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let delta = i64::try_from(*target)
                .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                - i64::try_from(instruction.address)
                    .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?;
            if delta % 4 != 0 {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            let imm14 = delta / 4;
            if !(-(1i64 << 13)..(1i64 << 13)).contains(&imm14) {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            values.insert("rt", i64::from(rt));
            values.insert("bit", *bit);
            values.insert("imm14", imm14);
        }
        "aarch64.adr" | "aarch64.adrp" => {
            let [Operand::Register(register), Operand::AbsoluteAddress(target)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let rd = adapters::parse_x_only_register(&register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rd", i64::from(rd));
            values.insert(
                "target",
                i64::try_from(*target)
                    .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?,
            );
        }
        "aarch64.add_imm" | "aarch64.sub_imm" => {
            let [Operand::Register(dst), Operand::Register(src), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rd) = adapters::parse_sp_capable_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (src_is_64, rn) = adapters::parse_sp_capable_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if is_64 != src_is_64 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("rn", i64::from(rn));
            values.insert("imm", *imm);
        }
        "aarch64.cmp_imm" | "aarch64.cmn_imm" => {
            let [Operand::Register(src), Operand::Immediate(imm)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rn) = adapters::parse_sp_capable_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rn", i64::from(rn));
            values.insert("imm", *imm);
        }
        "aarch64.mov_wide" | "aarch64.movk" | "aarch64.movn" => {
            let [Operand::Register(dst), Operand::Immediate(imm)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if *imm < 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (_, hw) = adapters::encode_move_wide_immediate(*imm as u64, is_64)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("hw", i64::from(hw));
            values.insert("imm", *imm);
        }
        "aarch64.mov_reg" => {
            let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (src_is_64, rm) = adapters::parse_width_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if is_64 != src_is_64 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("rm", i64::from(rm));
        }
        "aarch64.add_reg" => {
            let [Operand::Register(dst), Operand::Register(lhs), Operand::Register(rhs)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (lhs_is_64, rn) = adapters::parse_width_register(&lhs.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (rhs_is_64, rm) = adapters::parse_width_register(&rhs.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if is_64 != lhs_is_64 || is_64 != rhs_is_64 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("rn", i64::from(rn));
            values.insert("rm", i64::from(rm));
        }
        "aarch64.add_shifted_reg" => {
            let [Operand::Register(dst), Operand::Register(lhs), Operand::ShiftedRegister(rhs)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (lhs_is_64, rn) = adapters::parse_width_register(&lhs.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (rhs_is_64, rm) = adapters::parse_width_register(&rhs.register.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let shift_kind = adapters::shift_bits(&rhs.shift)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let width = if is_64 { 64 } else { 32 };
            if is_64 != lhs_is_64 || is_64 != rhs_is_64 || u32::from(rhs.amount) >= width {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("rn", i64::from(rn));
            values.insert("rm", i64::from(rm));
            values.insert("shift_kind", i64::from(shift_kind));
            values.insert("shift_amount", i64::from(rhs.amount));
        }
        "aarch64.cmp_reg" => {
            let [Operand::Register(lhs), Operand::Register(rhs)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rn) = adapters::parse_width_register(&lhs.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (rhs_is_64, rm) = adapters::parse_width_register(&rhs.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if is_64 != rhs_is_64 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rn", i64::from(rn));
            values.insert("rm", i64::from(rm));
        }
        "aarch64.csel" => {
            let [Operand::Register(dst), Operand::Register(lhs), Operand::Register(rhs), Operand::Condition(condition)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (lhs_is_64, rn) = adapters::parse_width_register(&lhs.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (rhs_is_64, rm) = adapters::parse_width_register(&rhs.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let cond = adapters::conditional_select_condition_bits(condition)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if is_64 != lhs_is_64 || is_64 != rhs_is_64 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("rn", i64::from(rn));
            values.insert("rm", i64::from(rm));
            values.insert("cond", i64::from(cond));
        }
        "aarch64.cset" => {
            let [Operand::Register(dst), Operand::Condition(condition)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let cond = adapters::conditional_select_condition_bits(condition)
                .map(adapters::invert_condition)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("cond", i64::from(cond));
        }
        "aarch64.ldr_unsigned" | "aarch64.str_unsigned" => {
            let [Operand::Register(register), Operand::Memory(memory)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let size = access_size_from_register(register, false)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if memory.index.is_some() || memory.writeback || memory.post_index || memory.offset < 0
            {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let bytes = access_size_bytes(size)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if memory.offset % bytes != 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let imm12 = memory.offset / bytes;
            if !(0..=0x0fff).contains(&imm12) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("size", i64::from(size));
            values.insert(
                "rt",
                i64::from(
                    access_register_index(register).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                ),
            );
            values.insert(
                "rn",
                i64::from(
                    memory_base_index(memory).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                ),
            );
            values.insert("imm12", imm12);
        }
        "aarch64.ldur" | "aarch64.stur" | "aarch64.ldr_pre" | "aarch64.str_pre"
        | "aarch64.ldr_post" | "aarch64.str_post" => {
            let [Operand::Register(register), Operand::Memory(memory)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let expected_writeback = matches!(
                form.id().name().as_str(),
                "aarch64.ldr_pre" | "aarch64.str_pre"
            );
            let expected_post_index = matches!(
                form.id().name().as_str(),
                "aarch64.ldr_post" | "aarch64.str_post"
            );
            if memory.index.is_some()
                || memory.writeback != expected_writeback
                || memory.post_index != expected_post_index
                || !(-256..=255).contains(&memory.offset)
            {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let size = access_size_from_register(register, false)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("size", i64::from(size));
            values.insert(
                "rt",
                i64::from(
                    access_register_index(register).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                ),
            );
            values.insert(
                "rn",
                i64::from(
                    memory_base_index(memory).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                ),
            );
            values.insert("imm9", memory.offset);
        }
        "aarch64.ldr_reg" | "aarch64.str_reg" => {
            let [Operand::Register(register), Operand::Memory(memory)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let size = access_size_from_register(register, false)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let bytes = access_size_bytes(size)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let index = memory
                .index
                .as_ref()
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let rm = index
                .name
                .strip_prefix('w')
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let scaled = if memory.scale == 1 {
                0
            } else if i64::from(memory.scale) == bytes {
                1
            } else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if memory.writeback || memory.post_index || memory.offset != 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("size", i64::from(size));
            values.insert(
                "rt",
                i64::from(
                    access_register_index(register).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                ),
            );
            values.insert(
                "rn",
                i64::from(
                    memory_base_index(memory).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                ),
            );
            values.insert("rm", i64::from(rm));
            values.insert("scaled", scaled);
        }
        "aarch64.ldp" | "aarch64.stp" | "aarch64.ldp_pre" | "aarch64.stp_pre"
        | "aarch64.ldp_post" | "aarch64.stp_post" => {
            let [Operand::Register(first), Operand::Register(second), Operand::Memory(memory)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let expected_writeback = matches!(
                form.id().name().as_str(),
                "aarch64.ldp_pre" | "aarch64.stp_pre"
            );
            let expected_post_index = matches!(
                form.id().name().as_str(),
                "aarch64.ldp_post" | "aarch64.stp_post"
            );
            if memory.index.is_some()
                || memory.writeback != expected_writeback
                || memory.post_index != expected_post_index
            {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }

            let (kind, rt) = adapters::parse_pair_register(&first.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (other_kind, rt2) = adapters::parse_pair_register(&second.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if kind != other_kind {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let (pair_vector, pair_high, size_bytes) = match kind {
                adapters::PairRegisterKind::W => (0, 0, 4i64),
                adapters::PairRegisterKind::X => (0, 1, 8i64),
                adapters::PairRegisterKind::Q => (1, 1, 16i64),
            };
            if memory.offset % size_bytes != 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let imm7 = memory.offset / size_bytes;
            if !(-64..=63).contains(&imm7) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }

            values.insert("pair_vector", pair_vector);
            values.insert("pair_high", pair_high);
            values.insert("rt", i64::from(rt));
            values.insert("rt2", i64::from(rt2));
            values.insert(
                "rn",
                i64::from(
                    memory_base_index(memory).ok_or_else(|| {
                        EncodeError::OperandMismatch(instruction.mnemonic.clone())
                    })?,
                ),
            );
            values.insert("imm7", imm7);
        }
        "aarch64.brk" => {
            let [Operand::Immediate(imm)] = instruction.operands.as_slice() else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if !(0..=0xffff).contains(imm) {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("imm", *imm);
        }
        "aarch64.movi_zero_2d" => {
            let [Operand::Register(dst), Operand::Immediate(imm)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if *imm != 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let rd = adapters::parse_v2d_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("rd", i64::from(rd));
            values.insert("imm", *imm);
        }
        "aarch64.and_imm" => {
            let [Operand::Register(dst), Operand::Register(src), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (src_is_64, rn) = adapters::parse_width_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if is_64 != src_is_64 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let mask = if is_64 {
                *imm as u64
            } else {
                *imm as u32 as u64
            };
            adapters::encode_logical_immediate_fields(mask, is_64)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("rn", i64::from(rn));
            values.insert("imm", *imm);
        }
        "aarch64.mov_imm" => {
            let [Operand::Register(dst), Operand::Immediate(imm)] = instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let mask = if is_64 {
                *imm as u64
            } else {
                *imm as u32 as u64
            };
            adapters::encode_logical_immediate_fields(mask, is_64)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("imm", *imm);
        }
        "aarch64.lsr_imm" | "aarch64.lsl_imm" | "aarch64.asr_imm" => {
            let [Operand::Register(dst), Operand::Register(src), Operand::Immediate(shift)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            if *shift < 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (src_is_64, rn) = adapters::parse_width_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if is_64 != src_is_64 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let width = if is_64 { 64 } else { 32 };
            if *shift >= i64::from(width) || (form.id().name() == "aarch64.lsl_imm" && *shift == 0)
            {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("rn", i64::from(rn));
            values.insert("shift", *shift);
        }
        "aarch64.lsr_reg" => {
            let [Operand::Register(dst), Operand::Register(src), Operand::Register(shift)] =
                instruction.operands.as_slice()
            else {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            };
            let (is_64, rd) = adapters::parse_width_register(&dst.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (src_is_64, rn) = adapters::parse_width_register(&src.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (shift_is_64, rm) = adapters::parse_width_register(&shift.name)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            if is_64 != src_is_64 || is_64 != shift_is_64 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            values.insert("sf", if is_64 { 1 } else { 0 });
            values.insert("rd", i64::from(rd));
            values.insert("rn", i64::from(rn));
            values.insert("rm", i64::from(rm));
        }
        _ => {}
    }

    Ok(values)
}

fn decode_mnemonic(form: &FormSchema, values: &ValueMap) -> Result<String, DecodeError> {
    if form.id().name() == "aarch64.b_cond" {
        let cond = u32::try_from(*values.get("cond").ok_or(DecodeError::UnsupportedTarget)?)
            .map_err(|_| DecodeError::UnsupportedTarget)?;
        let suffix = adapters::condition_name(cond).ok_or(DecodeError::UnsupportedTarget)?;
        return Ok(format!("b.{suffix}"));
    }

    Ok(form.mnemonic().to_string())
}

fn build_operands(
    form: &FormSchema,
    layout: Option<&LayoutView>,
    values: &ValueMap,
    address: u64,
    instruction_size: u8,
) -> Result<Vec<Operand>, DecodeError> {
    let mut operands = Vec::new();
    for operand in form.operands() {
        let semantic = match operand {
            crate::form::OperandSpec::FixedRegister { name } => {
                Operand::Register(crate::model::Register {
                    name: (*name).to_string(),
                })
            }
            crate::form::OperandSpec::FixedMemory { base, width_bits } => {
                Operand::Memory(MemoryOperand::base_offset(
                    crate::model::Register {
                        name: (*base).to_string(),
                    },
                    0,
                    Some(*width_bits),
                ))
            }
            crate::form::OperandSpec::Register { field, bank } => {
                let index = get_u32(values, field)?;
                let register = match *bank {
                    "aarch64.ret" if index == 30 => {
                        continue;
                    }
                    "aarch64.ret" => adapters::x_only_register(index),
                    "aarch64.x_only" => adapters::x_only_register(index),
                    "aarch64.access_gp" => {
                        let size = get_u32(values, "size")?;
                        let is_64 = match size {
                            2 => false,
                            3 => true,
                            _ => return Err(DecodeError::UnsupportedTarget),
                        };
                        adapters::width_register(index, is_64)
                    }
                    "aarch64.width_gp" => {
                        let is_64 = get_u32(values, "sf").unwrap_or(1) == 1;
                        adapters::width_register(index, is_64)
                    }
                    "aarch64.tb_width_gp" => {
                        let bit = get_u32(values, "bit")?;
                        adapters::width_register(index, bit >= 32)
                    }
                    "aarch64.width_gp_zr" => {
                        let is_64 = get_u32(values, "sf").unwrap_or(1) == 1;
                        adapters::zr_capable_register(index, is_64)
                    }
                    "aarch64.sp_width_gp" => {
                        let is_64 = get_u32(values, "sf").unwrap_or(1) == 1;
                        adapters::sp_capable_register(index, is_64)
                    }
                    "aarch64.pair_reg" => {
                        let kind = decode_pair_register_kind(values)?;
                        adapters::pair_register(index, kind)
                    }
                    "aarch64.v2d" => crate::arch::aarch64::registers::v_lane(index, "2d"),
                    "aarch64.q_only" => crate::arch::aarch64::registers::q(index),
                    "x86_64.r64" => x86_adapters::r64_register(index),
                    "x86_64.r32" => x86_adapters::r32_register(index),
                    "x86_64.r16" => x86_adapters::r16_register(index),
                    "x86_64.r8" => x86_adapters::r8_register(index),
                    "x86_64.mm" => x86_adapters::mm_register(index),
                    "x86_64.xmm" => x86_adapters::xmm_register(index),
                    "x86_64.ymm" => x86_adapters::ymm_register(index),
                    _ => return Err(DecodeError::UnsupportedTarget),
                };
                Operand::Register(register)
            }
            crate::form::OperandSpec::ShiftedRegister {
                reg_field,
                shift_field,
                amount_field,
                bank,
            } => {
                let index = get_u32(values, reg_field)?;
                let shift_bits = get_u32(values, shift_field)?;
                let amount = get_u32(values, amount_field)?;
                let is_64 = get_u32(values, "sf").unwrap_or(1) == 1;
                if (!is_64 && amount >= 32) || shift_bits > 2 {
                    return Err(DecodeError::UnsupportedTarget);
                }
                let register = match *bank {
                    "aarch64.width_gp_zr" => adapters::zr_capable_register(index, is_64),
                    "aarch64.width_gp" => adapters::width_register(index, is_64),
                    _ => return Err(DecodeError::UnsupportedTarget),
                };
                let shift =
                    adapters::shift_name(shift_bits).ok_or(DecodeError::UnsupportedTarget)?;
                Operand::ShiftedRegister(crate::model::ShiftedRegisterOperand {
                    register,
                    shift: shift.to_string(),
                    amount: u8::try_from(amount).map_err(|_| DecodeError::UnsupportedTarget)?,
                })
            }
            crate::form::OperandSpec::Immediate { field } => {
                Operand::Immediate(*values.get(field).ok_or(DecodeError::UnsupportedTarget)?)
            }
            crate::form::OperandSpec::RelativeTarget {
                field,
                scale,
                add_instruction_size,
            } => {
                let base = if *add_instruction_size {
                    address + u64::from(instruction_size)
                } else {
                    address
                };
                let raw = *values.get(field).ok_or(DecodeError::UnsupportedTarget)?;
                let target = base.wrapping_add_signed(raw * i64::from(*scale));
                Operand::AbsoluteAddress(target)
            }
            crate::form::OperandSpec::AbsoluteTarget { field } => {
                let target =
                    u64::try_from(*values.get(field).ok_or(DecodeError::UnsupportedTarget)?)
                        .map_err(|_| DecodeError::UnsupportedTarget)?;
                Operand::AbsoluteAddress(target)
            }
            crate::form::OperandSpec::Condition { field, table } => {
                let cond = get_u32(values, field)?;
                let name = match *table {
                    "aarch64.condsel" => adapters::conditional_select_condition_name(cond),
                    "aarch64.condsel_inverted" => adapters::conditional_select_condition_name(
                        adapters::invert_condition(cond),
                    ),
                    _ => adapters::condition_name(cond),
                }
                .ok_or(DecodeError::UnsupportedTarget)?;
                Operand::Condition(name.to_string())
            }
            crate::form::OperandSpec::Memory { kind } => {
                Operand::Memory(build_memory_operand(kind, values, layout, form)?)
            }
        };
        operands.push(semantic);
    }
    Ok(operands)
}

fn get_u32(values: &ValueMap, field: &str) -> Result<u32, DecodeError> {
    u32::try_from(*values.get(field).ok_or(DecodeError::UnsupportedTarget)?)
        .map_err(|_| DecodeError::UnsupportedTarget)
}

fn extract_absolute_target(instruction: &Instruction) -> Result<u64, EncodeError> {
    instruction
        .branch_target
        .or_else(|| {
            instruction
                .operands
                .iter()
                .find_map(|operand| match operand {
                    Operand::AbsoluteAddress(target) => Some(*target),
                    _ => None,
                })
        })
        .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))
}

fn build_memory_operand(
    kind: &MemorySpec,
    values: &ValueMap,
    layout: Option<&LayoutView>,
    form: &FormSchema,
) -> Result<MemoryOperand, DecodeError> {
    match kind {
        MemorySpec::X86Modrm { width_bits } => {
            let Some(LayoutView::X86ByteStream { bytes, .. }) = layout else {
                return Err(DecodeError::UnsupportedTarget);
            };
            let crate::form::DecodeLayout::ByteStream(byte_layout) = form.decode_layout() else {
                return Err(DecodeError::UnsupportedTarget);
            };
            x86_adapters::decode_modrm_memory(
                bytes,
                usize::from(byte_layout.opcode_len),
                *width_bits,
            )
        }
        MemorySpec::Aarch64UnsignedOffset {
            base_field,
            offset_field,
        } => {
            let base = crate::arch::aarch64::registers::x_or_sp(get_u32(values, base_field)?);
            let size = get_u32(values, "size")?;
            let size_bytes = access_size_bytes(size).ok_or(DecodeError::UnsupportedTarget)?;
            let offset = *values
                .get(offset_field)
                .ok_or(DecodeError::UnsupportedTarget)?
                * size_bytes;
            Ok(MemoryOperand::base_offset(
                base,
                offset,
                Some(u16::try_from(size_bytes * 8).map_err(|_| DecodeError::UnsupportedTarget)?),
            ))
        }
        MemorySpec::Aarch64SignedOffset {
            base_field,
            offset_field,
            writeback,
            post_index,
        } => {
            let base = crate::arch::aarch64::registers::x_or_sp(get_u32(values, base_field)?);
            let size = get_u32(values, "size")?;
            let size_bytes = access_size_bytes(size).ok_or(DecodeError::UnsupportedTarget)?;
            let mut memory = MemoryOperand::base_offset(
                base,
                *values
                    .get(offset_field)
                    .ok_or(DecodeError::UnsupportedTarget)?,
                Some(u16::try_from(size_bytes * 8).map_err(|_| DecodeError::UnsupportedTarget)?),
            );
            if *writeback {
                memory = memory.with_writeback();
            }
            if *post_index {
                memory = memory.with_post_index();
            }
            Ok(memory)
        }
        MemorySpec::Aarch64RegisterOffset {
            base_field,
            index_field,
            scaled_field,
        } => {
            let base = crate::arch::aarch64::registers::x_or_sp(get_u32(values, base_field)?);
            let index = crate::arch::aarch64::registers::w(get_u32(values, index_field)?);
            let size = get_u32(values, "size")?;
            let size_bytes = access_size_bytes(size).ok_or(DecodeError::UnsupportedTarget)?;
            let scaled = get_u32(values, scaled_field)?;
            let scale = if scaled == 0 {
                1
            } else if scaled == 1 {
                u8::try_from(size_bytes).map_err(|_| DecodeError::UnsupportedTarget)?
            } else {
                return Err(DecodeError::UnsupportedTarget);
            };
            Ok(MemoryOperand::indexed(
                Some(base),
                Some(index),
                scale,
                0,
                Some(u16::try_from(size_bytes * 8).map_err(|_| DecodeError::UnsupportedTarget)?),
            ))
        }
        MemorySpec::Aarch64PairOffset {
            base_field,
            offset_field,
            writeback,
            post_index,
        } => {
            let base = crate::arch::aarch64::registers::x_or_sp(get_u32(values, base_field)?);
            let size_bytes = pair_size_bytes(values).ok_or(DecodeError::UnsupportedTarget)?;
            let mut memory = MemoryOperand::base_offset(
                base,
                *values
                    .get(offset_field)
                    .ok_or(DecodeError::UnsupportedTarget)?
                    * size_bytes,
                Some(u16::try_from(size_bytes * 8).map_err(|_| DecodeError::UnsupportedTarget)?),
            );
            if *writeback {
                memory = memory.with_writeback();
            }
            if *post_index {
                memory = memory.with_post_index();
            }
            Ok(memory)
        }
    }
}

fn access_register_index(register: &crate::model::Register) -> Option<u32> {
    register
        .name
        .strip_prefix('x')
        .or_else(|| register.name.strip_prefix('w'))?
        .parse()
        .ok()
}

fn access_size_from_register(register: &crate::model::Register, allow_sp: bool) -> Option<u32> {
    match register.name.as_str() {
        "sp" if allow_sp => Some(3),
        "wsp" if allow_sp => Some(2),
        _ if register.name.starts_with('x') => Some(3),
        _ if register.name.starts_with('w') => Some(2),
        _ => None,
    }
}

fn memory_base_index(memory: &MemoryOperand) -> Option<u32> {
    memory
        .base
        .as_ref()
        .and_then(|register| adapters::parse_x_sp_register(&register.name))
}

fn access_size_bytes(size: u32) -> Option<i64> {
    match size {
        2 => Some(4),
        3 => Some(8),
        _ => None,
    }
}

fn decode_pair_register_kind(values: &ValueMap) -> Result<adapters::PairRegisterKind, DecodeError> {
    let vector = get_u32(values, "pair_vector").unwrap_or(0);
    let high = get_u32(values, "pair_high")?;
    match (vector, high) {
        (0, 0) => Ok(adapters::PairRegisterKind::W),
        (0, 1) => Ok(adapters::PairRegisterKind::X),
        (1, 1) => Ok(adapters::PairRegisterKind::Q),
        _ => Err(DecodeError::UnsupportedTarget),
    }
}

fn pair_size_bytes(values: &ValueMap) -> Option<i64> {
    match decode_pair_register_kind(values).ok()? {
        adapters::PairRegisterKind::W => Some(4),
        adapters::PairRegisterKind::X => Some(8),
        adapters::PairRegisterKind::Q => Some(16),
    }
}

fn instruction_size_for_form(form: &FormSchema) -> u8 {
    match form.decode_layout() {
        crate::form::DecodeLayout::FixedWidthBits { width } => width / 8,
        crate::form::DecodeLayout::ByteStream(layout) => {
            layout.opcode_len
                + u8::from(layout.uses_modrm)
                + u8::from(layout.uses_sib)
                + layout.displacement_bytes.unwrap_or(0)
                + layout.immediate_bytes.unwrap_or(0)
        }
    }
}

fn match_fixed_operands(form: &FormSchema, instruction: &Instruction) -> Result<(), EncodeError> {
    if instruction.operands.len() != form.operands().len() {
        return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
    }

    for (expected, actual) in form.operands().iter().zip(instruction.operands.iter()) {
        match (expected, actual) {
            (crate::form::OperandSpec::FixedRegister { name }, Operand::Register(register))
                if register.name == *name => {}
            (
                crate::form::OperandSpec::FixedMemory { base, width_bits },
                Operand::Memory(memory),
            ) if memory
                .base
                .as_ref()
                .is_some_and(|register| register.name == *base)
                && memory.index.is_none()
                && memory.scale == 1
                && memory.offset == 0
                && memory.width_bits == Some(*width_bits)
                && !memory.writeback
                && !memory.post_index
                && !memory.relative => {}
            (crate::form::OperandSpec::Immediate { .. }, Operand::Immediate(_)) => {}
            _ => return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone())),
        }
    }

    Ok(())
}

fn ensure_x86_memory_width(
    memory: &MemoryOperand,
    width_bits: u16,
    mnemonic: &str,
) -> Result<(), EncodeError> {
    if memory.width_bits != Some(width_bits) || memory.writeback || memory.post_index {
        return Err(EncodeError::OperandMismatch(mnemonic.to_string()));
    }
    Ok(())
}
