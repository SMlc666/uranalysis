use crate::{
    error::EncodeError,
    form::FormSchema,
    model::{Architecture, Instruction},
    runtime::ValueMap,
};

pub fn emit_instruction(
    form: &FormSchema,
    instruction: &Instruction,
    values: &ValueMap,
) -> Result<Vec<u8>, EncodeError> {
    match (instruction.architecture, form.id().name().as_str()) {
        (Architecture::Aarch64, "aarch64.nop") => Ok(0xd503201fu32.to_le_bytes().to_vec()),
        (Architecture::Aarch64, "aarch64.ret") => Ok(0xd65f03c0u32.to_le_bytes().to_vec()),
        (Architecture::Aarch64, "aarch64.br") | (Architecture::Aarch64, "aarch64.blr") => {
            let rn = get_u32(values, "rn", instruction)?;
            let base = if form.id().name() == "aarch64.blr" {
                0xd63f_0000u32
            } else {
                0xd61f_0000u32
            };
            Ok((base | (rn << 5)).to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.b") => {
            let imm26 = get_i64(values, "imm26", instruction)?;
            Ok((0x1400_0000u32 | ((imm26 as u32) & 0x03ff_ffff))
                .to_le_bytes()
                .to_vec())
        }
        (Architecture::Aarch64, "aarch64.bl") => {
            let imm26 = get_i64(values, "imm26", instruction)?;
            Ok((0x9400_0000u32 | ((imm26 as u32) & 0x03ff_ffff))
                .to_le_bytes()
                .to_vec())
        }
        (Architecture::Aarch64, "aarch64.b_cond") => {
            let imm19 = get_i64(values, "imm19", instruction)?;
            let cond = get_u32(values, "cond", instruction)?;
            Ok((0x5400_0000u32 | (((imm19 as u32) & 0x7ffff) << 5) | cond)
                .to_le_bytes()
                .to_vec())
        }
        (Architecture::Aarch64, "aarch64.cbz") | (Architecture::Aarch64, "aarch64.cbnz") => {
            let imm19 = get_i64(values, "imm19", instruction)?;
            let rt = get_u32(values, "rt", instruction)?;
            let sf = get_u32(values, "sf", instruction)?;
            let mut word = if form.id().name() == "aarch64.cbnz" {
                0x3500_0000u32
            } else {
                0x3400_0000u32
            } | (((imm19 as u32) & 0x7ffff) << 5)
                | rt;
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.adr") | (Architecture::Aarch64, "aarch64.adrp") => {
            let rd = get_u32(values, "rd", instruction)?;
            let target = u64::try_from(get_i64(values, "target", instruction)?)
                .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?;
            let page = form.id().name() == "aarch64.adrp";
            let imm = if page {
                if target & 0x0fff != 0 {
                    return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
                }
                let base = instruction.address & !0x0fff;
                let delta = i64::try_from(target)
                    .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                    - i64::try_from(base)
                        .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?;
                if delta % 4096 != 0 {
                    return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
                }
                delta / 4096
            } else {
                i64::try_from(target)
                    .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
                    - i64::try_from(instruction.address)
                        .map_err(|_| EncodeError::TargetOutOfRange(instruction.mnemonic.clone()))?
            };
            if !(-(1i64 << 20)..(1i64 << 20)).contains(&imm) {
                return Err(EncodeError::TargetOutOfRange(instruction.mnemonic.clone()));
            }
            let imm_u32 = (imm as i32 as u32) & 0x1f_ffff;
            let immlo = imm_u32 & 0x3;
            let immhi = (imm_u32 >> 2) & 0x7ffff;
            let base = if page { 0x9000_0000u32 } else { 0x1000_0000u32 };
            Ok((base | (immlo << 29) | (immhi << 5) | rd)
                .to_le_bytes()
                .to_vec())
        }
        (Architecture::Aarch64, "aarch64.add_imm")
        | (Architecture::Aarch64, "aarch64.sub_imm")
        | (Architecture::Aarch64, "aarch64.cmp_imm")
        | (Architecture::Aarch64, "aarch64.cmn_imm") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let imm = get_i64(values, "imm", instruction)?;
            let (imm12, shift_flag) = crate::arch::aarch64::adapters::encode_add_sub_immediate(imm)
                .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (base, rd) = match form.id().name().as_str() {
                "aarch64.add_imm" => (0x1100_0000u32, get_u32(values, "rd", instruction)?),
                "aarch64.sub_imm" => (0x5100_0000u32, get_u32(values, "rd", instruction)?),
                "aarch64.cmp_imm" => (0x7100_0000u32, 31),
                "aarch64.cmn_imm" => (0x3100_0000u32, 31),
                _ => unreachable!(),
            };
            let mut word = base | (imm12 << 10) | (rn << 5) | rd;
            if sf == 1 {
                word |= 1 << 31;
            }
            if shift_flag {
                word |= 1 << 22;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.add_reg") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rd = get_u32(values, "rd", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            let mut word = 0x0b00_0000u32 | (rm << 16) | (rn << 5) | rd;
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.add_shifted_reg") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rd = get_u32(values, "rd", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            let shift_kind = get_u32(values, "shift_kind", instruction)?;
            let shift_amount = get_u32(values, "shift_amount", instruction)?;
            let mut word = 0x0b00_0000u32
                | (shift_kind << 22)
                | (rm << 16)
                | (shift_amount << 10)
                | (rn << 5)
                | rd;
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.cmp_reg") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            let mut word = 0x6b00_001fu32 | (rm << 16) | (rn << 5);
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.csel") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rd = get_u32(values, "rd", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            let cond = get_u32(values, "cond", instruction)?;
            let mut word = 0x1a80_0000u32 | (rm << 16) | (cond << 12) | (rn << 5) | rd;
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.cset") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rd = get_u32(values, "rd", instruction)?;
            let cond = get_u32(values, "cond", instruction)?;
            let mut word = 0x1a80_0400u32 | (31 << 16) | (cond << 12) | (31 << 5) | rd;
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.ldr_unsigned")
        | (Architecture::Aarch64, "aarch64.str_unsigned") => {
            let size = get_u32(values, "size", instruction)?;
            let rt = get_u32(values, "rt", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let imm12 = get_u32(values, "imm12", instruction)?;
            let load = form.id().name() == "aarch64.ldr_unsigned";
            let word = 0x3900_0000u32
                | (size << 30)
                | (u32::from(load) << 22)
                | (imm12 << 10)
                | (rn << 5)
                | rt;
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.ldur")
        | (Architecture::Aarch64, "aarch64.stur")
        | (Architecture::Aarch64, "aarch64.ldr_pre")
        | (Architecture::Aarch64, "aarch64.str_pre")
        | (Architecture::Aarch64, "aarch64.ldr_post")
        | (Architecture::Aarch64, "aarch64.str_post") => {
            let size = get_u32(values, "size", instruction)?;
            let rt = get_u32(values, "rt", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let imm9 = get_i64(values, "imm9", instruction)?;
            let mode_bits = match form.id().name().as_str() {
                "aarch64.ldr_pre" | "aarch64.str_pre" => 0b11,
                "aarch64.ldr_post" | "aarch64.str_post" => 0b01,
                _ => 0b00,
            };
            let load = matches!(
                form.id().name().as_str(),
                "aarch64.ldur" | "aarch64.ldr_pre" | "aarch64.ldr_post"
            );
            let word = 0x3800_0000u32
                | (size << 30)
                | (u32::from(load) << 22)
                | (((imm9 as u32) & 0x1ff) << 12)
                | (mode_bits << 10)
                | (rn << 5)
                | rt;
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.ldr_reg") | (Architecture::Aarch64, "aarch64.str_reg") => {
            let size = get_u32(values, "size", instruction)?;
            let rt = get_u32(values, "rt", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            let scaled = get_u32(values, "scaled", instruction)?;
            let load = form.id().name() == "aarch64.ldr_reg";
            let word = 0x3820_4800u32
                | (size << 30)
                | (u32::from(load) << 22)
                | (rm << 16)
                | (scaled << 12)
                | (rn << 5)
                | rt;
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.stp")
        | (Architecture::Aarch64, "aarch64.ldp")
        | (Architecture::Aarch64, "aarch64.stp_pre")
        | (Architecture::Aarch64, "aarch64.ldp_pre")
        | (Architecture::Aarch64, "aarch64.stp_post")
        | (Architecture::Aarch64, "aarch64.ldp_post") => {
            let pair_high = get_u32(values, "pair_high", instruction)?;
            let pair_vector = get_u32(values, "pair_vector", instruction)?;
            let rt = get_u32(values, "rt", instruction)?;
            let rt2 = get_u32(values, "rt2", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let imm7 = get_i64(values, "imm7", instruction)?;
            let load = matches!(
                form.id().name().as_str(),
                "aarch64.ldp" | "aarch64.ldp_pre" | "aarch64.ldp_post"
            );
            let base = match form.id().name().as_str() {
                "aarch64.stp" | "aarch64.ldp" => 0x2900_0000u32,
                "aarch64.stp_pre" | "aarch64.ldp_pre" => 0x2980_0000u32,
                "aarch64.stp_post" | "aarch64.ldp_post" => 0x2880_0000u32,
                _ => unreachable!(),
            };
            let word = base
                | (pair_high << 31)
                | (pair_vector << 26)
                | (u32::from(load) << 22)
                | (((imm7 as u32) & 0x7f) << 15)
                | (rt2 << 10)
                | (rn << 5)
                | rt;
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.tbz") | (Architecture::Aarch64, "aarch64.tbnz") => {
            let rt = get_u32(values, "rt", instruction)?;
            let bit = get_u32(values, "bit", instruction)?;
            let imm14 = get_u32(values, "imm14", instruction)?;
            let base = if form.id().name() == "aarch64.tbnz" {
                0x3700_0000u32
            } else {
                0x3600_0000u32
            };
            Ok(
                (base | ((bit >> 5) << 31) | ((bit & 0x1f) << 19) | (imm14 << 5) | rt)
                    .to_le_bytes()
                    .to_vec(),
            )
        }
        (Architecture::Aarch64, "aarch64.brk") => {
            let imm = get_u32(values, "imm", instruction)?;
            Ok((0xd420_0000u32 | (imm << 5)).to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.movi_zero_2d") => {
            let rd = get_u32(values, "rd", instruction)?;
            Ok((0x6f00_e400u32 | rd).to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.mov_wide")
        | (Architecture::Aarch64, "aarch64.movk")
        | (Architecture::Aarch64, "aarch64.movn") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rd = get_u32(values, "rd", instruction)?;
            let imm = u64::try_from(get_i64(values, "imm", instruction)?)
                .map_err(|_| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let (imm16, hw) =
                crate::arch::aarch64::adapters::encode_move_wide_immediate(imm, sf == 1)
                    .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let opc = match form.id().name().as_str() {
                "aarch64.mov_wide" => 0b10,
                "aarch64.movk" => 0b11,
                "aarch64.movn" => 0b00,
                _ => unreachable!(),
            };
            let mut word = 0x1280_0000u32 | (opc << 29) | (hw << 21) | (imm16 << 5) | rd;
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.mov_reg") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rd = get_u32(values, "rd", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            let mut word = 0x2a00_03e0u32 | (rm << 16) | rd;
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.and_imm") | (Architecture::Aarch64, "aarch64.mov_imm") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rd = get_u32(values, "rd", instruction)?;
            let rn = if form.id().name() == "aarch64.mov_imm" {
                31
            } else {
                get_u32(values, "rn", instruction)?
            };
            let imm = get_i64(values, "imm", instruction)?;
            let mask = if sf == 1 {
                imm as u64
            } else {
                imm as u32 as u64
            };
            let (n, immr, imms) =
                crate::arch::aarch64::adapters::encode_logical_immediate_fields(mask, sf == 1)
                    .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))?;
            let opc = if form.id().name() == "aarch64.mov_imm" {
                0b01
            } else {
                0b00
            };
            let mut word = 0x1200_0000u32
                | (opc << 29)
                | (n << 22)
                | (immr << 16)
                | (imms << 10)
                | (rn << 5)
                | rd;
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.lsr_imm")
        | (Architecture::Aarch64, "aarch64.lsl_imm")
        | (Architecture::Aarch64, "aarch64.asr_imm") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rd = get_u32(values, "rd", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let shift = get_u32(values, "shift", instruction)?;
            let width = if sf == 1 { 64 } else { 32 };
            let (base, immr, imms) = match form.id().name().as_str() {
                "aarch64.lsr_imm" => (0x5300_0000u32, shift, width - 1),
                "aarch64.lsl_imm" => {
                    let immr = width - shift;
                    (0x5300_0000u32, immr, immr - 1)
                }
                "aarch64.asr_imm" => (0x1300_0000u32, shift, width - 1),
                _ => unreachable!(),
            };
            let mut word = base | (immr << 16) | (imms << 10) | (rn << 5) | rd;
            if sf == 1 {
                word |= (1 << 31) | (1 << 22);
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::Aarch64, "aarch64.lsr_reg") => {
            let sf = get_u32(values, "sf", instruction)?;
            let rd = get_u32(values, "rd", instruction)?;
            let rn = get_u32(values, "rn", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            let mut word = 0x1ac0_2400u32 | (rm << 16) | (rn << 5) | rd;
            if sf == 1 {
                word |= 1 << 31;
            }
            Ok(word.to_le_bytes().to_vec())
        }
        (Architecture::X86_64, "x86_64.ret") => Ok(vec![0xc3]),
        (Architecture::X86_64, "x86_64.ret_imm16") => {
            let imm = get_u32(values, "imm", instruction)? as u16;
            let mut out = vec![0xc2];
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.retf") => Ok(vec![0xcb]),
        (Architecture::X86_64, "x86_64.retf_imm16") => {
            let imm = get_u32(values, "imm", instruction)? as u16;
            let mut out = vec![0xca];
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.call_rel32") => {
            let disp = get_i64(values, "disp", instruction)? as i32;
            let mut out = vec![0xe8];
            out.extend_from_slice(&disp.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.call_rm64") => {
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![
                0x48 | u8::from(rm >= 8),
                0xff,
                0xd0 | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.jmp_rel8") => {
            let disp = get_i64(values, "disp", instruction)? as i8;
            Ok(vec![0xeb, disp as u8])
        }
        (Architecture::X86_64, "x86_64.jmp_rel32") => {
            let disp = get_i64(values, "disp", instruction)? as i32;
            let mut out = vec![0xe9];
            out.extend_from_slice(&disp.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.jmp_rm64") => {
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![
                0x48 | u8::from(rm >= 8),
                0xff,
                0xe0 | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.je_rel8") => {
            let disp = get_i64(values, "disp", instruction)? as i8;
            Ok(vec![0x74, disp as u8])
        }
        (Architecture::X86_64, "x86_64.jne_rel32") => {
            let disp = get_i64(values, "disp", instruction)? as i32;
            let mut out = vec![0x0f, 0x85];
            out.extend_from_slice(&disp.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.loopne")
        | (Architecture::X86_64, "x86_64.loope")
        | (Architecture::X86_64, "x86_64.loop")
        | (Architecture::X86_64, "x86_64.jrcxz") => {
            let opcode = match form.id().name().as_str() {
                "x86_64.loopne" => 0xe0,
                "x86_64.loope" => 0xe1,
                "x86_64.loop" => 0xe2,
                "x86_64.jrcxz" => 0xe3,
                _ => unreachable!(),
            };
            let disp = get_i64(values, "disp", instruction)? as i8;
            Ok(vec![opcode, disp as u8])
        }
        (Architecture::X86_64, "x86_64.mov_r64_imm64") => {
            let rd = get_u32(values, "rd", instruction)?;
            let imm = get_i64(values, "imm", instruction)?;
            let mut out = vec![0x48 | u8::from(rd >= 8), 0xb8 | ((rd as u8) & 0x07)];
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_r32_imm32") => {
            let rd = get_u32(values, "rd", instruction)?;
            let imm = get_i64(values, "imm", instruction)? as u32;
            let mut out = vec![0xb8 | ((rd as u8) & 0x07)];
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_m8_r8") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let register = expect_register_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let rex = x86_r8_rex_bits(&register.name, reg) | (encoded.rex_x << 1) | encoded.rex_b;
            let mut out = Vec::new();
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0x88);
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_r8_m8") => {
            let register = expect_register_operand(instruction, 0)?;
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let rex = x86_r8_rex_bits(&register.name, reg) | (encoded.rex_x << 1) | encoded.rex_b;
            let mut out = Vec::new();
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0x8a);
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_m8_imm8") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let imm = get_u32(values, "imm", instruction)? as u8;
            let mut out = Vec::new();
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0xc6);
            out.push(((encoded.mod_bits & 0x03) << 6) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            out.push(imm);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.movsx_r32_m8")
        | (Architecture::X86_64, "x86_64.movzx_r32_m8") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = Vec::new();
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0x0f);
            out.push(if form.id().name() == "x86_64.movzx_r32_m8" {
                0xb6
            } else {
                0xbe
            });
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_r64_imm32_c7") => {
            let rm = get_u32(values, "rm", instruction)?;
            let imm = get_i64(values, "imm", instruction)? as u32;
            let mut out = vec![0x48 | u8::from(rm >= 8), 0xc7, 0xc0 | ((rm as u8) & 0x07)];
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_m64_imm32_c7") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let imm = get_i64(values, "imm", instruction)? as u32;
            let mut out = vec![
                0x48 | (encoded.rex_x << 1) | encoded.rex_b,
                0xc7,
                ((encoded.mod_bits & 0x03) << 6) | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_m16_imm16_c7") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let imm = get_u32(values, "imm", instruction)? as u16;
            let mut out = vec![0x66];
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0xc7);
            out.push(((encoded.mod_bits & 0x03) << 6) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.cmpxchg_r16_r16") => {
            let rm = get_u32(values, "rm", instruction)?;
            let reg = get_u32(values, "reg", instruction)?;
            Ok(vec![
                0x66,
                0x0f,
                0xb1,
                0xc0 | (((reg as u8) & 0x07) << 3) | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.mov_r64_r64") => {
            let rm = get_u32(values, "rm", instruction)?;
            let reg = get_u32(values, "reg", instruction)?;
            Ok(vec![
                0x48 | (u8::from(reg >= 8) << 2) | u8::from(rm >= 8),
                0x89,
                0xc0 | (((reg as u8) & 0x07) << 3) | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.mov_m32_r32") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = Vec::new();
            if reg >= 8 || encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0x89);
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_r32_m32") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = Vec::new();
            if reg >= 8 || encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0x8b);
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_m64_r64") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = vec![
                0x48 | (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b,
                0x89,
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.cmpxchg_m64_r64") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = vec![
                0x48 | (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b,
                0x0f,
                0xb1,
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.movq_mm_m64") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let mut out = vec![
                0x0f,
                0x6f,
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.movups_m128_xmm")
        | (Architecture::X86_64, "x86_64.movaps_m128_xmm") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            if reg >= 8 || encoded.rex_x != 0 || encoded.rex_b != 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let mut out = vec![
                0x0f,
                if form.id().name() == "x86_64.movaps_m128_xmm" {
                    0x29
                } else {
                    0x11
                },
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.movups_xmm_m128")
        | (Architecture::X86_64, "x86_64.movaps_xmm_m128") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            if reg >= 8 || encoded.rex_x != 0 || encoded.rex_b != 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let mut out = vec![
                0x0f,
                if form.id().name() == "x86_64.movaps_xmm_m128" {
                    0x28
                } else {
                    0x10
                },
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.vmovdqa_xmm_m128") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            if reg >= 8 || encoded.rex_x != 0 || encoded.rex_b != 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let mut out = vec![
                0xc5,
                0xf9,
                0x6f,
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_r64_m64") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = vec![
                0x48 | (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b,
                0x8b,
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.movsxd_r32_m32") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = Vec::new();
            let rex = (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b;
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0x63);
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.movsxd_r64_r32") => {
            let rm = get_u32(values, "rm", instruction)?;
            let reg = get_u32(values, "reg", instruction)?;
            Ok(vec![
                0x48 | (u8::from(reg >= 8) << 2) | u8::from(rm >= 8),
                0x63,
                0xc0 | (((reg as u8) & 0x07) << 3) | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.lea_r64_m") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = vec![
                0x48 | (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b,
                0x8d,
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.cmovb_r32_r32")
        | (Architecture::X86_64, "x86_64.adc_r32_r32")
        | (Architecture::X86_64, "x86_64.sbb_r32_r32")
        | (Architecture::X86_64, "x86_64.cmpxchg_r32_r32")
        | (Architecture::X86_64, "x86_64.imul_r32_r32") => {
            let reg = get_u32(values, "reg", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            let opcode = match form.id().name().as_str() {
                "x86_64.cmovb_r32_r32" => vec![0x0f, 0x42],
                "x86_64.adc_r32_r32" => vec![0x13],
                "x86_64.sbb_r32_r32" => vec![0x1b],
                "x86_64.cmpxchg_r32_r32" => vec![0x0f, 0xb1],
                "x86_64.imul_r32_r32" => vec![0x0f, 0xaf],
                _ => unreachable!(),
            };
            let mut out = opcode;
            out.push(0xc0 | (((reg as u8) & 0x07) << 3) | ((rm as u8) & 0x07));
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.cmovae_r64_r64") => {
            let reg = get_u32(values, "reg", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![
                0x48 | (u8::from(reg >= 8) << 2) | u8::from(rm >= 8),
                0x0f,
                0x43,
                0xc0 | (((reg as u8) & 0x07) << 3) | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.bswap_r32") => {
            let rd = get_u32(values, "rd", instruction)?;
            Ok(vec![0x0f, 0xc8 | ((rd as u8) & 0x07)])
        }
        (Architecture::X86_64, "x86_64.add_r64_imm8")
        | (Architecture::X86_64, "x86_64.or_r64_imm8")
        | (Architecture::X86_64, "x86_64.adc_r64_imm8")
        | (Architecture::X86_64, "x86_64.sbb_r64_imm8")
        | (Architecture::X86_64, "x86_64.and_r64_imm8") => {
            let opcode_ext = match form.id().name().as_str() {
                "x86_64.add_r64_imm8" => 0,
                "x86_64.or_r64_imm8" => 1,
                "x86_64.adc_r64_imm8" => 2,
                "x86_64.sbb_r64_imm8" => 3,
                "x86_64.and_r64_imm8" => 4,
                _ => unreachable!(),
            };
            let rm = get_u32(values, "rm", instruction)?;
            let imm = get_u32(values, "imm", instruction)? as u8;
            Ok(vec![
                0x48 | u8::from(rm >= 8),
                0x83,
                0xc0 | ((opcode_ext as u8) << 3) | ((rm as u8) & 0x07),
                imm,
            ])
        }
        (Architecture::X86_64, "x86_64.cmp_m8_imm8") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let imm = get_u32(values, "imm", instruction)? as u8;
            let mut out = Vec::new();
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0x80);
            out.push(((encoded.mod_bits & 0x03) << 6) | (7 << 3) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            out.push(imm);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.cmp_al_imm8") => {
            let imm = get_u32(values, "imm", instruction)? as u8;
            Ok(vec![0x3c, imm])
        }
        (Architecture::X86_64, "x86_64.or_al_imm8")
        | (Architecture::X86_64, "x86_64.adc_al_imm8")
        | (Architecture::X86_64, "x86_64.sbb_al_imm8")
        | (Architecture::X86_64, "x86_64.and_al_imm8")
        | (Architecture::X86_64, "x86_64.sub_al_imm8") => {
            let opcode = match form.id().name().as_str() {
                "x86_64.or_al_imm8" => 0x0c,
                "x86_64.adc_al_imm8" => 0x14,
                "x86_64.sbb_al_imm8" => 0x1c,
                "x86_64.and_al_imm8" => 0x24,
                "x86_64.sub_al_imm8" => 0x2c,
                _ => unreachable!(),
            };
            let imm = get_u32(values, "imm", instruction)? as u8;
            Ok(vec![opcode, imm])
        }
        (Architecture::X86_64, "x86_64.add_r8_r8") | (Architecture::X86_64, "x86_64.or_r8_r8") => {
            let reg = get_u32(values, "reg", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            let first = expect_register_operand(instruction, 0)?;
            let second = expect_register_operand(instruction, 1)?;
            let needs_low_rex = matches!(first.name.as_str(), "spl" | "bpl" | "sil" | "dil")
                || matches!(second.name.as_str(), "spl" | "bpl" | "sil" | "dil");
            let rex = (u8::from(reg >= 8) << 2) | u8::from(rm >= 8 || needs_low_rex);
            let opcode = if form.id().name() == "x86_64.add_r8_r8" {
                0x02
            } else {
                0x08
            };
            let mut out = Vec::new();
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(opcode);
            out.push(0xc0 | (((reg as u8) & 0x07) << 3) | ((rm as u8) & 0x07));
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.add_r64_imm32")
        | (Architecture::X86_64, "x86_64.xor_r64_imm32")
        | (Architecture::X86_64, "x86_64.test_r64_imm32") => {
            let opcode_ext = match form.id().name().as_str() {
                "x86_64.add_r64_imm32" => 0,
                "x86_64.xor_r64_imm32" => 6,
                "x86_64.test_r64_imm32" => 0,
                _ => unreachable!(),
            };
            let opcode = if form.id().name() == "x86_64.test_r64_imm32" {
                0xf7
            } else {
                0x81
            };
            let rm = get_u32(values, "rm", instruction)?;
            let imm = get_i64(values, "imm", instruction)? as u32;
            let mut out = vec![
                0x48 | u8::from(rm >= 8),
                opcode,
                0xc0 | ((opcode_ext as u8) << 3) | ((rm as u8) & 0x07),
            ];
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.cmp_m64_imm32") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let imm = get_i64(values, "imm", instruction)? as u32;
            let mut out = vec![0x48 | (encoded.rex_x << 1) | encoded.rex_b, 0x81];
            out.push(((encoded.mod_bits & 0x03) << 6) | (7 << 3) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.cmp_eax_imm32")
        | (Architecture::X86_64, "x86_64.test_eax_imm32")
        | (Architecture::X86_64, "x86_64.and_eax_imm32")
        | (Architecture::X86_64, "x86_64.add_eax_imm32")
        | (Architecture::X86_64, "x86_64.or_eax_imm32")
        | (Architecture::X86_64, "x86_64.adc_eax_imm32")
        | (Architecture::X86_64, "x86_64.sbb_eax_imm32")
        | (Architecture::X86_64, "x86_64.sub_eax_imm32")
        | (Architecture::X86_64, "x86_64.xor_eax_imm32") => {
            let opcode = match form.id().name().as_str() {
                "x86_64.cmp_eax_imm32" => 0x3d,
                "x86_64.test_eax_imm32" => 0xa9,
                "x86_64.and_eax_imm32" => 0x25,
                "x86_64.add_eax_imm32" => 0x05,
                "x86_64.or_eax_imm32" => 0x0d,
                "x86_64.adc_eax_imm32" => 0x15,
                "x86_64.sbb_eax_imm32" => 0x1d,
                "x86_64.sub_eax_imm32" => 0x2d,
                "x86_64.xor_eax_imm32" => 0x35,
                _ => unreachable!(),
            };
            let imm = get_i64(values, "imm", instruction)? as u32;
            let mut out = vec![opcode];
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.cmp_rax_imm32")
        | (Architecture::X86_64, "x86_64.test_rax_imm32") => {
            let opcode = if form.id().name() == "x86_64.cmp_rax_imm32" {
                0x3d
            } else {
                0xa9
            };
            let imm = get_i64(values, "imm", instruction)? as u32;
            let mut out = vec![0x48, opcode];
            out.extend_from_slice(&imm.to_le_bytes());
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.not_r64") | (Architecture::X86_64, "x86_64.neg_r64") => {
            let opcode_ext = if form.id().name() == "x86_64.not_r64" {
                2
            } else {
                3
            };
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![
                0x48 | u8::from(rm >= 8),
                0xf7,
                0xc0 | ((opcode_ext as u8) << 3) | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.imul_m64") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let mut out = vec![0x48 | (encoded.rex_x << 1) | encoded.rex_b, 0xf7];
            out.push(((encoded.mod_bits & 0x03) << 6) | (5 << 3) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.imul_r64_m64") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = vec![
                0x48 | (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b,
                0x0f,
                0xaf,
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.idiv_r64") => {
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![
                0x48 | u8::from(rm >= 8),
                0xf7,
                0xf8 | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.pavgb_mm_mm") => {
            let reg = get_u32(values, "reg", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![
                0x0f,
                0xe0,
                0xc0 | (((reg as u8) & 0x07) << 3) | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.vmovdqu_ymm_m256_c5") => {
            let memory = expect_memory_operand(instruction, 1)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let byte1 = 0x7e | if reg < 8 { 0x80 } else { 0 };
            let mut out = vec![
                0xc5,
                byte1,
                0x6f,
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.vmovdqu_ymm_m256_c4")
        | (Architecture::X86_64, "x86_64.vmovdqu_m256_ymm_c4")
        | (Architecture::X86_64, "x86_64.vmovntdq_m256_ymm_c4") => {
            let (memory_index, opcode, third_byte) = match form.id().name().as_str() {
                "x86_64.vmovdqu_ymm_m256_c4" => (1, 0x6f, 0x7e),
                "x86_64.vmovdqu_m256_ymm_c4" => (0, 0x7f, 0x7e),
                "x86_64.vmovntdq_m256_ymm_c4" => (0, 0xe7, 0x7d),
                _ => unreachable!(),
            };
            let memory = expect_memory_operand(instruction, memory_index)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let byte2 = (if reg < 8 { 0x80 } else { 0 })
                | (if encoded.rex_x == 0 { 0x40 } else { 0 })
                | (if encoded.rex_b == 0 { 0x20 } else { 0 })
                | 0x01;
            let mut out = vec![
                0xc4,
                byte2,
                third_byte,
                opcode,
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            ];
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.vpmovmskb_r32_xmm") => {
            let reg = get_u32(values, "reg", instruction)?;
            let rm = get_u32(values, "rm", instruction)?;
            if rm >= 8 {
                return Err(EncodeError::OperandMismatch(instruction.mnemonic.clone()));
            }
            let byte1 = 0x79 | if reg < 8 { 0x80 } else { 0 };
            Ok(vec![
                0xc5,
                byte1,
                0xd7,
                0xc0 | (((reg as u8) & 0x07) << 3) | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.inc_m8_groupfe") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let mut out = Vec::new();
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0xfe);
            out.push(((encoded.mod_bits & 0x03) << 6) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.dec_r8_groupfe") => {
            let rm = get_u32(values, "rm", instruction)?;
            let register = expect_register_operand(instruction, 0)?;
            let rex = x86_r8_rex_bits(&register.name, rm);
            let mut out = Vec::new();
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0xfe);
            out.push(0xc8 | ((rm as u8) & 0x07));
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.shr_r8_imm8") => {
            let rm = get_u32(values, "rm", instruction)?;
            let imm = get_u32(values, "imm", instruction)? as u8;
            let register = expect_register_operand(instruction, 0)?;
            let rex = x86_r8_rex_bits(&register.name, rm);
            let mut out = Vec::new();
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0xc0);
            out.push(0xe8 | ((rm as u8) & 0x07));
            out.push(imm);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.rol_m32_imm8") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let imm = get_u32(values, "imm", instruction)? as u8;
            let mut out = Vec::new();
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0xc1);
            out.push(((encoded.mod_bits & 0x03) << 6) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            out.push(imm);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.sar_r64_imm8") => {
            let rm = get_u32(values, "rm", instruction)?;
            let imm = get_u32(values, "imm", instruction)? as u8;
            Ok(vec![
                0x48 | u8::from(rm >= 8),
                0xc1,
                0xf8 | ((rm as u8) & 0x07),
                imm,
            ])
        }
        (Architecture::X86_64, "x86_64.shl_r32_one") => {
            let rm = get_u32(values, "rm", instruction)?;
            let mut out = Vec::new();
            if rm >= 8 {
                out.push(0x41);
            }
            out.push(0xd1);
            out.push(0xe0 | ((rm as u8) & 0x07));
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.shr_r64_one") => {
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![
                0x48 | u8::from(rm >= 8),
                0xd1,
                0xe8 | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.rcl_r8_cl") => {
            let rm = get_u32(values, "rm", instruction)?;
            let register = expect_register_operand(instruction, 0)?;
            let rex = x86_r8_rex_bits(&register.name, rm);
            let mut out = Vec::new();
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0xd2);
            out.push(0xd0 | ((rm as u8) & 0x07));
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.rcl_m8_cl") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let mut out = Vec::new();
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0xd2);
            out.push(((encoded.mod_bits & 0x03) << 6) | (2 << 3) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.ror_r32_cl") => {
            let rm = get_u32(values, "rm", instruction)?;
            let mut out = Vec::new();
            if rm >= 8 {
                out.push(0x41);
            }
            out.push(0xd3);
            out.push(0xc8 | ((rm as u8) & 0x07));
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.rcl_r32_cl") => {
            let rm = get_u32(values, "rm", instruction)?;
            let mut out = Vec::new();
            if rm >= 8 {
                out.push(0x41);
            }
            out.push(0xd3);
            out.push(0xd0 | ((rm as u8) & 0x07));
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.shr_r64_cl") => {
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![
                0x48 | u8::from(rm >= 8),
                0xd3,
                0xe8 | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.inc_r64_groupff")
        | (Architecture::X86_64, "x86_64.dec_r64_groupff")
        | (Architecture::X86_64, "x86_64.push_r64_groupff") => {
            let opcode_ext = match form.id().name().as_str() {
                "x86_64.inc_r64_groupff" => 0,
                "x86_64.dec_r64_groupff" => 1,
                "x86_64.push_r64_groupff" => 6,
                _ => unreachable!(),
            };
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![
                0x48 | u8::from(rm >= 8),
                0xff,
                0xc0 | ((opcode_ext as u8) << 3) | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.xchg_r32_r32") => {
            let rm = get_u32(values, "rm", instruction)?;
            let reg = get_u32(values, "reg", instruction)?;
            Ok(vec![
                0x87,
                0xc0 | (((reg as u8) & 0x07) << 3) | ((rm as u8) & 0x07),
            ])
        }
        (Architecture::X86_64, "x86_64.xchg_m8_r8") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let rex = x86_r8_rex_bits(&expect_register_operand(instruction, 1)?.name, reg)
                | (encoded.rex_x << 1)
                | encoded.rex_b;
            let mut out = Vec::new();
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0x86);
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.cmpxchg_lock_m8_r8") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let rex = x86_r8_rex_bits(&expect_register_operand(instruction, 1)?.name, reg)
                | (encoded.rex_x << 1)
                | encoded.rex_b;
            let mut out = vec![0xf0];
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0x0f);
            out.push(0xb0);
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.xchg_m32_r32") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = Vec::new();
            let rex = (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b;
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0x87);
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.xadd_lock_m32_r32") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let reg = get_u32(values, "reg", instruction)?;
            let mut out = vec![0xf0];
            let rex = (u8::from(reg >= 8) << 2) | (encoded.rex_x << 1) | encoded.rex_b;
            if rex != 0 {
                out.push(0x40 | rex);
            }
            out.push(0x0f);
            out.push(0xc1);
            out.push(
                ((encoded.mod_bits & 0x03) << 6)
                    | (((reg as u8) & 0x07) << 3)
                    | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.xchg_eax_r32") => {
            let reg = get_u32(values, "reg", instruction)?;
            Ok(vec![0x90 | ((reg as u8) & 0x07)])
        }
        (Architecture::X86_64, "x86_64.xchg_rax_r64") => {
            let reg = get_u32(values, "reg", instruction)?;
            Ok(vec![0x48 | u8::from(reg >= 8), 0x90 | ((reg as u8) & 0x07)])
        }
        (Architecture::X86_64, "x86_64.sete_r8") => {
            let rm = get_u32(values, "rm", instruction)?;
            Ok(vec![0x0f, 0x94, 0xc0 | ((rm as u8) & 0x07)])
        }
        (Architecture::X86_64, "x86_64.setne_m8") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let mut out = Vec::new();
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0x0f);
            out.push(0x95);
            out.push(((encoded.mod_bits & 0x03) << 6) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.fimul_m32")
        | (Architecture::X86_64, "x86_64.fistp_m32")
        | (Architecture::X86_64, "x86_64.fstp_m64")
        | (Architecture::X86_64, "x86_64.fisttp_m64") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let (opcode, opcode_ext) = match form.id().name().as_str() {
                "x86_64.fimul_m32" => (0xda, 1u8),
                "x86_64.fistp_m32" => (0xdb, 3u8),
                "x86_64.fstp_m64" => (0xdd, 3u8),
                "x86_64.fisttp_m64" => (0xdd, 1u8),
                _ => unreachable!(),
            };
            let mut out = Vec::new();
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(opcode);
            out.push(((encoded.mod_bits & 0x03) << 6) | (opcode_ext << 3) | encoded.rm_low_bits);
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.mov_r8_imm8") => {
            let rd = get_u32(values, "rd", instruction)?;
            let imm = get_i64(values, "imm", instruction)? as u8;
            Ok(vec![0xb0 | ((rd as u8) & 0x07), imm])
        }
        (Architecture::X86_64, "x86_64.push_r64")
        | (Architecture::X86_64, "x86_64.push_r64_rex") => {
            let reg = get_u32(values, "reg", instruction)?;
            if reg >= 8 {
                Ok(vec![0x41, 0x50 | ((reg as u8) & 0x07)])
            } else {
                Ok(vec![0x50 | (reg as u8)])
            }
        }
        (Architecture::X86_64, "x86_64.pop_r64") | (Architecture::X86_64, "x86_64.pop_r64_rex") => {
            let reg = get_u32(values, "reg", instruction)?;
            if reg >= 8 {
                Ok(vec![0x41, 0x58 | ((reg as u8) & 0x07)])
            } else {
                Ok(vec![0x58 | (reg as u8)])
            }
        }
        (Architecture::X86_64, "x86_64.int3") => Ok(vec![0xcc]),
        (Architecture::X86_64, "x86_64.int_imm8") => {
            let imm = get_u32(values, "imm", instruction)? as u8;
            Ok(vec![0xcd, imm])
        }
        (Architecture::X86_64, "x86_64.int1") => Ok(vec![0xf1]),
        (Architecture::X86_64, "x86_64.cmc") => Ok(vec![0xf5]),
        (Architecture::X86_64, "x86_64.sti") => Ok(vec![0xfb]),
        (Architecture::X86_64, "x86_64.in_al_imm8") => {
            let imm = get_u32(values, "imm", instruction)? as u8;
            Ok(vec![0xe4, imm])
        }
        (Architecture::X86_64, "x86_64.in_eax_imm8") => {
            let imm = get_u32(values, "imm", instruction)? as u8;
            Ok(vec![0xe5, imm])
        }
        (Architecture::X86_64, "x86_64.out_imm8_al") => {
            let imm = get_u32(values, "imm", instruction)? as u8;
            Ok(vec![0xe6, imm])
        }
        (Architecture::X86_64, "x86_64.insb") => Ok(vec![0x6c]),
        (Architecture::X86_64, "x86_64.outsd") => Ok(vec![0x6f]),
        (Architecture::X86_64, "x86_64.enter") => {
            let frame = get_u32(values, "frame", instruction)? as u16;
            let nesting = get_u32(values, "nesting", instruction)? as u8;
            let mut out = vec![0xc8];
            out.extend_from_slice(&frame.to_le_bytes());
            out.push(nesting);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.leave") => Ok(vec![0xc9]),
        (Architecture::X86_64, "x86_64.nop") => Ok(vec![0x90]),
        (Architecture::X86_64, "x86_64.nop_4") => Ok(vec![0x0f, 0x1f, 0x40, 0x00]),
        (Architecture::X86_64, "x86_64.nop_5") => Ok(vec![0x0f, 0x1f, 0x44, 0x00, 0x00]),
        (Architecture::X86_64, "x86_64.nop_9") => {
            Ok(vec![0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00])
        }
        (Architecture::X86_64, "x86_64.ud2") => Ok(vec![0x0f, 0x0b]),
        (Architecture::X86_64, "x86_64.xgetbv") => Ok(vec![0x0f, 0x01, 0xd0]),
        (Architecture::X86_64, "x86_64.sfence") => Ok(vec![0x0f, 0xae, 0xf8]),
        (Architecture::X86_64, "x86_64.cpuid") => Ok(vec![0x0f, 0xa2]),
        (Architecture::X86_64, "x86_64.iretd") => Ok(vec![0xcf]),
        (Architecture::X86_64, "x86_64.iretq") => Ok(vec![0x48, 0xcf]),
        (Architecture::X86_64, "x86_64.cwde") => Ok(vec![0x98]),
        (Architecture::X86_64, "x86_64.cdqe") => Ok(vec![0x48, 0x98]),
        (Architecture::X86_64, "x86_64.cdq") => Ok(vec![0x99]),
        (Architecture::X86_64, "x86_64.cqo") => Ok(vec![0x48, 0x99]),
        (Architecture::X86_64, "x86_64.pushfq") => Ok(vec![0x9c]),
        (Architecture::X86_64, "x86_64.popfq") => Ok(vec![0x9d]),
        (Architecture::X86_64, "x86_64.sahf") => Ok(vec![0x9e]),
        (Architecture::X86_64, "x86_64.lahf") => Ok(vec![0x9f]),
        (Architecture::X86_64, "x86_64.movsb") => Ok(vec![0xa4]),
        (Architecture::X86_64, "x86_64.movsd") => Ok(vec![0xa5]),
        (Architecture::X86_64, "x86_64.movsq") => Ok(vec![0x48, 0xa5]),
        (Architecture::X86_64, "x86_64.cmpsb") => Ok(vec![0xa6]),
        (Architecture::X86_64, "x86_64.cmpsd") => Ok(vec![0xa7]),
        (Architecture::X86_64, "x86_64.stosb") => Ok(vec![0xaa]),
        (Architecture::X86_64, "x86_64.stosd") => Ok(vec![0xab]),
        (Architecture::X86_64, "x86_64.lodsb") => Ok(vec![0xac]),
        (Architecture::X86_64, "x86_64.lodsd") => Ok(vec![0xad]),
        (Architecture::X86_64, "x86_64.scasb") => Ok(vec![0xae]),
        (Architecture::X86_64, "x86_64.scasd") => Ok(vec![0xaf]),
        (Architecture::X86_64, "x86_64.stmxcsr_m32")
        | (Architecture::X86_64, "x86_64.ldmxcsr_m32") => {
            let memory = expect_memory_operand(instruction, 0)?;
            let encoded = crate::arch::x86_64::adapters::encode_modrm_memory(memory)?;
            let opcode_ext = if form.id().name() == "x86_64.stmxcsr_m32" {
                3
            } else {
                2
            };
            let mut out = Vec::new();
            if encoded.rex_x != 0 || encoded.rex_b != 0 {
                out.push(0x40 | (encoded.rex_x << 1) | encoded.rex_b);
            }
            out.push(0x0f);
            out.push(0xae);
            out.push(
                ((encoded.mod_bits & 0x03) << 6) | ((opcode_ext as u8) << 3) | encoded.rm_low_bits,
            );
            if let Some(sib) = encoded.sib {
                out.push(sib);
            }
            out.extend_from_slice(&encoded.displacement);
            Ok(out)
        }
        (Architecture::X86_64, "x86_64.vzeroupper") => Ok(vec![0xc5, 0xf8, 0x77]),
        _ => Err(EncodeError::UnsupportedForm(instruction.mnemonic.clone())),
    }
}

fn get_i64(values: &ValueMap, field: &str, instruction: &Instruction) -> Result<i64, EncodeError> {
    values
        .get(field)
        .copied()
        .ok_or_else(|| EncodeError::OperandMismatch(instruction.mnemonic.clone()))
}

fn get_u32(values: &ValueMap, field: &str, instruction: &Instruction) -> Result<u32, EncodeError> {
    u32::try_from(get_i64(values, field, instruction)?)
        .map_err(|_| EncodeError::OperandMismatch(instruction.mnemonic.clone()))
}

fn expect_memory_operand(
    instruction: &Instruction,
    index: usize,
) -> Result<&crate::model::MemoryOperand, EncodeError> {
    match instruction.operands.get(index) {
        Some(crate::model::Operand::Memory(memory)) => Ok(memory),
        _ => Err(EncodeError::OperandMismatch(instruction.mnemonic.clone())),
    }
}

fn expect_register_operand(
    instruction: &Instruction,
    index: usize,
) -> Result<&crate::model::Register, EncodeError> {
    match instruction.operands.get(index) {
        Some(crate::model::Operand::Register(register)) => Ok(register),
        _ => Err(EncodeError::OperandMismatch(instruction.mnemonic.clone())),
    }
}

fn x86_r8_rex_bits(name: &str, index: u32) -> u8 {
    (u8::from(index >= 8) << 2) | u8::from(matches!(name, "spl" | "bpl" | "sil" | "dil"))
}
