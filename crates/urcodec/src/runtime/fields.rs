use crate::{
    arch::{aarch64::adapters, x86_64::adapters as x86_adapters},
    error::DecodeError,
    form::{FieldSource, FormSchema},
    runtime::{layout::LayoutView, ValueMap},
};

pub fn extract_fields(form: &FormSchema, layout: &LayoutView) -> Result<ValueMap, DecodeError> {
    let mut values = ValueMap::new();
    for field in form.fields() {
        let value = match (&field.source, layout) {
            (FieldSource::Bits { start, end }, LayoutView::Aarch64Word { word, .. }) => {
                i64::from(extract_bits(*word, *start, *end))
            }
            (FieldSource::SignedBits { start, end }, LayoutView::Aarch64Word { word, .. }) => {
                sign_extend(extract_bits(*word, *start, *end), end - start + 1)
            }
            (FieldSource::Literal(value), _) => *value,
            (FieldSource::Aarch64AdrTarget { page }, LayoutView::Aarch64Word { word, address }) => {
                let immlo = extract_bits(*word, 29, 30);
                let immhi = extract_bits(*word, 5, 23);
                let imm = (immhi << 2) | immlo;
                let target = if *page {
                    let offset = sign_extend(imm, 21) << 12;
                    (*address & !0x0fff).wrapping_add_signed(offset)
                } else {
                    let offset = sign_extend(imm, 21);
                    address.wrapping_add_signed(offset)
                };
                i64::try_from(target).map_err(|_| DecodeError::UnsupportedTarget)?
            }
            (FieldSource::Aarch64AddSubImmediate, LayoutView::Aarch64Word { word, .. }) => {
                let shift = if extract_bits(*word, 22, 22) == 1 {
                    12
                } else {
                    0
                };
                i64::from(extract_bits(*word, 10, 21) << shift)
            }
            (FieldSource::Aarch64TbzBit, LayoutView::Aarch64Word { word, .. }) => {
                i64::from((extract_bits(*word, 31, 31) << 5) | extract_bits(*word, 19, 23))
            }
            (FieldSource::Aarch64MoveWideImmediate, LayoutView::Aarch64Word { word, .. }) => {
                let hw = extract_bits(*word, 21, 22);
                let imm16 = u64::from(extract_bits(*word, 5, 20));
                i64::try_from(imm16 << (hw * 16)).map_err(|_| DecodeError::UnsupportedTarget)?
            }
            (FieldSource::Aarch64LogicalImmediate, LayoutView::Aarch64Word { word, .. }) => {
                let is_64 = extract_bits(*word, 31, 31) == 1;
                let reg_size = if is_64 { 64 } else { 32 };
                let n = extract_bits(*word, 22, 22);
                let immr = extract_bits(*word, 16, 21);
                let imms = extract_bits(*word, 10, 15);
                let mask = adapters::decode_logical_immediate_mask(n, immr, imms, reg_size)
                    .ok_or(DecodeError::UnsupportedTarget)?;
                if is_64 {
                    mask as i64
                } else {
                    i64::from((mask & 0xffff_ffff) as u32)
                }
            }
            (FieldSource::Aarch64BitfieldLsrImmediate, LayoutView::Aarch64Word { word, .. }) => {
                let is_64 = extract_bits(*word, 31, 31) == 1;
                let width = if is_64 { 64 } else { 32 };
                let immr = extract_bits(*word, 16, 21);
                let imms = extract_bits(*word, 10, 15);
                if imms != width - 1 {
                    return Err(DecodeError::UnsupportedTarget);
                }
                i64::from(immr)
            }
            (FieldSource::Aarch64BitfieldLslImmediate, LayoutView::Aarch64Word { word, .. }) => {
                let is_64 = extract_bits(*word, 31, 31) == 1;
                let width = if is_64 { 64 } else { 32 };
                let immr = extract_bits(*word, 16, 21);
                let imms = extract_bits(*word, 10, 15);
                if immr == 0 || imms + 1 != immr {
                    return Err(DecodeError::UnsupportedTarget);
                }
                i64::from(width - immr)
            }
            (FieldSource::Aarch64BitfieldAsrImmediate, LayoutView::Aarch64Word { word, .. }) => {
                let is_64 = extract_bits(*word, 31, 31) == 1;
                let width = if is_64 { 64 } else { 32 };
                let immr = extract_bits(*word, 16, 21);
                let imms = extract_bits(*word, 10, 15);
                if imms != width - 1 {
                    return Err(DecodeError::UnsupportedTarget);
                }
                i64::from(immr)
            }
            (
                FieldSource::OpcodeLowBits { offset, mask },
                LayoutView::X86ByteStream { bytes, .. },
            ) => i64::from(
                *bytes
                    .get(*offset as usize)
                    .ok_or(DecodeError::UnsupportedTarget)?
                    & mask,
            ),
            (FieldSource::OpcodeRegister { offset }, LayoutView::X86ByteStream { bytes, .. }) => {
                let opcode = *bytes
                    .get(*offset as usize)
                    .ok_or(DecodeError::UnsupportedTarget)?;
                i64::from((opcode & 0x07) | (rex_b(bytes, *offset as usize) << 3))
            }
            (FieldSource::VexVvvv, LayoutView::X86ByteStream { bytes, .. }) => {
                let vex_byte = match bytes.first().copied() {
                    Some(0xc5) => *bytes.get(1).ok_or(DecodeError::UnsupportedTarget)?,
                    Some(0xc4) => *bytes.get(2).ok_or(DecodeError::UnsupportedTarget)?,
                    _ => return Err(DecodeError::UnsupportedTarget),
                };
                i64::from((!((vex_byte >> 3) & 0x0f)) & 0x0f)
            }
            (FieldSource::ModrmReg, LayoutView::X86ByteStream { bytes, .. }) => {
                let modrm = read_modrm_byte(form, bytes)?;
                let offset = modrm_offset(form);
                i64::from(((modrm >> 3) & 0x07) | (rex_r(bytes, offset) << 3))
            }
            (FieldSource::ModrmRm, LayoutView::X86ByteStream { bytes, .. }) => {
                let modrm = read_modrm_byte(form, bytes)?;
                let offset = modrm_offset(form);
                i64::from((modrm & 0x07) | (rex_b(bytes, offset) << 3))
            }
            (FieldSource::ByteAt { offset }, LayoutView::X86ByteStream { bytes, .. }) => {
                i64::from(*bytes.get(*offset as usize).ok_or(
                    DecodeError::TruncatedInstruction {
                        expected: *offset as usize + 1,
                        actual: bytes.len(),
                    },
                )?)
            }
            (FieldSource::Immediate8, LayoutView::X86ByteStream { bytes, .. }) => {
                i64::from(read_immediate_bytes(form, bytes, 1)?[0])
            }
            (FieldSource::SignedImmediate8, LayoutView::X86ByteStream { bytes, .. }) => i64::from(
                i8::from_le_bytes([read_immediate_bytes(form, bytes, 1)?[0]]),
            ),
            (FieldSource::Immediate16, LayoutView::X86ByteStream { bytes, .. }) => {
                let imm = read_immediate_bytes(form, bytes, 2)?;
                i64::from(u16::from_le_bytes([imm[0], imm[1]]))
            }
            (FieldSource::Immediate32, LayoutView::X86ByteStream { bytes, .. }) => {
                let imm = read_immediate_bytes(form, bytes, 4)?;
                i64::from(u32::from_le_bytes([imm[0], imm[1], imm[2], imm[3]]))
            }
            (FieldSource::SignedImmediate32, LayoutView::X86ByteStream { bytes, .. }) => {
                let imm = read_immediate_bytes(form, bytes, 4)?;
                i64::from(i32::from_le_bytes([imm[0], imm[1], imm[2], imm[3]]))
            }
            (FieldSource::Immediate64, LayoutView::X86ByteStream { bytes, .. }) => {
                let imm = read_immediate_bytes(form, bytes, 8)?;
                i64::from_le_bytes([
                    imm[0], imm[1], imm[2], imm[3], imm[4], imm[5], imm[6], imm[7],
                ])
            }
            _ => 0,
        };
        values.insert(field.name, value);
    }
    Ok(values)
}

fn read_modrm_byte(form: &FormSchema, bytes: &[u8]) -> Result<u8, DecodeError> {
    let crate::form::DecodeLayout::ByteStream(layout) = form.decode_layout() else {
        return Err(DecodeError::UnsupportedTarget);
    };
    if !layout.uses_modrm {
        return Err(DecodeError::UnsupportedTarget);
    }
    let offset = layout.opcode_len as usize;
    bytes
        .get(offset)
        .copied()
        .ok_or(DecodeError::TruncatedInstruction {
            expected: offset + 1,
            actual: bytes.len(),
        })
}

fn modrm_offset(form: &FormSchema) -> usize {
    let crate::form::DecodeLayout::ByteStream(layout) = form.decode_layout() else {
        return 0;
    };
    layout.opcode_len as usize
}

fn read_immediate_bytes<'a>(
    form: &FormSchema,
    bytes: &'a [u8],
    width: usize,
) -> Result<&'a [u8], DecodeError> {
    let crate::form::DecodeLayout::ByteStream(layout) = form.decode_layout() else {
        return Err(DecodeError::UnsupportedTarget);
    };
    let offset = byte_stream_payload_offset(layout, bytes);
    let end = offset + width;
    bytes
        .get(offset..end)
        .ok_or(DecodeError::TruncatedInstruction {
            expected: end,
            actual: bytes.len(),
        })
}

fn byte_stream_payload_offset(layout: crate::form::ByteStreamLayout, bytes: &[u8]) -> usize {
    if layout.uses_modrm {
        x86_adapters::modrm_operand_end(bytes, usize::from(layout.opcode_len))
            .unwrap_or_else(|_| usize::from(layout.opcode_len) + 1)
    } else {
        usize::from(layout.opcode_len)
            + usize::from(layout.uses_sib)
            + layout.displacement_bytes.map(usize::from).unwrap_or(0)
    }
}

fn rex_b(bytes: &[u8], limit: usize) -> u8 {
    x86_adapters::rex_extension_bits(bytes, limit).0
}

fn rex_r(bytes: &[u8], limit: usize) -> u8 {
    x86_adapters::rex_extension_bits(bytes, limit).2
}

fn extract_bits(word: u32, start: u8, end: u8) -> u32 {
    let width = end - start + 1;
    let mask = if width == 32 {
        u32::MAX
    } else {
        (1u32 << width) - 1
    };
    (word >> start) & mask
}

fn sign_extend(value: u32, width: u8) -> i64 {
    let shift = 64 - i64::from(width);
    ((i64::from(value)) << shift) >> shift
}
