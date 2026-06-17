use crate::{
    Architecture, Endian, FormatDetails, ImageClass, ImageFormat, LoadError, LoadProfile,
    LoadedImage, Result, Segment,
};

const ELF: &str = "ELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

pub fn load(bytes: &[u8]) -> Result<LoadedImage> {
    let header = parse_header(bytes)?;
    let segments = parse_program_headers(bytes, &header)?;
    Ok(LoadedImage {
        format: ImageFormat::Elf,
        architecture: Architecture::Aarch64,
        class: ImageClass::Bits64,
        endian: Endian::Little,
        profile: elf_profile(header.file_type),
        entry: header.entry,
        image_base: 0,
        segments,
        sections: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        diagnostics: Vec::new(),
        format_details: FormatDetails::Elf {
            file_type: header.file_type,
            machine: header.machine,
        },
        bytes: bytes.to_vec(),
    })
}

struct ElfHeader {
    file_type: u16,
    machine: u16,
    entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

fn parse_header(bytes: &[u8]) -> Result<ElfHeader> {
    need(bytes, 0, 64, "header")?;
    if &bytes[0..4] != b"\x7fELF" {
        return Err(LoadError::UnknownFormat);
    }
    if bytes[4] != ELFCLASS64 {
        return Err(LoadError::Unsupported {
            format: ELF,
            field: "class",
            value: bytes[4].to_string(),
        });
    }
    if bytes[5] != ELFDATA2LSB {
        return Err(LoadError::Unsupported {
            format: ELF,
            field: "endianness",
            value: bytes[5].to_string(),
        });
    }
    let file_type = u16_at(bytes, 0x10, "e_type")?;
    let machine = u16_at(bytes, 0x12, "e_machine")?;
    if machine != EM_AARCH64 {
        return Err(LoadError::Unsupported {
            format: ELF,
            field: "machine",
            value: machine.to_string(),
        });
    }
    Ok(ElfHeader {
        file_type,
        machine,
        entry: u64_at(bytes, 0x18, "e_entry")?,
        phoff: u64_at(bytes, 0x20, "e_phoff")?,
        phentsize: u16_at(bytes, 0x36, "e_phentsize")?,
        phnum: u16_at(bytes, 0x38, "e_phnum")?,
    })
}

fn parse_program_headers(bytes: &[u8], header: &ElfHeader) -> Result<Vec<Segment>> {
    let mut segments = Vec::new();
    for idx in 0..header.phnum {
        let off = checked_table_offset(header.phoff, header.phentsize, idx, "program headers")?;
        need(bytes, off, usize::from(header.phentsize), "program header")?;
        let p_type = u32_at(bytes, off, "p_type")?;
        if p_type != PT_LOAD {
            continue;
        }
        let flags = u32_at(bytes, off + 4, "p_flags")?;
        let file_offset = u64_at(bytes, off + 8, "p_offset")?;
        let vaddr = u64_at(bytes, off + 16, "p_vaddr")?;
        let file_size = u64_at(bytes, off + 32, "p_filesz")?;
        let mem_size = u64_at(bytes, off + 40, "p_memsz")?;
        range_in_file(bytes, file_offset, file_size, "segment file range")?;
        segments.push(Segment {
            id: i64::from(idx),
            name: format!("LOAD_{idx}"),
            vaddr,
            file_offset,
            file_size,
            mem_size,
            permissions: permissions(flags),
        });
    }
    Ok(segments)
}

fn elf_profile(file_type: u16) -> LoadProfile {
    match file_type {
        ET_DYN => LoadProfile::SharedObject,
        ET_EXEC => LoadProfile::Executable,
        ET_REL => LoadProfile::Relocatable,
        _ => LoadProfile::StrippedLike,
    }
}

fn permissions(flags: u32) -> String {
    let mut out = String::new();
    out.push(if flags & PF_R != 0 { 'r' } else { '-' });
    out.push(if flags & PF_W != 0 { 'w' } else { '-' });
    out.push(if flags & PF_X != 0 { 'x' } else { '-' });
    out
}

fn checked_table_offset(base: u64, entsize: u16, idx: u16, field: &'static str) -> Result<usize> {
    let offset =
        base.checked_add(u64::from(entsize) * u64::from(idx))
            .ok_or_else(|| LoadError::Malformed {
                format: ELF,
                field,
                message: "table offset overflow".to_string(),
            })?;
    usize::try_from(offset).map_err(|_| LoadError::Malformed {
        format: ELF,
        field,
        message: "table offset does not fit host usize".to_string(),
    })
}

fn range_in_file(bytes: &[u8], offset: u64, size: u64, field: &'static str) -> Result<()> {
    let end = offset.checked_add(size).ok_or_else(|| LoadError::Malformed {
        format: ELF,
        field,
        message: "range overflow".to_string(),
    })?;
    let end = usize::try_from(end).map_err(|_| LoadError::Malformed {
        format: ELF,
        field,
        message: "range does not fit host usize".to_string(),
    })?;
    if end > bytes.len() {
        return Err(LoadError::Malformed {
            format: ELF,
            field,
            message: "range exceeds file length".to_string(),
        });
    }
    Ok(())
}

fn need(bytes: &[u8], offset: usize, len: usize, field: &'static str) -> Result<()> {
    if offset
        .checked_add(len)
        .is_some_and(|end| end <= bytes.len())
    {
        Ok(())
    } else {
        Err(LoadError::Truncated { format: ELF, field })
    }
}

fn u16_at(bytes: &[u8], offset: usize, field: &'static str) -> Result<u16> {
    need(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes(
        bytes[offset..offset + 2].try_into().expect("length checked"),
    ))
}

fn u32_at(bytes: &[u8], offset: usize, field: &'static str) -> Result<u32> {
    need(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes(
        bytes[offset..offset + 4].try_into().expect("length checked"),
    ))
}

fn u64_at(bytes: &[u8], offset: usize, field: &'static str) -> Result<u64> {
    need(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes(
        bytes[offset..offset + 8].try_into().expect("length checked"),
    ))
}
