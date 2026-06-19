use crate::{
    Architecture, Endian, FormatDetails, ImageClass, ImageFormat, LoadError, LoadProfile, RawImage,
    Result, Segment,
};

const ELF: &str = "ELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const SHT_SYMTAB: u32 = 2;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;

pub fn load(bytes: &[u8]) -> Result<RawImage> {
    let header = parse_header(bytes)?;
    let segments = parse_program_headers(bytes, &header)?;
    let raw_sections = parse_raw_sections(bytes, &header)?;
    let sections = normalize_sections(bytes, &raw_sections, header.shstrndx);
    let symbols = parse_symbols(bytes, &raw_sections)?;
    Ok(RawImage {
        format: ImageFormat::Elf,
        architecture: elf_architecture(header.machine),
        class: ImageClass::Bits64,
        endian: Endian::Little,
        profile: elf_profile(header.file_type),
        entry: header.entry,
        image_base: 0,
        segments,
        sections,
        symbols,
        imports: Vec::new(),
        exports: Vec::new(),
        relocations: Vec::new(),
        diagnostics: Vec::new(),
        format_details: FormatDetails::Elf {
            file_type: header.file_type,
            machine: header.machine,
        },
    })
}

struct ElfHeader {
    file_type: u16,
    machine: u16,
    entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    shoff: u64,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
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
    if !matches!(machine, EM_AARCH64 | EM_X86_64) {
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
        shoff: u64_at(bytes, 0x28, "e_shoff")?,
        shentsize: u16_at(bytes, 0x3a, "e_shentsize")?,
        shnum: u16_at(bytes, 0x3c, "e_shnum")?,
        shstrndx: u16_at(bytes, 0x3e, "e_shstrndx")?,
    })
}

fn elf_architecture(machine: u16) -> Architecture {
    match machine {
        EM_AARCH64 => Architecture::Aarch64,
        EM_X86_64 => Architecture::X86_64,
        other => Architecture::Unknown(other),
    }
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

#[derive(Debug, Clone)]
struct RawSection {
    name_offset: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

fn parse_raw_sections(bytes: &[u8], header: &ElfHeader) -> Result<Vec<RawSection>> {
    let mut out = Vec::new();
    for idx in 0..header.shnum {
        let off = checked_table_offset(header.shoff, header.shentsize, idx, "section headers")?;
        need(bytes, off, usize::from(header.shentsize), "section header")?;
        let section = RawSection {
            name_offset: u32_at(bytes, off, "sh_name")?,
            sh_type: u32_at(bytes, off + 4, "sh_type")?,
            flags: u64_at(bytes, off + 8, "sh_flags")?,
            addr: u64_at(bytes, off + 16, "sh_addr")?,
            offset: u64_at(bytes, off + 24, "sh_offset")?,
            size: u64_at(bytes, off + 32, "sh_size")?,
            link: u32_at(bytes, off + 40, "sh_link")?,
            entsize: u64_at(bytes, off + 56, "sh_entsize")?,
        };
        if section.size > 0 && section.sh_type != SHT_NOBITS {
            range_in_file(bytes, section.offset, section.size, "section file range")?;
        }
        out.push(section);
    }
    Ok(out)
}

fn normalize_sections(bytes: &[u8], raw: &[RawSection], shstrndx: u16) -> Vec<crate::Section> {
    let names = raw.get(usize::from(shstrndx));
    raw.iter()
        .enumerate()
        .map(|(idx, section)| crate::Section {
            id: idx as i64,
            name: names
                .and_then(|names| string_at_section(bytes, names, section.name_offset))
                .unwrap_or_default(),
            addr: section.addr,
            offset: section.offset,
            size: section.size,
            permissions: section_permissions(section.flags),
            flags: section.flags,
        })
        .collect()
}

fn parse_symbols(bytes: &[u8], raw: &[RawSection]) -> Result<Vec<crate::Symbol>> {
    let mut symbols = Vec::new();
    for section in raw {
        if section.sh_type != SHT_SYMTAB && section.sh_type != SHT_DYNSYM {
            continue;
        }
        if section.entsize == 0 {
            continue;
        }
        let Some(strings) = raw.get(section.link as usize) else {
            continue;
        };
        let count = section.size / section.entsize;
        for idx in 0..count {
            let off = section
                .offset
                .checked_add(idx * section.entsize)
                .ok_or_else(|| LoadError::Malformed {
                    format: ELF,
                    field: "symbol table",
                    message: "symbol offset overflow".to_string(),
                })?;
            let off = usize::try_from(off).map_err(|_| LoadError::Malformed {
                format: ELF,
                field: "symbol table",
                message: "symbol offset does not fit host usize".to_string(),
            })?;
            need(bytes, off, 24, "symbol")?;
            let name_offset = u32_at(bytes, off, "st_name")?;
            let info = bytes[off + 4];
            let value = u64_at(bytes, off + 8, "st_value")?;
            let size = u64_at(bytes, off + 16, "st_size")?;
            if value == 0 && name_offset == 0 {
                continue;
            }
            let name = string_at_section(bytes, strings, name_offset).unwrap_or_default();
            symbols.push(crate::Symbol {
                id: symbols.len() as i64,
                name,
                addr: value,
                size,
                kind: symbol_kind(info & 0x0f).to_string(),
                is_import: value == 0,
                is_export: value != 0,
            });
        }
    }
    Ok(symbols)
}

fn string_at_section(bytes: &[u8], section: &RawSection, offset: u32) -> Option<String> {
    let start = section.offset.checked_add(u64::from(offset))? as usize;
    let limit = section.offset.checked_add(section.size)? as usize;
    if start >= limit || limit > bytes.len() {
        return None;
    }
    let end = bytes[start..limit]
        .iter()
        .position(|byte| *byte == 0)
        .map(|pos| start + pos)
        .unwrap_or(limit);
    Some(String::from_utf8_lossy(&bytes[start..end]).to_string())
}

fn section_permissions(flags: u64) -> String {
    let writable = flags & 0x1 != 0;
    let executable = flags & 0x4 != 0;
    let mut out = String::new();
    out.push('r');
    out.push(if writable { 'w' } else { '-' });
    out.push(if executable { 'x' } else { '-' });
    out
}

fn symbol_kind(kind: u8) -> &'static str {
    match kind {
        1 => "Object",
        2 => "Func",
        3 => "Section",
        4 => "File",
        _ => "Unknown",
    }
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
    let offset = base
        .checked_add(u64::from(entsize) * u64::from(idx))
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
    let end = offset
        .checked_add(size)
        .ok_or_else(|| LoadError::Malformed {
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
        bytes[offset..offset + 2]
            .try_into()
            .expect("length checked"),
    ))
}

fn u32_at(bytes: &[u8], offset: usize, field: &'static str) -> Result<u32> {
    need(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("length checked"),
    ))
}

fn u64_at(bytes: &[u8], offset: usize, field: &'static str) -> Result<u64> {
    need(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("length checked"),
    ))
}
