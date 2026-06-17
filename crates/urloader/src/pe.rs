use crate::{
    Architecture, Endian, FormatDetails, ImageClass, ImageFormat, LoadError, LoadProfile,
    LoadedImage, Result, Section, Segment,
};

const PE: &str = "PE";
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const OPTIONAL_PE32: u16 = 0x10b;
const OPTIONAL_PE32_PLUS: u16 = 0x20b;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub fn load(bytes: &[u8]) -> Result<LoadedImage> {
    need(bytes, 0, 0x40, "dos header")?;
    if &bytes[0..2] != b"MZ" {
        return Err(LoadError::UnknownFormat);
    }
    let pe_offset = u32_at(bytes, 0x3c, "e_lfanew")? as usize;
    need(bytes, pe_offset, 4, "pe signature")?;
    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(LoadError::Malformed {
            format: PE,
            field: "signature",
            message: "missing PE signature".to_string(),
        });
    }

    let coff = pe_offset + 4;
    need(bytes, coff, 20, "coff header")?;
    let machine = u16_at(bytes, coff, "machine")?;
    let section_count = u16_at(bytes, coff + 2, "number_of_sections")?;
    let optional_size = u16_at(bytes, coff + 16, "size_of_optional_header")?;
    let optional = coff + 20;
    need(
        bytes,
        optional,
        usize::from(optional_size),
        "optional header",
    )?;

    let magic = u16_at(bytes, optional, "optional magic")?;
    let class = match magic {
        OPTIONAL_PE32 => ImageClass::Bits32,
        OPTIONAL_PE32_PLUS => ImageClass::Bits64,
        other => {
            return Err(LoadError::Unsupported {
                format: PE,
                field: "optional header magic",
                value: format!("0x{other:x}"),
            })
        }
    };
    let entry_rva = u32_at(bytes, optional + 16, "address_of_entry_point")?;
    let image_base = match class {
        ImageClass::Bits32 => u32_at(bytes, optional + 28, "image_base")? as u64,
        ImageClass::Bits64 => u64_at(bytes, optional + 24, "image_base")?,
    };

    let section_table = optional + usize::from(optional_size);
    let sections = parse_sections(bytes, section_table, section_count, image_base)?;
    let segments = sections_to_segments(&sections);
    Ok(LoadedImage {
        format: ImageFormat::Pe,
        architecture: pe_arch(machine),
        class,
        endian: Endian::Little,
        profile: LoadProfile::Executable,
        entry: image_base + u64::from(entry_rva),
        image_base,
        segments,
        sections,
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        diagnostics: Vec::new(),
        format_details: FormatDetails::Pe {
            machine,
            image_base,
        },
        bytes: bytes.to_vec(),
    })
}

fn parse_sections(bytes: &[u8], table: usize, count: u16, image_base: u64) -> Result<Vec<Section>> {
    let mut sections = Vec::new();
    for idx in 0..count {
        let off = table + usize::from(idx) * 40;
        need(bytes, off, 40, "section header")?;
        let raw_name = &bytes[off..off + 8];
        let name_len = raw_name.iter().position(|byte| *byte == 0).unwrap_or(8);
        let virtual_size = u32_at(bytes, off + 8, "virtual_size")?;
        let virtual_address = u32_at(bytes, off + 12, "virtual_address")?;
        let raw_size = u32_at(bytes, off + 16, "size_of_raw_data")?;
        let raw_ptr = u32_at(bytes, off + 20, "pointer_to_raw_data")?;
        let characteristics = u32_at(bytes, off + 36, "characteristics")?;
        range_in_file(
            bytes,
            u64::from(raw_ptr),
            u64::from(raw_size),
            "section raw range",
        )?;
        sections.push(Section {
            id: i64::from(idx),
            name: String::from_utf8_lossy(&raw_name[..name_len]).to_string(),
            addr: image_base + u64::from(virtual_address),
            offset: u64::from(raw_ptr),
            size: u64::from(raw_size.max(virtual_size)),
            permissions: section_permissions(characteristics),
            flags: u64::from(characteristics),
        });
    }
    Ok(sections)
}

fn sections_to_segments(sections: &[Section]) -> Vec<Segment> {
    sections
        .iter()
        .map(|section| Segment {
            id: section.id,
            name: section.name.clone(),
            vaddr: section.addr,
            file_offset: section.offset,
            file_size: section.size,
            mem_size: section.size,
            permissions: section.permissions.clone(),
        })
        .collect()
}

fn pe_arch(machine: u16) -> Architecture {
    match machine {
        IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
        other => Architecture::Unknown(other),
    }
}

fn section_permissions(flags: u32) -> String {
    let mut out = String::new();
    out.push(if flags & IMAGE_SCN_MEM_READ != 0 {
        'r'
    } else {
        '-'
    });
    out.push(if flags & IMAGE_SCN_MEM_WRITE != 0 {
        'w'
    } else {
        '-'
    });
    out.push(if flags & IMAGE_SCN_MEM_EXECUTE != 0 {
        'x'
    } else {
        '-'
    });
    out
}

fn range_in_file(bytes: &[u8], offset: u64, size: u64, field: &'static str) -> Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| LoadError::Malformed {
            format: PE,
            field,
            message: "range overflow".to_string(),
        })?;
    let end = usize::try_from(end).map_err(|_| LoadError::Malformed {
        format: PE,
        field,
        message: "range does not fit host usize".to_string(),
    })?;
    if end > bytes.len() {
        return Err(LoadError::Malformed {
            format: PE,
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
        Err(LoadError::Truncated { format: PE, field })
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
