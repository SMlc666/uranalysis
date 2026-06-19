use crate::{
    normalize::normalize_relocation, Architecture, Endian, FormatDetails, ImageClass, ImageFormat,
    LoadError, LoadProfile, RawImage, Result, Section, Segment,
};

const PE: &str = "PE";
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const OPTIONAL_PE32: u16 = 0x10b;
const OPTIONAL_PE32_PLUS: u16 = 0x20b;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, Default)]
struct DataDirectory {
    rva: u32,
    size: u32,
}

pub fn load(bytes: &[u8]) -> Result<RawImage> {
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
    let directories = parse_data_directories(bytes, optional, class, optional_size)?;
    let imports = parse_imports(bytes, &sections, image_base, directories[1])?;
    let exports = parse_exports(bytes, &sections, image_base, directories[0])?;
    let relocations = parse_base_relocations(bytes, &sections, image_base, directories[5])?;
    Ok(RawImage {
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
        imports,
        exports,
        relocations,
        diagnostics: Vec::new(),
        format_details: FormatDetails::Pe {
            machine,
            image_base,
        },
    })
}

fn parse_data_directories(
    bytes: &[u8],
    optional: usize,
    class: ImageClass,
    optional_size: u16,
) -> Result<[DataDirectory; 16]> {
    let directory_offset = match class {
        ImageClass::Bits32 => optional + 96,
        ImageClass::Bits64 => optional + 112,
    };
    if directory_offset >= optional + usize::from(optional_size) {
        return Ok([DataDirectory::default(); 16]);
    }
    let mut dirs = [DataDirectory::default(); 16];
    for (idx, dir) in dirs.iter_mut().enumerate() {
        let off = directory_offset + idx * 8;
        if off + 8 > optional + usize::from(optional_size) {
            break;
        }
        dir.rva = u32_at(bytes, off, "directory rva")?;
        dir.size = u32_at(bytes, off + 4, "directory size")?;
    }
    Ok(dirs)
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

fn parse_imports(
    bytes: &[u8],
    sections: &[Section],
    image_base: u64,
    directory: DataDirectory,
) -> Result<Vec<crate::Import>> {
    if directory.rva == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    let mut imports = Vec::new();
    let mut desc_off = rva_to_offset_sections(sections, image_base, u64::from(directory.rva))
        .ok_or_else(|| LoadError::Malformed {
            format: PE,
            field: "import directory",
            message: "directory rva not mapped".to_string(),
        })? as usize;
    let end_off = desc_off + directory.size as usize;
    while desc_off + 20 <= end_off {
        let original_first_thunk = u32_at(bytes, desc_off, "import original_first_thunk")?;
        let name_rva = u32_at(bytes, desc_off + 12, "import name rva")?;
        let first_thunk = u32_at(bytes, desc_off + 16, "import first_thunk")?;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let dll_name = read_c_string_rva(bytes, sections, image_base, name_rva)?;
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let mut thunk_off = rva_to_offset_sections(sections, image_base, u64::from(thunk_rva))
            .ok_or_else(|| LoadError::Malformed {
                format: PE,
                field: "import thunk",
                message: "thunk rva not mapped".to_string(),
            })? as usize;
        loop {
            let thunk_value = u64_at(bytes, thunk_off, "import thunk value")?;
            if thunk_value == 0 {
                break;
            }
            let name = if thunk_value & (1u64 << 63) != 0 {
                format!("ordinal:{}", thunk_value & 0xffff)
            } else {
                let hint_name_rva = thunk_value as u32;
                let hint_name_off =
                    rva_to_offset_sections(sections, image_base, u64::from(hint_name_rva))
                        .ok_or_else(|| LoadError::Malformed {
                            format: PE,
                            field: "import name",
                            message: "hint/name rva not mapped".to_string(),
                        })? as usize;
                read_c_string(bytes, hint_name_off + 2)?
            };
            imports.push(crate::Import {
                name,
                library: Some(dll_name.clone()),
            });
            thunk_off += 8;
        }
        desc_off += 20;
    }
    Ok(imports)
}

fn parse_exports(
    bytes: &[u8],
    sections: &[Section],
    image_base: u64,
    directory: DataDirectory,
) -> Result<Vec<crate::Export>> {
    if directory.rva == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    let export_off = rva_to_offset_sections(sections, image_base, u64::from(directory.rva))
        .ok_or_else(|| LoadError::Malformed {
            format: PE,
            field: "export directory",
            message: "directory rva not mapped".to_string(),
        })? as usize;
    need(bytes, export_off, 40, "export directory")?;
    let number_of_names = u32_at(bytes, export_off + 24, "export name count")?;
    let address_of_functions = u32_at(bytes, export_off + 28, "export functions rva")?;
    let address_of_names = u32_at(bytes, export_off + 32, "export names rva")?;
    let address_of_ordinals = u32_at(bytes, export_off + 36, "export ordinals rva")?;
    let funcs_off = rva_to_offset_sections(sections, image_base, u64::from(address_of_functions))
        .ok_or_else(|| LoadError::Malformed {
            format: PE,
            field: "export functions",
            message: "functions rva not mapped".to_string(),
        })? as usize;
    let names_off = rva_to_offset_sections(sections, image_base, u64::from(address_of_names))
        .ok_or_else(|| LoadError::Malformed {
            format: PE,
            field: "export names",
            message: "names rva not mapped".to_string(),
        })? as usize;
    let ord_off = rva_to_offset_sections(sections, image_base, u64::from(address_of_ordinals))
        .ok_or_else(|| LoadError::Malformed {
            format: PE,
            field: "export ordinals",
            message: "ordinals rva not mapped".to_string(),
        })? as usize;
    let mut exports = Vec::new();
    for idx in 0..number_of_names as usize {
        let name_rva = u32_at(bytes, names_off + idx * 4, "export name rva")?;
        let ordinal = u16_at(bytes, ord_off + idx * 2, "export ordinal")? as usize;
        let func_rva = u32_at(bytes, funcs_off + ordinal * 4, "export function rva")?;
        exports.push(crate::Export {
            name: read_c_string_rva(bytes, sections, image_base, name_rva)?,
            addr: image_base + u64::from(func_rva),
        });
    }
    Ok(exports)
}

fn parse_base_relocations(
    bytes: &[u8],
    sections: &[Section],
    image_base: u64,
    directory: DataDirectory,
) -> Result<Vec<crate::NormalizedRelocation>> {
    if directory.rva == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    let mut relocations = Vec::new();
    let mut off = rva_to_offset_sections(sections, image_base, u64::from(directory.rva))
        .ok_or_else(|| LoadError::Malformed {
            format: PE,
            field: "base relocation directory",
            message: "directory rva not mapped".to_string(),
        })? as usize;
    let end = off + directory.size as usize;
    while off + 8 <= end {
        let page_rva = u32_at(bytes, off, "relocation page rva")?;
        let block_size = u32_at(bytes, off + 4, "relocation block size")? as usize;
        if page_rva == 0 || block_size < 8 {
            break;
        }
        let entry_count = (block_size - 8) / 2;
        for idx in 0..entry_count {
            let entry = u16_at(bytes, off + 8 + idx * 2, "relocation entry")?;
            let kind = entry >> 12;
            let offset = entry & 0x0fff;
            if kind == 0 {
                continue;
            }
            let kind_name = match kind {
                10 => "DIR64",
                _ => "OTHER",
            };
            relocations.push(normalize_relocation(
                image_base + u64::from(page_rva) + u64::from(offset),
                kind_name,
                None,
                "pe:base_reloc",
            ));
        }
        off += block_size;
    }
    Ok(relocations)
}

fn rva_to_offset_sections(sections: &[Section], image_base: u64, rva: u64) -> Option<u64> {
    let addr = image_base.checked_add(rva)?;
    sections.iter().find_map(|section| {
        let end = section.addr.checked_add(section.size)?;
        if addr >= section.addr && addr < end {
            Some(section.offset + (addr - section.addr))
        } else {
            None
        }
    })
}

fn read_c_string_rva(
    bytes: &[u8],
    sections: &[Section],
    image_base: u64,
    rva: u32,
) -> Result<String> {
    let off = rva_to_offset_sections(sections, image_base, u64::from(rva)).ok_or_else(|| {
        LoadError::Malformed {
            format: PE,
            field: "string rva",
            message: "string rva not mapped".to_string(),
        }
    })? as usize;
    read_c_string(bytes, off)
}

fn read_c_string(bytes: &[u8], offset: usize) -> Result<String> {
    let end = bytes[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|len| offset + len)
        .ok_or_else(|| LoadError::Malformed {
            format: PE,
            field: "string",
            message: "unterminated string".to_string(),
        })?;
    Ok(String::from_utf8_lossy(&bytes[offset..end]).to_string())
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
