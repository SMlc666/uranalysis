use goblin::elf::{header, program_header, Elf};

use crate::{
    model::{Architecture, BinaryFormat, LoadProfile, Section, Segment, Symbol},
    Result, UraError,
};

#[derive(Debug, Clone)]
pub struct LoadedElf {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub profile: LoadProfile,
    pub entry: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub bytes: Vec<u8>,
}

impl LoadedElf {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let elf = Elf::parse(bytes).map_err(|err| UraError::Elf(err.to_string()))?;
        if elf.header.e_ident[header::EI_CLASS] != header::ELFCLASS64 {
            return Err(UraError::Unsupported("expected ELF64".to_string()));
        }
        if elf.header.e_machine != header::EM_AARCH64 {
            return Err(UraError::Unsupported("expected AArch64 ELF".to_string()));
        }
        if !elf.little_endian {
            return Err(UraError::Unsupported(
                "expected little-endian ELF".to_string(),
            ));
        }

        let profile = match elf.header.e_type {
            header::ET_DYN => LoadProfile::SharedObject,
            header::ET_EXEC => LoadProfile::Executable,
            header::ET_REL => LoadProfile::Relocatable,
            _ => LoadProfile::StrippedLike,
        };

        let segments = elf
            .program_headers
            .iter()
            .enumerate()
            .filter(|(_, ph)| ph.p_type == program_header::PT_LOAD)
            .map(|(idx, ph)| Segment {
                id: idx as i64,
                name: format!("LOAD_{idx}"),
                vaddr: ph.p_vaddr,
                file_offset: ph.p_offset,
                file_size: ph.p_filesz,
                mem_size: ph.p_memsz,
                permissions: permissions(ph.p_flags),
            })
            .collect::<Vec<_>>();

        let sections = elf
            .section_headers
            .iter()
            .enumerate()
            .map(|(idx, sh)| Section {
                id: idx as i64,
                name: elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string(),
                addr: sh.sh_addr,
                offset: sh.sh_offset,
                size: sh.sh_size,
                flags: sh.sh_flags,
            })
            .collect::<Vec<_>>();

        let mut symbols = Vec::new();
        for sym in elf.syms.iter() {
            if sym.st_value == 0 {
                continue;
            }
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
            symbols.push(Symbol {
                id: symbols.len() as i64,
                name,
                addr: sym.st_value,
                size: sym.st_size,
                kind: format!("{:?}", sym.st_type()),
                is_import: false,
                is_export: sym.is_function(),
            });
        }
        for sym in elf.dynsyms.iter() {
            let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
            symbols.push(Symbol {
                id: symbols.len() as i64,
                name,
                addr: sym.st_value,
                size: sym.st_size,
                kind: format!("{:?}", sym.st_type()),
                is_import: sym.st_value == 0,
                is_export: sym.st_value != 0,
            });
        }

        Ok(Self {
            format: BinaryFormat::Elf64,
            architecture: Architecture::Aarch64,
            profile,
            entry: elf.entry,
            segments,
            sections,
            symbols,
            bytes: bytes.to_vec(),
        })
    }

    pub fn va_to_offset(&self, addr: u64) -> Option<u64> {
        self.segments.iter().find_map(|seg| {
            let end = seg.vaddr.checked_add(seg.file_size)?;
            if addr >= seg.vaddr && addr < end {
                Some(seg.file_offset + (addr - seg.vaddr))
            } else {
                None
            }
        })
    }

    pub fn executable_ranges(&self) -> Vec<(u64, u64)> {
        self.segments
            .iter()
            .filter(|seg| seg.permissions.contains('x'))
            .map(|seg| (seg.vaddr, seg.vaddr + seg.mem_size))
            .collect()
    }

    pub fn bytes_at(&self, addr: u64, size: usize) -> Option<&[u8]> {
        let offset = self.va_to_offset(addr)? as usize;
        self.bytes.get(offset..offset.checked_add(size)?)
    }
}

fn permissions(flags: u32) -> String {
    let mut out = String::new();
    out.push(if flags & program_header::PF_R != 0 {
        'r'
    } else {
        '-'
    });
    out.push(if flags & program_header::PF_W != 0 {
        'w'
    } else {
        '-'
    });
    out.push(if flags & program_header::PF_X != 0 {
        'x'
    } else {
        '-'
    });
    out
}
