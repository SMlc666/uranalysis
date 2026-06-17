use crate::{elf_loader::LoadedElf, model::StringRef};

pub fn extract_strings(loaded: &LoadedElf) -> Vec<StringRef> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < loaded.bytes.len() {
        while start < loaded.bytes.len() && !is_printable(loaded.bytes[start]) {
            start += 1;
        }
        let mut end = start;
        while end < loaded.bytes.len() && is_printable(loaded.bytes[end]) {
            end += 1;
        }
        if end.saturating_sub(start) >= 4 {
            let value = String::from_utf8_lossy(&loaded.bytes[start..end]).to_string();
            let addr = loaded
                .segments
                .iter()
                .find_map(|seg| {
                    let seg_start = seg.file_offset as usize;
                    let seg_end = seg_start.checked_add(seg.file_size as usize)?;
                    if start >= seg_start && start < seg_end {
                        Some(seg.vaddr + (start - seg_start) as u64)
                    } else {
                        None
                    }
                })
                .unwrap_or(start as u64);
            out.push(StringRef {
                addr,
                value,
                encoding: "ascii".to_string(),
            });
        }
        start = end.saturating_add(1);
    }
    out
}

fn is_printable(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e)
}
