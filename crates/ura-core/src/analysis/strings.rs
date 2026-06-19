use crate::{analysis::AnalysisImage, model::StringRef};

pub fn extract_strings(image: &AnalysisImage<'_>) -> Vec<StringRef> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < image.bytes.len() {
        while start < image.bytes.len() && !is_printable(image.bytes[start]) {
            start += 1;
        }
        let mut end = start;
        while end < image.bytes.len() && is_printable(image.bytes[end]) {
            end += 1;
        }
        if end.saturating_sub(start) >= 4 {
            let value = String::from_utf8_lossy(&image.bytes[start..end]).to_string();
            let addr = image
                .ranges
                .iter()
                .find_map(|range| {
                    let range_start = range.file_offset as usize;
                    let range_end = range_start.checked_add(range.file_size as usize)?;
                    if start >= range_start && start < range_end {
                        Some(range.start + (start - range_start) as u64)
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
