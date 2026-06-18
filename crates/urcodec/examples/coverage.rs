use std::{
    collections::BTreeMap,
    env, fs, io,
    path::{Path, PathBuf},
};

use goblin::{elf::program_header, Object};
use urcodec::{Architecture, DecodeOptions, DecodeStatus, Decoder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = env::args().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: cargo run -p urcodec --example coverage -- <file-or-directory>",
        )
    })?;
    let mut files = Vec::new();
    collect_files(Path::new(&root), &mut files)?;

    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default())?;
    let mut decoded = 0u64;
    let mut unknown = 0u64;
    let mut clusters: BTreeMap<u32, Vec<(u64, u32)>> = BTreeMap::new();

    for path in files {
        let bytes = fs::read(&path)?;
        let Ok(Object::Elf(elf)) = Object::parse(&bytes) else {
            continue;
        };
        if elf.header.e_machine != goblin::elf::header::EM_AARCH64 {
            continue;
        }
        for ph in elf.program_headers.iter().filter(|ph| {
            ph.p_type == program_header::PT_LOAD
                && ph.p_flags & program_header::PF_X != 0
                && ph.p_filesz > 0
        }) {
            let start = ph.p_offset as usize;
            let end = start.saturating_add(ph.p_filesz as usize).min(bytes.len());
            for (idx, chunk) in bytes[start..end].chunks_exact(4).enumerate() {
                let addr = ph.p_vaddr + (idx as u64 * 4);
                let insn = decoder.decode_one(chunk, addr)?;
                decoded += 1;
                if insn.status == DecodeStatus::Unknown {
                    unknown += 1;
                    let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let key = word & 0x1fe0_0000;
                    clusters.entry(key).or_default().push((addr, word));
                }
            }
        }
    }

    let unknown_rate = if decoded == 0 {
        0.0
    } else {
        (unknown as f64 / decoded as f64) * 100.0
    };
    println!("decoded: {decoded}");
    println!("unknown: {unknown}");
    println!("unknown_rate: {unknown_rate:.2}%");
    println!();
    println!("top_unknown_patterns:");

    let mut ranked = clusters.into_iter().collect::<Vec<_>>();
    ranked.sort_by_key(|(_, examples)| std::cmp::Reverse(examples.len()));
    for (key, examples) in ranked.into_iter().take(10) {
        let rendered = examples
            .iter()
            .take(3)
            .map(|(addr, word)| format!("0x{addr:x}:0x{word:08x}"))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "  key=0x{key:08x} count={} examples={rendered}",
            examples.len()
        );
    }

    Ok(())
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}
