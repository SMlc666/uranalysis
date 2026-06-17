use capstone::{arch::arm64::ArchMode, prelude::*};

use crate::{elf_loader::LoadedElf, model::Instruction, Result, UraError};

pub fn linear_disassemble(loaded: &LoadedElf) -> Result<Vec<Instruction>> {
    let cs = Capstone::new()
        .arm64()
        .mode(ArchMode::Arm)
        .build()
        .map_err(|err| UraError::Analysis(err.to_string()))?;
    let mut out = Vec::new();
    for (start, end) in loaded.executable_ranges() {
        let size = (end - start) as usize;
        let Some(bytes) = loaded.bytes_at(start, size) else {
            continue;
        };
        for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
            let addr = start + (idx as u64 * 4);
            let insns = cs
                .disasm_count(chunk, addr, 1)
                .map_err(|err| UraError::Analysis(err.to_string()))?;
            let Some(insn) = insns.iter().next() else {
                continue;
            };
            let addr = insn.address();
            let size = insn.bytes().len() as u8;
            let mnemonic = insn.mnemonic().unwrap_or("").to_string();
            let operands = insn.op_str().unwrap_or("").to_string();
            let fallthrough = if is_terminal(&mnemonic) {
                None
            } else {
                Some(addr + u64::from(size))
            };
            out.push(Instruction {
                addr,
                size,
                bytes: insn.bytes().to_vec(),
                mnemonic,
                operands: operands.clone(),
                fallthrough,
                branch_target: parse_branch_target(&operands),
                function_addr: None,
            });
        }
    }
    Ok(out)
}

fn is_terminal(mnemonic: &str) -> bool {
    matches!(mnemonic, "ret" | "br" | "blr" | "b")
}

fn parse_branch_target(operands: &str) -> Option<u64> {
    let trimmed = operands.trim().strip_prefix('#').unwrap_or(operands.trim());
    u64::from_str_radix(trimmed.strip_prefix("0x")?, 16).ok()
}
