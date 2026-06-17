use crate::model::{Diagnostic, Instruction};

pub fn collect_diagnostics(instructions: &[Instruction]) -> Vec<Diagnostic> {
    instructions
        .iter()
        .filter(|insn| insn.decode_status == "Unknown" || insn.mnemonic.is_empty())
        .map(|insn| Diagnostic {
            addr: Some(insn.addr),
            severity: "warning".to_string(),
            message: if insn.decode_status == "Unknown" {
                "unknown instruction".to_string()
            } else {
                "instruction decoded without mnemonic".to_string()
            },
        })
        .collect()
}
