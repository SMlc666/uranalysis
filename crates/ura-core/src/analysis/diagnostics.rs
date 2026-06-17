use crate::model::{Diagnostic, Instruction};

pub fn collect_diagnostics(instructions: &[Instruction]) -> Vec<Diagnostic> {
    instructions
        .iter()
        .filter(|insn| insn.mnemonic.is_empty())
        .map(|insn| Diagnostic {
            addr: Some(insn.addr),
            severity: "warning".to_string(),
            message: "instruction decoded without mnemonic".to_string(),
        })
        .collect()
}
