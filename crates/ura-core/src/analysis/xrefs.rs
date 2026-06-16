use crate::model::{Instruction, StringRef, Xref, XrefKind};

pub fn build_xrefs(instructions: &[Instruction], strings: &[StringRef]) -> Vec<Xref> {
    let mut out = Vec::new();
    for insn in instructions {
        if let Some(target) = insn.branch_target {
            let kind = if insn.mnemonic == "bl" {
                XrefKind::Call
            } else {
                XrefKind::Code
            };
            out.push(Xref {
                from_addr: insn.addr,
                to_addr: target,
                kind,
            });
        }
        for s in strings {
            if insn.operands.contains(&format!("0x{:x}", s.addr)) {
                out.push(Xref {
                    from_addr: insn.addr,
                    to_addr: s.addr,
                    kind: XrefKind::String,
                });
            }
        }
    }
    out
}
