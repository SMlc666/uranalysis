use std::collections::{HashMap, HashSet};

use crate::model::{FlowKind, Instruction, InstructionKind, StringRef, Xref, XrefKind};

pub fn build_xrefs(instructions: &[Instruction], strings: &[StringRef]) -> Vec<Xref> {
    let mut out = Vec::new();
    let strings_by_operand = strings_by_operand(strings);
    for insn in instructions {
        if let Some(target) = insn.branch_target {
            let kind = if matches!(insn.flow, FlowKind::Call | FlowKind::IndirectCall)
                || insn.kind == InstructionKind::Call
            {
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

        let mut matched_strings = HashSet::new();
        for token in hex_address_tokens(&insn.operands) {
            let Some(addresses) = strings_by_operand.get(&token) else {
                continue;
            };
            for addr in addresses {
                if !matched_strings.insert(*addr) {
                    continue;
                }
                out.push(Xref {
                    from_addr: insn.addr,
                    to_addr: *addr,
                    kind: XrefKind::String,
                });
            }
        }
    }
    out
}

fn strings_by_operand(strings: &[StringRef]) -> HashMap<String, Vec<u64>> {
    let mut out = HashMap::with_capacity(strings.len());
    for s in strings {
        out.entry(format!("0x{:x}", s.addr))
            .or_insert_with(Vec::new)
            .push(s.addr);
    }
    out
}

fn hex_address_tokens(operands: &str) -> impl Iterator<Item = String> + '_ {
    operands
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == 'x' || ch == 'X'))
        .filter(|token| token.starts_with("0x") || token.starts_with("0X"))
        .map(str::to_ascii_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DecodeStatus;

    #[test]
    fn string_xrefs_match_whole_hex_operands() {
        let instructions = vec![instruction("mov x0, #0x10")];
        let strings = vec![string_ref(0x1), string_ref(0x10)];

        let xrefs = build_xrefs(&instructions, &strings);

        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].to_addr, 0x10);
        assert_eq!(xrefs[0].kind, XrefKind::String);
    }

    fn instruction(operands: &str) -> Instruction {
        Instruction {
            addr: 0x4000,
            size: 4,
            bytes: vec![0],
            mnemonic: "mov".to_string(),
            operands: operands.to_string(),
            text: operands.to_string(),
            kind: InstructionKind::Move,
            flow: FlowKind::Fallthrough,
            fallthrough: Some(0x4004),
            branch_target: None,
            decode_status: DecodeStatus::Complete,
            decoder: "test".to_string(),
            decoder_version: "test".to_string(),
            function_addr: None,
        }
    }

    fn string_ref(addr: u64) -> StringRef {
        StringRef {
            addr,
            value: "test".to_string(),
            encoding: "ascii".to_string(),
        }
    }
}
