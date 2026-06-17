use crate::model::{
    CfgEdge, CfgEdgeKind, DecodeStatus, Diagnostic, Function, FunctionSource, Instruction,
};

pub fn collect_diagnostics(instructions: &[Instruction]) -> Vec<Diagnostic> {
    instructions
        .iter()
        .filter(|insn| insn.decode_status == DecodeStatus::Unknown || insn.mnemonic.is_empty())
        .map(|insn| Diagnostic {
            addr: Some(insn.addr),
            severity: "warning".to_string(),
            message: if insn.decode_status == DecodeStatus::Unknown {
                "unknown instruction".to_string()
            } else {
                "instruction decoded without mnemonic".to_string()
            },
        })
        .collect()
}

pub fn collect_graph_diagnostics(cfg_edges: &[CfgEdge]) -> Vec<Diagnostic> {
    cfg_edges
        .iter()
        .filter(|edge| edge.kind == CfgEdgeKind::Indirect)
        .map(|edge| Diagnostic {
            addr: Some(edge.from_addr),
            severity: "warning".to_string(),
            message: "unresolved indirect control flow".to_string(),
        })
        .collect()
}

pub fn collect_user_function_diagnostics(
    functions: &[Function],
    instructions: &[Instruction],
) -> Vec<Diagnostic> {
    functions
        .iter()
        .filter(|func| func.source == FunctionSource::User)
        .filter(|func| !instructions.iter().any(|insn| insn.addr == func.addr))
        .map(|func| Diagnostic {
            addr: Some(func.addr),
            severity: "warning".to_string(),
            message: "manual function root is not in disassembly".to_string(),
        })
        .collect()
}
