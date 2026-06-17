use crate::{
    analysis::AnalysisImage,
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind},
    Result, UraError,
};

pub fn linear_disassemble(image: &AnalysisImage<'_>) -> Result<Vec<Instruction>> {
    let decoder = urdisassembly::Decoder::new(
        urdisassembly::Architecture::Aarch64,
        urdisassembly::DecodeOptions::default(),
    )
    .map_err(|err| UraError::Analysis(err.to_string()))?;

    let mut out = Vec::new();
    for (start, end) in image.executable_ranges() {
        let size = (end - start) as usize;
        let Some(bytes) = image.bytes_at(start, size) else {
            continue;
        };
        for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
            let addr = start + (idx as u64 * 4);
            let decoded = decoder
                .decode_one(chunk, addr)
                .map_err(|err| UraError::Analysis(err.to_string()))?;
            let operands = decoded.operand_text();
            let fallthrough = match decoded.flow {
                urdisassembly::FlowKind::Branch
                | urdisassembly::FlowKind::Return
                | urdisassembly::FlowKind::IndirectBranch => None,
                _ => Some(addr + u64::from(decoded.size)),
            };
            out.push(Instruction {
                addr: decoded.address,
                size: decoded.size,
                bytes: decoded.bytes,
                mnemonic: decoded.mnemonic,
                operands,
                text: decoded.text,
                kind: convert_kind(decoded.kind),
                flow: convert_flow(decoded.flow),
                fallthrough,
                branch_target: decoded.branch_target,
                decode_status: convert_status(decoded.status),
                decoder: "urdisassembly/aarch64".to_string(),
                decoder_version: env!("CARGO_PKG_VERSION").to_string(),
                function_addr: None,
            });
        }
    }
    Ok(out)
}

fn convert_kind(kind: urdisassembly::InstructionKind) -> InstructionKind {
    match kind {
        urdisassembly::InstructionKind::Branch => InstructionKind::Branch,
        urdisassembly::InstructionKind::Call => InstructionKind::Call,
        urdisassembly::InstructionKind::Return => InstructionKind::Return,
        urdisassembly::InstructionKind::Compare => InstructionKind::Compare,
        urdisassembly::InstructionKind::Load => InstructionKind::Load,
        urdisassembly::InstructionKind::Store => InstructionKind::Store,
        urdisassembly::InstructionKind::Address => InstructionKind::Address,
        urdisassembly::InstructionKind::Arithmetic => InstructionKind::Arithmetic,
        urdisassembly::InstructionKind::Logical => InstructionKind::Logical,
        urdisassembly::InstructionKind::Move => InstructionKind::Move,
        urdisassembly::InstructionKind::System => InstructionKind::System,
        urdisassembly::InstructionKind::Unknown => InstructionKind::Unknown,
    }
}

fn convert_flow(flow: urdisassembly::FlowKind) -> FlowKind {
    match flow {
        urdisassembly::FlowKind::Fallthrough => FlowKind::Fallthrough,
        urdisassembly::FlowKind::Branch => FlowKind::Branch,
        urdisassembly::FlowKind::ConditionalBranch => FlowKind::ConditionalBranch,
        urdisassembly::FlowKind::Call => FlowKind::Call,
        urdisassembly::FlowKind::Return => FlowKind::Return,
        urdisassembly::FlowKind::IndirectBranch => FlowKind::IndirectBranch,
        urdisassembly::FlowKind::IndirectCall => FlowKind::IndirectCall,
    }
}

fn convert_status(status: urdisassembly::DecodeStatus) -> DecodeStatus {
    match status {
        urdisassembly::DecodeStatus::Complete => DecodeStatus::Complete,
        urdisassembly::DecodeStatus::Partial => DecodeStatus::Partial,
        urdisassembly::DecodeStatus::Unknown => DecodeStatus::Unknown,
    }
}
