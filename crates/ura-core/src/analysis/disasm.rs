use crate::{
    analysis::AnalysisImage,
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind},
    Result, UraError,
};

pub fn linear_disassemble(image: &AnalysisImage<'_>) -> Result<Vec<Instruction>> {
    linear_disassemble_with_limit(image, None)
}

pub fn linear_disassemble_with_limit(
    image: &AnalysisImage<'_>,
    max_instructions: Option<usize>,
) -> Result<Vec<Instruction>> {
    match image.target.architecture {
        crate::model::Architecture::Aarch64 => disassemble_aarch64(image, max_instructions),
        crate::model::Architecture::X86_64 => disassemble_x86_64(image, max_instructions),
    }
}

fn disassemble_aarch64(
    image: &AnalysisImage<'_>,
    max_instructions: Option<usize>,
) -> Result<Vec<Instruction>> {
    let decoder = urcodec::Decoder::new(
        urcodec::Architecture::Aarch64,
        urcodec::DecodeOptions::default(),
    )
    .map_err(|err| UraError::Analysis(err.to_string()))?;

    let mut out = Vec::new();
    if reached_instruction_limit(&out, max_instructions) {
        return Ok(out);
    }
    for (start, end) in executable_ranges_for_analysis(image, max_instructions) {
        let size = (end - start) as usize;
        let Some(bytes) = image.bytes_at(start, size) else {
            continue;
        };
        for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
            let addr = start + (idx as u64 * 4);
            let decoded = decoder
                .decode_one(chunk, addr)
                .map_err(|err| UraError::Analysis(err.to_string()))?;
            out.push(convert_instruction(decoded, "urcodec/aarch64"));
            if reached_instruction_limit(&out, max_instructions) {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

fn disassemble_x86_64(
    image: &AnalysisImage<'_>,
    max_instructions: Option<usize>,
) -> Result<Vec<Instruction>> {
    let decoder = urcodec::Decoder::new(
        urcodec::Architecture::X86_64,
        urcodec::DecodeOptions::default(),
    )
    .map_err(|err| UraError::Analysis(err.to_string()))?;

    let mut out = Vec::new();
    if reached_instruction_limit(&out, max_instructions) {
        return Ok(out);
    }
    for (start, end) in executable_ranges_for_analysis(image, max_instructions) {
        let mut addr = start;
        while addr < end {
            let remaining = (end - addr).min(15) as usize;
            if remaining == 0 {
                break;
            }
            let Some(bytes) = image.bytes_at(addr, remaining) else {
                break;
            };
            match decoder.decode_one(bytes, addr) {
                Ok(decoded) => {
                    let size = u64::from(decoded.size.max(1));
                    out.push(convert_instruction(decoded, "urcodec/x86_64"));
                    addr = addr.saturating_add(size);
                    if reached_instruction_limit(&out, max_instructions) {
                        return Ok(out);
                    }
                }
                Err(_) => {
                    out.push(unknown_byte_instruction(addr, bytes[0]));
                    addr = addr.saturating_add(1);
                    if reached_instruction_limit(&out, max_instructions) {
                        return Ok(out);
                    }
                }
            }
        }
    }
    Ok(out)
}

fn executable_ranges_for_analysis(
    image: &AnalysisImage<'_>,
    max_instructions: Option<usize>,
) -> Vec<(u64, u64)> {
    let ranges = image.executable_ranges();
    if max_instructions.is_none() {
        return ranges;
    }
    let mut prioritized = Vec::new();
    for (start, end) in &ranges {
        if image.entry >= *start && image.entry < *end {
            prioritized.push((image.entry, *end));
        }
    }
    prioritized.extend(
        ranges
            .into_iter()
            .filter(|(start, end)| !(image.entry >= *start && image.entry < *end)),
    );
    prioritized
}

fn reached_instruction_limit(out: &[Instruction], max_instructions: Option<usize>) -> bool {
    max_instructions.is_some_and(|limit| out.len() >= limit)
}

fn convert_instruction(decoded: urcodec::Instruction, decoder: &str) -> Instruction {
    let operands = decoded.operand_text();
    let fallthrough = match decoded.flow {
        urcodec::FlowKind::Branch
        | urcodec::FlowKind::Return
        | urcodec::FlowKind::IndirectBranch => None,
        _ => Some(decoded.address + u64::from(decoded.size)),
    };
    Instruction {
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
        decoder: decoder.to_string(),
        decoder_version: env!("CARGO_PKG_VERSION").to_string(),
        function_addr: None,
    }
}

fn unknown_byte_instruction(addr: u64, byte: u8) -> Instruction {
    Instruction {
        addr,
        size: 1,
        bytes: vec![byte],
        mnemonic: ".byte".to_string(),
        operands: format!("0x{byte:02x}"),
        text: format!(".byte 0x{byte:02x}"),
        kind: InstructionKind::Unknown,
        flow: FlowKind::Fallthrough,
        fallthrough: Some(addr + 1),
        branch_target: None,
        decode_status: DecodeStatus::Unknown,
        decoder: "urcodec/x86_64".to_string(),
        decoder_version: env!("CARGO_PKG_VERSION").to_string(),
        function_addr: None,
    }
}

fn convert_kind(kind: urcodec::InstructionKind) -> InstructionKind {
    match kind {
        urcodec::InstructionKind::Branch => InstructionKind::Branch,
        urcodec::InstructionKind::Call => InstructionKind::Call,
        urcodec::InstructionKind::Return => InstructionKind::Return,
        urcodec::InstructionKind::Compare => InstructionKind::Compare,
        urcodec::InstructionKind::Load => InstructionKind::Load,
        urcodec::InstructionKind::Store => InstructionKind::Store,
        urcodec::InstructionKind::Address => InstructionKind::Address,
        urcodec::InstructionKind::Arithmetic => InstructionKind::Arithmetic,
        urcodec::InstructionKind::Logical => InstructionKind::Logical,
        urcodec::InstructionKind::Move => InstructionKind::Move,
        urcodec::InstructionKind::System => InstructionKind::System,
        urcodec::InstructionKind::Unknown => InstructionKind::Unknown,
    }
}

fn convert_flow(flow: urcodec::FlowKind) -> FlowKind {
    match flow {
        urcodec::FlowKind::Fallthrough => FlowKind::Fallthrough,
        urcodec::FlowKind::Branch => FlowKind::Branch,
        urcodec::FlowKind::ConditionalBranch => FlowKind::ConditionalBranch,
        urcodec::FlowKind::Call => FlowKind::Call,
        urcodec::FlowKind::Return => FlowKind::Return,
        urcodec::FlowKind::IndirectBranch => FlowKind::IndirectBranch,
        urcodec::FlowKind::IndirectCall => FlowKind::IndirectCall,
    }
}

fn convert_status(status: urcodec::DecodeStatus) -> DecodeStatus {
    match status {
        urcodec::DecodeStatus::Complete => DecodeStatus::Complete,
        urcodec::DecodeStatus::Partial => DecodeStatus::Partial,
        urcodec::DecodeStatus::Unknown => DecodeStatus::Unknown,
    }
}
