use crate::{analysis::AnalysisImage, model::Instruction, Result, UraError};

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
            let kind = format!("{:?}", decoded.kind);
            let flow = format!("{:?}", decoded.flow);
            let decode_status = format!("{:?}", decoded.status);
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
                kind,
                flow,
                fallthrough,
                branch_target: decoded.branch_target,
                decode_status,
                decoder: "urdisassembly/aarch64".to_string(),
                decoder_version: env!("CARGO_PKG_VERSION").to_string(),
                function_addr: None,
            });
        }
    }
    Ok(out)
}
