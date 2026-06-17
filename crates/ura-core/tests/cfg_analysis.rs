use ura_core::{
    analysis::{
        cfg::build_cfg,
        refresh::{AnalysisWindow, RefreshReason},
    },
    model::{CfgEdgeKind, DecodeStatus, FlowKind, Instruction, InstructionKind},
    Result,
};

#[test]
fn aarch64_conditional_branch_creates_true_and_false_edges() -> Result<()> {
    let instructions = vec![
        instruction(
            0x400080,
            4,
            "b.eq 0x400088",
            InstructionKind::Branch,
            FlowKind::ConditionalBranch,
            Some(0x400084),
            Some(0x400088),
            DecodeStatus::Complete,
        ),
        instruction(
            0x400084,
            4,
            "ret",
            InstructionKind::Return,
            FlowKind::Return,
            None,
            None,
            DecodeStatus::Complete,
        ),
        instruction(
            0x400088,
            4,
            "ret",
            InstructionKind::Return,
            FlowKind::Return,
            None,
            None,
            DecodeStatus::Complete,
        ),
    ];

    let cfg = build_cfg(&instructions, &[0x400080], window(0x400080, 0x40008c))?;

    assert_eq!(cfg.basic_blocks.len(), 3);
    assert!(cfg.cfg_edges.iter().any(|edge| {
        edge.kind == CfgEdgeKind::ConditionalTrue && edge.to_addr == Some(0x400088)
    }));
    assert!(cfg.cfg_edges.iter().any(|edge| {
        edge.kind == CfgEdgeKind::ConditionalFalse && edge.to_addr == Some(0x400084)
    }));
    Ok(())
}

#[test]
fn x86_64_call_creates_call_and_fallthrough_edges() -> Result<()> {
    let instructions = vec![
        instruction(
            0x401000,
            5,
            "call 0x401010",
            InstructionKind::Call,
            FlowKind::Call,
            Some(0x401005),
            Some(0x401010),
            DecodeStatus::Complete,
        ),
        instruction(
            0x401005,
            1,
            "ret",
            InstructionKind::Return,
            FlowKind::Return,
            None,
            None,
            DecodeStatus::Complete,
        ),
        instruction(
            0x401010,
            1,
            "ret",
            InstructionKind::Return,
            FlowKind::Return,
            None,
            None,
            DecodeStatus::Complete,
        ),
    ];

    let cfg = build_cfg(&instructions, &[0x401000], window(0x401000, 0x401011))?;

    assert!(cfg
        .cfg_edges
        .iter()
        .any(|edge| edge.kind == CfgEdgeKind::Call && edge.to_addr == Some(0x401010)));
    assert!(cfg
        .cfg_edges
        .iter()
        .any(|edge| edge.kind == CfgEdgeKind::Fallthrough && edge.to_addr == Some(0x401005)));
    Ok(())
}

#[test]
fn unreachable_unknown_instruction_does_not_fail_cfg() -> Result<()> {
    let instructions = vec![
        instruction(
            0x400080,
            4,
            "ret",
            InstructionKind::Return,
            FlowKind::Return,
            None,
            None,
            DecodeStatus::Complete,
        ),
        instruction(
            0x400084,
            4,
            ".word 0xffffffff",
            InstructionKind::Unknown,
            FlowKind::Fallthrough,
            Some(0x400088),
            None,
            DecodeStatus::Unknown,
        ),
    ];

    let cfg = build_cfg(&instructions, &[0x400080], window(0x400080, 0x400088))?;

    assert_eq!(cfg.basic_blocks.len(), 1);
    Ok(())
}

#[test]
fn reachable_unknown_instruction_fails_cfg_with_address_and_bytes() {
    let mut unknown = instruction(
        0x400080,
        4,
        ".word 0xffffffff",
        InstructionKind::Unknown,
        FlowKind::Fallthrough,
        Some(0x400084),
        None,
        DecodeStatus::Unknown,
    );
    unknown.bytes = vec![0xff, 0xff, 0xff, 0xff];

    let err = build_cfg(&[unknown], &[0x400080], window(0x400080, 0x400084))
        .unwrap_err()
        .to_string();

    assert!(err.contains("CFG decode gap"), "{err}");
    assert!(err.contains("0x400080"), "{err}");
    assert!(err.contains("ff ff ff ff"), "{err}");
}

fn window(start: u64, end: u64) -> AnalysisWindow {
    AnalysisWindow {
        start,
        end,
        reason: RefreshReason::ManualFunctionRangeChanged {
            addr: start,
            start,
            end,
        },
    }
}

fn instruction(
    addr: u64,
    size: u8,
    text: &str,
    kind: InstructionKind,
    flow: FlowKind,
    fallthrough: Option<u64>,
    branch_target: Option<u64>,
    decode_status: DecodeStatus,
) -> Instruction {
    let mnemonic = text.split_whitespace().next().unwrap_or(text).to_string();
    Instruction {
        addr,
        size,
        bytes: vec![0; usize::from(size)],
        mnemonic,
        operands: text
            .split_once(' ')
            .map(|(_, operands)| operands.to_string())
            .unwrap_or_default(),
        text: text.to_string(),
        kind,
        flow,
        fallthrough,
        branch_target,
        decode_status,
        decoder: "test".to_string(),
        decoder_version: "test".to_string(),
        function_addr: None,
    }
}
