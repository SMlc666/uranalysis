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
        instruction(InstructionSpec {
            addr: 0x400080,
            size: 4,
            text: "b.eq 0x400088",
            kind: InstructionKind::Branch,
            flow: FlowKind::ConditionalBranch,
            fallthrough: Some(0x400084),
            branch_target: Some(0x400088),
            decode_status: DecodeStatus::Complete,
        }),
        instruction(InstructionSpec {
            addr: 0x400084,
            size: 4,
            text: "ret",
            kind: InstructionKind::Return,
            flow: FlowKind::Return,
            fallthrough: None,
            branch_target: None,
            decode_status: DecodeStatus::Complete,
        }),
        instruction(InstructionSpec {
            addr: 0x400088,
            size: 4,
            text: "ret",
            kind: InstructionKind::Return,
            flow: FlowKind::Return,
            fallthrough: None,
            branch_target: None,
            decode_status: DecodeStatus::Complete,
        }),
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
        instruction(InstructionSpec {
            addr: 0x401000,
            size: 5,
            text: "call 0x401010",
            kind: InstructionKind::Call,
            flow: FlowKind::Call,
            fallthrough: Some(0x401005),
            branch_target: Some(0x401010),
            decode_status: DecodeStatus::Complete,
        }),
        instruction(InstructionSpec {
            addr: 0x401005,
            size: 1,
            text: "ret",
            kind: InstructionKind::Return,
            flow: FlowKind::Return,
            fallthrough: None,
            branch_target: None,
            decode_status: DecodeStatus::Complete,
        }),
        instruction(InstructionSpec {
            addr: 0x401010,
            size: 1,
            text: "ret",
            kind: InstructionKind::Return,
            flow: FlowKind::Return,
            fallthrough: None,
            branch_target: None,
            decode_status: DecodeStatus::Complete,
        }),
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
        instruction(InstructionSpec {
            addr: 0x400080,
            size: 4,
            text: "ret",
            kind: InstructionKind::Return,
            flow: FlowKind::Return,
            fallthrough: None,
            branch_target: None,
            decode_status: DecodeStatus::Complete,
        }),
        instruction(InstructionSpec {
            addr: 0x400084,
            size: 4,
            text: ".word 0xffffffff",
            kind: InstructionKind::Unknown,
            flow: FlowKind::Fallthrough,
            fallthrough: Some(0x400088),
            branch_target: None,
            decode_status: DecodeStatus::Unknown,
        }),
    ];

    let cfg = build_cfg(&instructions, &[0x400080], window(0x400080, 0x400088))?;

    assert_eq!(cfg.basic_blocks.len(), 1);
    Ok(())
}

#[test]
fn reachable_unknown_instruction_fails_cfg_with_address_and_bytes() {
    let mut unknown = instruction(InstructionSpec {
        addr: 0x400080,
        size: 4,
        text: ".word 0xffffffff",
        kind: InstructionKind::Unknown,
        flow: FlowKind::Fallthrough,
        fallthrough: Some(0x400084),
        branch_target: None,
        decode_status: DecodeStatus::Unknown,
    });
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

struct InstructionSpec<'a> {
    addr: u64,
    size: u8,
    text: &'a str,
    kind: InstructionKind,
    flow: FlowKind,
    fallthrough: Option<u64>,
    branch_target: Option<u64>,
    decode_status: DecodeStatus,
}

fn instruction(spec: InstructionSpec<'_>) -> Instruction {
    let mnemonic = spec
        .text
        .split_whitespace()
        .next()
        .unwrap_or(spec.text)
        .to_string();
    Instruction {
        addr: spec.addr,
        size: spec.size,
        bytes: vec![0; usize::from(spec.size)],
        mnemonic,
        operands: spec
            .text
            .split_once(' ')
            .map(|(_, operands)| operands.to_string())
            .unwrap_or_default(),
        text: spec.text.to_string(),
        kind: spec.kind,
        flow: spec.flow,
        fallthrough: spec.fallthrough,
        branch_target: spec.branch_target,
        decode_status: spec.decode_status,
        decoder: "test".to_string(),
        decoder_version: "test".to_string(),
        function_addr: None,
    }
}
