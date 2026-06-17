use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{
    analysis::refresh::AnalysisWindow,
    model::{
        BasicBlock, BasicBlockSource, CfgEdge, CfgEdgeKind, DecodeStatus, FlowKind, Instruction,
    },
    Result, UraError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgOutput {
    pub basic_blocks: Vec<BasicBlock>,
    pub cfg_edges: Vec<CfgEdge>,
}

pub fn build_cfg(
    instructions: &[Instruction],
    roots: &[u64],
    window: AnalysisWindow,
) -> Result<CfgOutput> {
    let by_addr = instructions
        .iter()
        .map(|insn| (insn.addr, insn))
        .collect::<BTreeMap<_, _>>();
    let mut block_starts = roots.iter().copied().collect::<BTreeSet<_>>();
    let mut visited = BTreeSet::new();
    let mut queue = roots.iter().copied().collect::<VecDeque<_>>();
    let mut terminal_by_start = BTreeMap::new();

    while let Some(start) = queue.pop_front() {
        if !visited.insert(start) {
            continue;
        }

        let mut addr = start;
        while let Some(insn) = by_addr.get(&addr).copied() {
            ensure_graph_decodable(insn, window)?;

            if addr != start && block_starts.contains(&addr) {
                break;
            }

            match insn.flow {
                FlowKind::Branch => {
                    enqueue_target(insn.branch_target, &mut block_starts, &mut queue);
                    terminal_by_start.insert(start, insn.addr);
                    break;
                }
                FlowKind::ConditionalBranch => {
                    enqueue_target(insn.branch_target, &mut block_starts, &mut queue);
                    enqueue_target(insn.fallthrough, &mut block_starts, &mut queue);
                    terminal_by_start.insert(start, insn.addr);
                    break;
                }
                FlowKind::Call | FlowKind::IndirectCall => {
                    enqueue_target(insn.branch_target, &mut block_starts, &mut queue);
                    enqueue_target(insn.fallthrough, &mut block_starts, &mut queue);
                    terminal_by_start.insert(start, insn.addr);
                    break;
                }
                FlowKind::Return | FlowKind::IndirectBranch => {
                    terminal_by_start.insert(start, insn.addr);
                    break;
                }
                FlowKind::Fallthrough => {
                    let Some(next) = insn.fallthrough else {
                        terminal_by_start.insert(start, insn.addr);
                        break;
                    };
                    addr = next;
                }
            }
        }
    }

    let mut basic_blocks = Vec::new();
    let mut id_by_start = BTreeMap::new();
    for start in block_starts {
        let Some(first) = by_addr.get(&start).copied() else {
            continue;
        };
        if !visited.contains(&start) {
            continue;
        }
        let terminal_addr = terminal_by_start.get(&start).copied().unwrap_or(first.addr);
        let end = by_addr
            .get(&terminal_addr)
            .map(|insn| insn.addr + u64::from(insn.size.max(1)))
            .unwrap_or_else(|| start + u64::from(first.size.max(1)));
        let instruction_count = instructions
            .iter()
            .filter(|insn| insn.addr >= start && insn.addr < end)
            .count();
        let id = basic_blocks.len() as i64;
        id_by_start.insert(start, id);
        basic_blocks.push(BasicBlock {
            id,
            function_addr: None,
            start,
            end,
            terminal_addr: Some(terminal_addr),
            instruction_count,
            source: if roots.contains(&start) {
                BasicBlockSource::Entry
            } else {
                BasicBlockSource::BranchTarget
            },
        });
    }

    let mut cfg_edges = Vec::new();
    for block in &basic_blocks {
        let Some(terminal_addr) = block.terminal_addr else {
            continue;
        };
        let Some(terminal) = by_addr.get(&terminal_addr).copied() else {
            continue;
        };
        push_edges(block, terminal, &id_by_start, &mut cfg_edges);
    }

    Ok(CfgOutput {
        basic_blocks,
        cfg_edges,
    })
}

fn enqueue_target(
    target: Option<u64>,
    block_starts: &mut BTreeSet<u64>,
    queue: &mut VecDeque<u64>,
) {
    if let Some(target) = target {
        if block_starts.insert(target) {
            queue.push_back(target);
        }
    }
}

fn ensure_graph_decodable(insn: &Instruction, window: AnalysisWindow) -> Result<()> {
    if insn.decode_status == DecodeStatus::Unknown {
        return Err(UraError::Analysis(format!(
            "CFG decode gap at 0x{:x}: bytes={} window=0x{:x}..0x{:x} reason={:?}",
            insn.addr,
            format_bytes(&insn.bytes),
            window.start,
            window.end,
            window.reason
        )));
    }
    if insn.decode_status == DecodeStatus::Partial
        && matches!(
            insn.flow,
            FlowKind::Branch
                | FlowKind::ConditionalBranch
                | FlowKind::Call
                | FlowKind::Return
                | FlowKind::IndirectBranch
                | FlowKind::IndirectCall
        )
    {
        return Err(UraError::Analysis(format!(
            "CFG partial decode gap at 0x{:x}: bytes={} window=0x{:x}..0x{:x} reason={:?}",
            insn.addr,
            format_bytes(&insn.bytes),
            window.start,
            window.end,
            window.reason
        )));
    }
    Ok(())
}

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn push_edges(
    block: &BasicBlock,
    terminal: &Instruction,
    id_by_start: &BTreeMap<u64, i64>,
    out: &mut Vec<CfgEdge>,
) {
    match terminal.flow {
        FlowKind::Branch => push_edge(
            block,
            terminal,
            terminal.branch_target,
            CfgEdgeKind::Branch,
            id_by_start,
            out,
        ),
        FlowKind::ConditionalBranch => {
            push_edge(
                block,
                terminal,
                terminal.branch_target,
                CfgEdgeKind::ConditionalTrue,
                id_by_start,
                out,
            );
            push_edge(
                block,
                terminal,
                terminal.fallthrough,
                CfgEdgeKind::ConditionalFalse,
                id_by_start,
                out,
            );
        }
        FlowKind::Call => {
            push_edge(
                block,
                terminal,
                terminal.branch_target,
                CfgEdgeKind::Call,
                id_by_start,
                out,
            );
            push_edge(
                block,
                terminal,
                terminal.fallthrough,
                CfgEdgeKind::Fallthrough,
                id_by_start,
                out,
            );
        }
        FlowKind::IndirectCall => {
            out.push(CfgEdge {
                from_block: block.id,
                to_block: None,
                from_addr: terminal.addr,
                to_addr: None,
                kind: CfgEdgeKind::Indirect,
            });
            push_edge(
                block,
                terminal,
                terminal.fallthrough,
                CfgEdgeKind::Fallthrough,
                id_by_start,
                out,
            );
        }
        FlowKind::Return => out.push(CfgEdge {
            from_block: block.id,
            to_block: None,
            from_addr: terminal.addr,
            to_addr: None,
            kind: CfgEdgeKind::Return,
        }),
        FlowKind::IndirectBranch => out.push(CfgEdge {
            from_block: block.id,
            to_block: None,
            from_addr: terminal.addr,
            to_addr: None,
            kind: CfgEdgeKind::Indirect,
        }),
        FlowKind::Fallthrough => push_edge(
            block,
            terminal,
            terminal.fallthrough,
            CfgEdgeKind::Fallthrough,
            id_by_start,
            out,
        ),
    }
}

fn push_edge(
    block: &BasicBlock,
    terminal: &Instruction,
    target: Option<u64>,
    kind: CfgEdgeKind,
    id_by_start: &BTreeMap<u64, i64>,
    out: &mut Vec<CfgEdge>,
) {
    out.push(CfgEdge {
        from_block: block.id,
        to_block: target.and_then(|addr| id_by_start.get(&addr).copied()),
        from_addr: terminal.addr,
        to_addr: target,
        kind,
    });
}
