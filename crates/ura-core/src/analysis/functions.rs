use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::model::{
    BasicBlock, CfgEdge, CfgEdgeKind, FlowKind, Function, FunctionSource, Instruction, UserFacts,
};

pub fn manual_functions_from_facts(user_facts: &UserFacts) -> Vec<Function> {
    let mut out = Vec::new();
    for addr in &user_facts.manual_function_roots {
        let (start, end) = user_facts
            .manual_function_ranges
            .get(addr)
            .copied()
            .unwrap_or((*addr, addr + 4));
        let name = user_facts
            .renames
            .get(addr)
            .cloned()
            .unwrap_or_else(|| format!("sub_{addr:x}"));
        out.push(Function {
            addr: *addr,
            name,
            start,
            end,
            source: FunctionSource::User,
        });
    }
    out.sort_by_key(|func| func.addr);
    out
}

pub fn discover_functions(
    entry: u64,
    instructions: &[Instruction],
    basic_blocks: &[BasicBlock],
    cfg_edges: &[CfgEdge],
    user_functions: &[Function],
) -> Vec<Function> {
    let mut roots = BTreeMap::new();
    roots.insert(entry, FunctionSource::Entry);

    for edge in cfg_edges {
        if edge.kind == CfgEdgeKind::Call {
            if let Some(target) = edge.to_addr {
                roots.entry(target).or_insert(FunctionSource::BranchTarget);
            }
        }
    }

    for user in user_functions {
        roots.insert(user.addr, FunctionSource::User);
    }

    let block_by_start = basic_blocks
        .iter()
        .map(|block| (block.start, block))
        .collect::<BTreeMap<_, _>>();
    let block_by_id = basic_blocks
        .iter()
        .map(|block| (block.id, block))
        .collect::<BTreeMap<_, _>>();
    let edges_by_block = edges_by_block(cfg_edges);
    let known_roots = roots.keys().copied().collect::<BTreeSet<_>>();

    let mut functions = Vec::new();
    for (root, source) in roots {
        if source == FunctionSource::User {
            continue;
        }
        let owned_blocks = reachable_function_blocks(
            root,
            &block_by_start,
            &block_by_id,
            &edges_by_block,
            &known_roots,
        );
        let end = owned_blocks
            .iter()
            .filter_map(|id| block_by_id.get(id).map(|block| block.end))
            .max()
            .unwrap_or_else(|| fallback_function_end(root, instructions));
        functions.push(Function {
            addr: root,
            name: format!("sub_{root:x}"),
            start: root,
            end,
            source,
        });
    }

    for user in user_functions {
        functions.retain(|func| func.addr != user.addr);
        functions.push(user.clone());
    }

    functions.sort_by_key(|func| func.addr);
    functions
}

fn edges_by_block(cfg_edges: &[CfgEdge]) -> BTreeMap<i64, Vec<&CfgEdge>> {
    let mut out = BTreeMap::<i64, Vec<&CfgEdge>>::new();
    for edge in cfg_edges {
        out.entry(edge.from_block).or_default().push(edge);
    }
    out
}

fn reachable_function_blocks(
    root: u64,
    block_by_start: &BTreeMap<u64, &BasicBlock>,
    block_by_id: &BTreeMap<i64, &BasicBlock>,
    edges_by_block: &BTreeMap<i64, Vec<&CfgEdge>>,
    known_roots: &BTreeSet<u64>,
) -> BTreeSet<i64> {
    let mut out = BTreeSet::new();
    let Some(root_block) = block_by_start.get(&root) else {
        return out;
    };

    let mut queue = VecDeque::from([root_block.id]);
    while let Some(block_id) = queue.pop_front() {
        if !out.insert(block_id) {
            continue;
        }
        for edge in edges_by_block.get(&block_id).into_iter().flatten() {
            if edge.kind == CfgEdgeKind::Call {
                continue;
            }
            let Some(to_block) = edge.to_block else {
                continue;
            };
            let Some(target_block) = block_by_id.get(&to_block) else {
                continue;
            };
            if target_block.start != root && known_roots.contains(&target_block.start) {
                continue;
            }
            queue.push_back(to_block);
        }
    }
    out
}

fn fallback_function_end(root: u64, instructions: &[Instruction]) -> u64 {
    instructions
        .iter()
        .filter(|insn| insn.addr >= root)
        .find(|insn| {
            matches!(
                insn.flow,
                FlowKind::Return | FlowKind::Branch | FlowKind::IndirectBranch
            )
        })
        .map(|insn| insn.addr + u64::from(insn.size))
        .unwrap_or(root + 4)
}
