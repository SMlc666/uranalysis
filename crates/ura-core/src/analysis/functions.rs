use std::collections::BTreeSet;

use crate::model::{Function, FunctionSource, Instruction};

pub fn discover_functions(
    entry: u64,
    instructions: &[Instruction],
    user_functions: &[Function],
) -> Vec<Function> {
    let mut starts = BTreeSet::new();
    starts.insert((entry, FunctionSource::Entry));
    for insn in instructions {
        if matches!(insn.flow.as_str(), "Call" | "Branch" | "ConditionalBranch") {
            if let Some(target) = insn.branch_target {
                starts.insert((target, FunctionSource::BranchTarget));
            }
        }
    }
    let mut functions = starts
        .into_iter()
        .map(|(addr, source)| Function {
            addr,
            name: format!("sub_{addr:x}"),
            start: addr,
            end: first_terminal_end(addr, instructions).unwrap_or(addr + 4),
            source,
        })
        .collect::<Vec<_>>();
    for user in user_functions {
        functions.retain(|func| func.addr != user.addr);
        functions.push(user.clone());
    }
    functions.sort_by_key(|func| func.addr);
    functions
}

fn first_terminal_end(start: u64, instructions: &[Instruction]) -> Option<u64> {
    instructions
        .iter()
        .filter(|insn| insn.addr >= start)
        .find(|insn| matches!(insn.flow.as_str(), "Return" | "Branch" | "IndirectBranch"))
        .map(|insn| insn.addr + u64::from(insn.size))
}
