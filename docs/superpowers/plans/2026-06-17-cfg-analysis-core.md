# CFG Analysis Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a trustworthy CFG-centered analysis core with persisted basic blocks, CFG edges, event-driven bounded refresh, and strict CFG decode failure.

**Architecture:** `ura-core::analysis` remains the analysis orchestration boundary. Full import runs only for first project creation or source replacement; later user edits trigger no refresh or bounded graph-window refresh over existing instructions. Raw disassembly may preserve unknown instructions, but CFG construction fails when a reachable graph window requires unknown or graph-critical partial decode semantics.

**Tech Stack:** Rust 2021, existing Cargo workspace, `serde`/`bincode` project storage, existing handwritten ELF/PE fixtures, existing `urloader` and `urdisassembly` crates.

---

## Scope Notes

This plan implements `docs/superpowers/specs/2026-06-17-cfg-analysis-core-design.md`.

Keep the first implementation serial. Do not add a thread pool, `rayon`, or CLI thread flags in this plan.

The CFG builder should walk reachable graph windows from trusted roots. It should not fail on unknown instructions that are present in linear disassembly but unreachable from the requested CFG roots.

## File Structure

- Modify `crates/ura-core/src/model.rs`: schema-facing model additions for basic blocks, CFG edges, block source, edge kind, and source bytes.
- Modify `crates/ura-core/src/store.rs`: schema version 4 and `ProjectFile` fields.
- Modify `crates/ura-core/src/commands.rs`: source-byte persistence, graph query commands, refresh event use, and graph-window refresh from user function events.
- Modify `crates/ura-core/src/analysis/mod.rs`: add CFG output to `AnalysisOutput` and wire import flow.
- Create `crates/ura-core/src/analysis/refresh.rs`: `ProjectEvent`, `RefreshReason`, `AnalysisWindow`, `RefreshPlan`, and refresh policy.
- Create `crates/ura-core/src/analysis/cfg.rs`: reachable CFG builder and strict decode errors.
- Modify `crates/ura-core/src/analysis/functions.rs`: discover function ranges from CFG reachability.
- Modify `crates/ura-core/src/analysis/xrefs.rs`: derive code and call xrefs from CFG edges while keeping string xrefs from operands.
- Modify `crates/ura-core/src/analysis/diagnostics.rs`: include graph diagnostics and invalid manual function diagnostics.
- Modify `crates/ura-core/tests/project_roundtrip.rs`: schema v4 and source/graph persistence tests.
- Modify `crates/ura-core/tests/project_store.rs`: user truth persistence and old-schema error expectations.
- Create `crates/ura-core/tests/refresh_policy.rs`: refresh event and command-level no-refresh tests.
- Create `crates/ura-core/tests/cfg_analysis.rs`: CFG behavior tests for AArch64 and x86-64.
- Modify `crates/ura-core/tests/analysis_smoke.rs`: full import produces graph results and user edits preserve truth.
- Modify `crates/ura-corpus-gate/src/main.rs`: structural corpus metrics.

---

### Task 1: Add Schema v4 Source Bytes And Graph Model

**Files:**
- Modify: `crates/ura-core/src/model.rs`
- Modify: `crates/ura-core/src/store.rs`
- Modify: `crates/ura-core/src/commands.rs`
- Modify: `crates/ura-core/tests/project_roundtrip.rs`
- Modify: `crates/ura-core/tests/project_store.rs`

- [ ] **Step 1: Add failing schema v4 source-byte persistence tests**

In `crates/ura-core/tests/project_roundtrip.rs`, update the existing schema tests from v3 to v4 and add this test:

```rust
#[test]
fn project_schema_v4_persists_source_bytes_and_graph_fields() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project_path = dir.path().join("sample.ura");
    let bytes = fixtures::minimal_elf64_aarch64_executable();
    std::fs::write(&input, &bytes)?;

    commands::new_project(&input, &project_path)?;
    let project = Project::open(&project_path)?;

    assert_eq!(project.schema_version()?, 4);
    assert_eq!(project.file().source_bytes, bytes);
    assert!(project.file().basic_blocks.is_empty());
    assert!(project.file().cfg_edges.is_empty());
    Ok(())
}
```

In the same file, change assertions that currently expect `schema_version == 3` to `schema_version == 4`.

In `crates/ura-core/tests/project_store.rs`, add this import:

```rust
use ura_core::project::Project;
```

Then add this test:

```rust
#[test]
fn empty_project_schema_v4_has_source_and_graph_containers() -> Result<()> {
    let dir = tempdir()?;
    let project_path = dir.path().join("empty.ura");

    let project = Project::create_empty(&project_path, "hash-for-test")?;

    assert_eq!(project.file().info.schema_version, 4);
    assert!(project.file().source_bytes.is_empty());
    assert!(project.file().basic_blocks.is_empty());
    assert!(project.file().cfg_edges.is_empty());
    Ok(())
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p ura-core --test project_roundtrip project_schema_v4_persists_source_bytes_and_graph_fields -- --nocapture
cargo test -p ura-core --test project_store empty_project_schema_v4_has_source_and_graph_containers -- --nocapture
```

Expected: compile fails because `ProjectFile` has no `source_bytes`, `basic_blocks`, or `cfg_edges` fields, and schema version is still `3`.

- [ ] **Step 3: Add graph model types**

In `crates/ura-core/src/model.rs`, replace the current `BasicBlock` definition with this definition and add the new enums/structs immediately after `FunctionSource`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BasicBlockSource {
    Entry,
    BranchTarget,
    Fallthrough,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: i64,
    pub function_addr: Option<u64>,
    pub start: u64,
    pub end: u64,
    pub terminal_addr: Option<u64>,
    pub instruction_count: usize,
    pub source: BasicBlockSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgEdgeKind {
    Fallthrough,
    Branch,
    ConditionalTrue,
    ConditionalFalse,
    Call,
    Return,
    Indirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from_block: i64,
    pub to_block: Option<i64>,
    pub from_addr: u64,
    pub to_addr: Option<u64>,
    pub kind: CfgEdgeKind,
}
```

- [ ] **Step 4: Add project storage fields and schema v4**

In `crates/ura-core/src/store.rs`, update the imports to include `BasicBlock` and `CfgEdge`:

```rust
use crate::{
    model::{
        Architecture, BasicBlock, BinaryFormat, CfgEdge, Diagnostic, Endian, Function, ImageClass,
        Instruction, LoadProfile, ProjectInfo, Section, Segment, StringRef, Symbol, Xref,
    },
    Result, UraError,
};
```

Change:

```rust
pub const PROJECT_SCHEMA_VERSION: i64 = 3;
```

to:

```rust
pub const PROJECT_SCHEMA_VERSION: i64 = 4;
```

Add these fields to `ProjectFile` after `info`:

```rust
pub source_bytes: Vec<u8>,
```

and after `instructions`:

```rust
pub basic_blocks: Vec<BasicBlock>,
pub cfg_edges: Vec<CfgEdge>,
```

In `ProjectFile::empty`, initialize the new fields:

```rust
source_bytes: Vec::new(),
```

and:

```rust
basic_blocks: Vec::new(),
cfg_edges: Vec::new(),
```

- [ ] **Step 5: Persist source bytes during project creation**

In `crates/ura-core/src/commands.rs`, update the model import to include `BasicBlock` and `CfgEdge` if the compiler requires explicit names for later assignments:

```rust
use crate::{
    analysis::{self, target::AnalysisTarget, AnalysisImage},
    model::{
        Diagnostic, Function, FunctionSource, Instruction, LoadProfile, ProjectInfo, Section,
        Segment, StringRef, Symbol, Xref,
    },
    project::Project,
    store::{ProjectFile, PROJECT_SCHEMA_VERSION},
    Result, UraError,
};
```

Then in `build_project_file`, set the new `ProjectFile` fields:

```rust
Ok(ProjectFile {
    info: ProjectInfo {
        schema_version: PROJECT_SCHEMA_VERSION,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        source_hash: source_hash.to_string(),
        format: target.format,
        architecture: target.architecture,
        class: target.class,
        endian: target.endian,
        profile: convert_profile(loaded.profile),
    },
    source_bytes: loaded.bytes.clone(),
    segments,
    sections,
    symbols,
    instructions: analysis.instructions,
    basic_blocks: Vec::new(),
    cfg_edges: Vec::new(),
    functions: analysis.functions,
    xrefs: analysis.xrefs,
    strings: analysis.strings,
    comments: Default::default(),
    renames: Default::default(),
    diagnostics: analysis.diagnostics,
})
```

- [ ] **Step 6: Run focused tests and verify they pass**

Run:

```bash
cargo test -p ura-core --test project_roundtrip
cargo test -p ura-core --test project_store
```

Expected: all tests pass, with existing schema assertions updated to `4`.

- [ ] **Step 7: Commit**

Run:

```bash
git add crates/ura-core/src/model.rs crates/ura-core/src/store.rs crates/ura-core/src/commands.rs crates/ura-core/tests/project_roundtrip.rs crates/ura-core/tests/project_store.rs
git commit -m "feat: add cfg project schema"
```

---

### Task 2: Add Event-Driven Refresh Policy Types

**Files:**
- Create: `crates/ura-core/src/analysis/refresh.rs`
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Create: `crates/ura-core/tests/refresh_policy.rs`

- [ ] **Step 1: Write refresh policy tests**

Create `crates/ura-core/tests/refresh_policy.rs`:

```rust
use ura_core::analysis::refresh::{
    refresh_policy, AnalysisWindow, ProjectEvent, RefreshPlan, RefreshReason,
};

#[test]
fn new_project_uses_full_import() {
    assert_eq!(
        refresh_policy(ProjectEvent::SourceCreated),
        RefreshPlan::FullImport
    );
}

#[test]
fn source_replacement_uses_full_import() {
    assert_eq!(
        refresh_policy(ProjectEvent::SourceReplaced),
        RefreshPlan::FullImport
    );
}

#[test]
fn manual_function_added_uses_graph_window() {
    assert_eq!(
        refresh_policy(ProjectEvent::ManualFunctionAdded { addr: 0x400080 }),
        RefreshPlan::GraphWindow(AnalysisWindow {
            start: 0x400080,
            end: 0x400084,
            reason: RefreshReason::ManualFunctionAdded { addr: 0x400080 },
        })
    );
}

#[test]
fn manual_range_change_uses_exact_graph_window() {
    assert_eq!(
        refresh_policy(ProjectEvent::ManualFunctionRangeChanged {
            addr: 0x400080,
            start: 0x400080,
            end: 0x400090,
        }),
        RefreshPlan::GraphWindow(AnalysisWindow {
            start: 0x400080,
            end: 0x400090,
            reason: RefreshReason::ManualFunctionRangeChanged {
                addr: 0x400080,
                start: 0x400080,
                end: 0x400090,
            },
        })
    );
}

#[test]
fn rename_comment_and_queries_do_not_refresh() {
    assert_eq!(
        refresh_policy(ProjectEvent::RenameChanged { addr: 0x400080 }),
        RefreshPlan::None
    );
    assert_eq!(
        refresh_policy(ProjectEvent::CommentChanged { addr: 0x400080 }),
        RefreshPlan::None
    );
    assert_eq!(refresh_policy(ProjectEvent::Query), RefreshPlan::None);
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```bash
cargo test -p ura-core --test refresh_policy -- --nocapture
```

Expected: compile fails because `analysis::refresh` does not exist.

- [ ] **Step 3: Create the refresh module**

Create `crates/ura-core/src/analysis/refresh.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectEvent {
    SourceCreated,
    SourceReplaced,
    ManualFunctionAdded { addr: u64 },
    ManualFunctionRangeChanged { addr: u64, start: u64, end: u64 },
    RenameChanged { addr: u64 },
    CommentChanged { addr: u64 },
    Query,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshReason {
    ManualFunctionAdded { addr: u64 },
    ManualFunctionRangeChanged { addr: u64, start: u64, end: u64 },
    SourceBytesChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisWindow {
    pub start: u64,
    pub end: u64,
    pub reason: RefreshReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshPlan {
    None,
    GraphWindow(AnalysisWindow),
    DecodeWindow(AnalysisWindow),
    FullImport,
}

pub fn refresh_policy(event: ProjectEvent) -> RefreshPlan {
    match event {
        ProjectEvent::SourceCreated | ProjectEvent::SourceReplaced => RefreshPlan::FullImport,
        ProjectEvent::ManualFunctionAdded { addr } => RefreshPlan::GraphWindow(AnalysisWindow {
            start: addr,
            end: addr.saturating_add(4),
            reason: RefreshReason::ManualFunctionAdded { addr },
        }),
        ProjectEvent::ManualFunctionRangeChanged { addr, start, end } => {
            RefreshPlan::GraphWindow(AnalysisWindow {
                start,
                end,
                reason: RefreshReason::ManualFunctionRangeChanged { addr, start, end },
            })
        }
        ProjectEvent::RenameChanged { .. }
        | ProjectEvent::CommentChanged { .. }
        | ProjectEvent::Query => RefreshPlan::None,
    }
}
```

In `crates/ura-core/src/analysis/mod.rs`, add:

```rust
pub mod refresh;
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
cargo test -p ura-core --test refresh_policy
```

Expected: all refresh policy tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-core/src/analysis/mod.rs crates/ura-core/src/analysis/refresh.rs crates/ura-core/tests/refresh_policy.rs
git commit -m "feat: add analysis refresh policy"
```

---

### Task 3: Add Reachable CFG Builder With Strict Unknown Failure

**Files:**
- Create: `crates/ura-core/src/analysis/cfg.rs`
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Create: `crates/ura-core/tests/cfg_analysis.rs`

- [ ] **Step 1: Write CFG behavior tests**

Create `crates/ura-core/tests/cfg_analysis.rs`:

```rust
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
    assert!(cfg
        .cfg_edges
        .iter()
        .any(|edge| edge.kind == CfgEdgeKind::ConditionalTrue && edge.to_addr == Some(0x400088)));
    assert!(cfg
        .cfg_edges
        .iter()
        .any(|edge| edge.kind == CfgEdgeKind::ConditionalFalse && edge.to_addr == Some(0x400084)));
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
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p ura-core --test cfg_analysis -- --nocapture
```

Expected: compile fails because `analysis::cfg` and `build_cfg` do not exist.

- [ ] **Step 3: Add the CFG module root and output type**

In `crates/ura-core/src/analysis/mod.rs`, add:

```rust
pub mod cfg;
```

Create `crates/ura-core/src/analysis/cfg.rs`:

```rust
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
        loop {
            let Some(insn) = by_addr.get(&addr).copied() else {
                break;
            };
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
```

- [ ] **Step 4: Run CFG tests and verify they pass**

Run:

```bash
cargo test -p ura-core --test cfg_analysis
```

Expected: all CFG tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-core/src/analysis/mod.rs crates/ura-core/src/analysis/cfg.rs crates/ura-core/tests/cfg_analysis.rs
git commit -m "feat: add strict cfg builder"
```

---

### Task 4: Wire Full Import To Persist CFG Results

**Files:**
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Modify: `crates/ura-core/src/commands.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`

- [ ] **Step 1: Add command-level graph query tests**

In `crates/ura-core/tests/analysis_smoke.rs`, add this test:

```rust
#[test]
fn new_project_records_basic_blocks_and_cfg_edges() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    let blocks = commands::basic_blocks(&project)?;
    let edges = commands::cfg_edges(&project)?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].start, 0x400080);
    assert_eq!(blocks[0].end, 0x400084);
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, ura_core::model::CfgEdgeKind::Return);
    Ok(())
}
```

Update the Task 1 test `project_schema_v4_persists_source_bytes_and_graph_fields` so it now expects persisted graph output:

```rust
assert!(!project.file().basic_blocks.is_empty());
assert!(!project.file().cfg_edges.is_empty());
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p ura-core --test analysis_smoke new_project_records_basic_blocks_and_cfg_edges -- --nocapture
```

Expected: compile fails because `commands::basic_blocks` and `commands::cfg_edges` do not exist, or the graph vectors remain empty.

- [ ] **Step 3: Add graph output to the analysis pipeline**

In `crates/ura-core/src/analysis/mod.rs`, update imports:

```rust
use crate::{
    model::{BasicBlock, CfgEdge, Diagnostic, Function, Instruction, Segment, StringRef, Xref},
    Result,
};
```

Add fields to `AnalysisOutput`:

```rust
pub basic_blocks: Vec<BasicBlock>,
pub cfg_edges: Vec<CfgEdge>,
```

In `run_initial_analysis_with_instruction_limit`, after disassembly and strings, build CFG from the image entry:

```rust
let instructions = disasm::linear_disassemble_with_limit(image, max_instructions)?;
let strings = strings::extract_strings(image);
let window = refresh::AnalysisWindow {
    start: image.entry,
    end: image.entry.saturating_add(4),
    reason: refresh::RefreshReason::SourceBytesChanged,
};
let cfg = cfg::build_cfg(&instructions, &[image.entry], window)?;
let functions = functions::discover_functions(
    image.entry,
    &instructions,
    &cfg.basic_blocks,
    &cfg.cfg_edges,
    user_functions,
);
let xrefs = xrefs::build_xrefs(&instructions, &strings, &cfg.cfg_edges);
let diagnostics = diagnostics::collect_diagnostics(&instructions);
Ok(AnalysisOutput {
    instructions,
    basic_blocks: cfg.basic_blocks,
    cfg_edges: cfg.cfg_edges,
    strings,
    functions,
    xrefs,
    diagnostics,
})
```

This step changes function and xref signatures before their implementations are updated. Make the minimal signature changes needed to compile:

In `crates/ura-core/src/analysis/functions.rs`, change the function signature to:

```rust
pub fn discover_functions(
    entry: u64,
    instructions: &[Instruction],
    _basic_blocks: &[crate::model::BasicBlock],
    _cfg_edges: &[crate::model::CfgEdge],
    user_functions: &[Function],
) -> Vec<Function> {
```

Keep the existing body for now.

In `crates/ura-core/src/analysis/xrefs.rs`, change the function signature to:

```rust
pub fn build_xrefs(
    instructions: &[Instruction],
    strings: &[StringRef],
    _cfg_edges: &[crate::model::CfgEdge],
) -> Vec<Xref> {
```

Keep the existing body for now.

- [ ] **Step 4: Persist graph output and add command accessors**

In `crates/ura-core/src/commands.rs`, assign analysis graph output:

```rust
instructions: analysis.instructions,
basic_blocks: analysis.basic_blocks,
cfg_edges: analysis.cfg_edges,
functions: analysis.functions,
```

Add these command helpers after `functions`:

```rust
pub fn basic_blocks(project_path: impl AsRef<Path>) -> Result<Vec<crate::model::BasicBlock>> {
    Ok(Project::open(project_path)?.file().basic_blocks.clone())
}

pub fn cfg_edges(project_path: impl AsRef<Path>) -> Result<Vec<crate::model::CfgEdge>> {
    Ok(Project::open(project_path)?.file().cfg_edges.clone())
}
```

- [ ] **Step 5: Run focused tests and verify they pass**

Run:

```bash
cargo test -p ura-core --test analysis_smoke new_project_records_basic_blocks_and_cfg_edges
cargo test -p ura-core --test project_roundtrip project_schema_v4_persists_source_bytes_and_graph_fields
```

Expected: both tests pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add crates/ura-core/src/analysis/mod.rs crates/ura-core/src/analysis/functions.rs crates/ura-core/src/analysis/xrefs.rs crates/ura-core/src/commands.rs crates/ura-core/tests/analysis_smoke.rs crates/ura-core/tests/project_roundtrip.rs
git commit -m "feat: persist import cfg"
```

---

### Task 5: Discover Function Ranges From CFG Reachability

**Files:**
- Modify: `crates/ura-core/src/analysis/functions.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`
- Modify: `crates/ura-core/tests/cfg_analysis.rs`

- [ ] **Step 1: Add a function-discovery smoke test**

In `crates/ura-core/tests/analysis_smoke.rs`, add:

```rust
#[test]
fn function_discovery_uses_call_targets_without_merging_callee_body() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x94000002u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let funcs = commands::functions(&project)?;

    let entry = funcs
        .iter()
        .find(|func| func.addr == 0x400080)
        .expect("entry function should exist");
    let callee = funcs
        .iter()
        .find(|func| func.addr == 0x400088)
        .expect("call target function should exist");

    assert_eq!(entry.start, 0x400080);
    assert_eq!(entry.end, 0x400088);
    assert_eq!(callee.start, 0x400088);
    assert_eq!(callee.end, 0x40008c);
    Ok(())
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```bash
cargo test -p ura-core --test analysis_smoke function_discovery_uses_call_targets_without_merging_callee_body -- --nocapture
```

Expected: fails because function discovery still uses the first terminal range guess and does not derive bodies from CFG reachability.

- [ ] **Step 3: Replace function discovery with CFG reachability**

Replace `crates/ura-core/src/analysis/functions.rs` with:

```rust
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::model::{
    BasicBlock, CfgEdge, CfgEdgeKind, FlowKind, Function, FunctionSource, Instruction,
};

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
```

- [ ] **Step 4: Run focused tests and verify they pass**

Run:

```bash
cargo test -p ura-core --test analysis_smoke function_discovery_uses_call_targets_without_merging_callee_body
cargo test -p ura-core --test analysis_smoke branch_and_call_xrefs_use_decoder_flow
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-core/src/analysis/functions.rs crates/ura-core/tests/analysis_smoke.rs
git commit -m "feat: discover functions from cfg"
```

---

### Task 6: Add Graph-Window Refresh For Manual Function Events

**Files:**
- Modify: `crates/ura-core/src/commands.rs`
- Modify: `crates/ura-core/tests/refresh_policy.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`

- [ ] **Step 1: Add command tests proving edit events are bounded**

In `crates/ura-core/tests/refresh_policy.rs`, add:

```rust
mod fixtures;

use ura_core::{
    commands,
    project::Project,
    Result,
};
use tempfile::tempdir;
```

If the file already has imports from Task 2, merge these imports without duplicating module declarations.

Add this test:

```rust
#[test]
fn make_function_refreshes_graph_without_rebuilding_disassembly() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project_path = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project_path)?;
    {
        let mut project = Project::open(&project_path)?;
        project.file_mut().instructions[0].text = "ret /* preserved */".to_string();
        project.save()?;
    }

    commands::make_function(&project_path, 0x400080)?;
    let disasm = commands::disasm(&project_path, 0x400080, 1)?;
    let funcs = commands::functions(&project_path)?;

    assert_eq!(disasm[0].text, "ret /* preserved */");
    assert!(funcs
        .iter()
        .any(|func| func.addr == 0x400080 && func.source == ura_core::model::FunctionSource::User));
    Ok(())
}
```

In `crates/ura-core/tests/analysis_smoke.rs`, add:

```rust
#[test]
fn set_function_range_refreshes_only_the_graph_window() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    commands::set_function_range(&project, 0x400080, 0x400080, 0x400084)?;

    let funcs = commands::functions(&project)?;
    assert!(funcs.iter().any(|func| {
        func.addr == 0x400080
            && func.start == 0x400080
            && func.end == 0x400084
            && func.source == ura_core::model::FunctionSource::User
    }));
    Ok(())
}
```

- [ ] **Step 2: Run the tests and verify failure**

Run:

```bash
cargo test -p ura-core --test refresh_policy make_function_refreshes_graph_without_rebuilding_disassembly -- --nocapture
cargo test -p ura-core --test analysis_smoke set_function_range_refreshes_only_the_graph_window -- --nocapture
```

Expected: the first test fails if implementation rebuilds disassembly or if graph-window refresh does not preserve user truth.

- [ ] **Step 3: Add graph-window helper functions**

In `crates/ura-core/src/commands.rs`, add imports:

```rust
use crate::analysis::refresh::{refresh_policy, AnalysisWindow, ProjectEvent, RefreshPlan};
```

Add this helper near `upsert_user_function`:

```rust
fn apply_refresh_plan(project_file: &mut ProjectFile, plan: RefreshPlan) -> Result<()> {
    match plan {
        RefreshPlan::None => Ok(()),
        RefreshPlan::GraphWindow(window) => refresh_graph_window(project_file, window),
        RefreshPlan::DecodeWindow(window) => Err(UraError::Analysis(format!(
            "decode-window refresh is not available for 0x{:x}..0x{:x}",
            window.start, window.end
        ))),
        RefreshPlan::FullImport => Err(UraError::Analysis(
            "full import is only valid during source import".to_string(),
        )),
    }
}

fn refresh_graph_window(project_file: &mut ProjectFile, window: AnalysisWindow) -> Result<()> {
    let mut roots = project_file
        .functions
        .iter()
        .filter(|func| func.source == FunctionSource::User)
        .map(|func| func.addr)
        .collect::<Vec<_>>();
    if !roots.contains(&window.start) {
        roots.push(window.start);
    }
    if roots.is_empty() {
        return Ok(());
    }

    let cfg = analysis::cfg::build_cfg(&project_file.instructions, &roots, window)?;
    project_file.basic_blocks = cfg.basic_blocks;
    project_file.cfg_edges = cfg.cfg_edges;
    let user_functions = project_file
        .functions
        .iter()
        .filter(|func| func.source == FunctionSource::User)
        .cloned()
        .collect::<Vec<_>>();
    let entry = project_file
        .instructions
        .first()
        .map(|insn| insn.addr)
        .unwrap_or(window.start);
    project_file.functions = analysis::functions::discover_functions(
        entry,
        &project_file.instructions,
        &project_file.basic_blocks,
        &project_file.cfg_edges,
        &user_functions,
    );
    project_file.xrefs =
        analysis::xrefs::build_xrefs(&project_file.instructions, &project_file.strings, &project_file.cfg_edges);
    project_file.diagnostics = analysis::diagnostics::collect_diagnostics(&project_file.instructions);
    Ok(())
}
```

- [ ] **Step 4: Use refresh policy in manual function commands**

In `make_function`, after `upsert_user_function(...)` and before `project.save()`, add:

```rust
let plan = refresh_policy(ProjectEvent::ManualFunctionAdded { addr });
apply_refresh_plan(project.file_mut(), plan)?;
```

In `set_function_range`, after `upsert_user_function(...)` and before `project.save()`, add:

```rust
let plan = refresh_policy(ProjectEvent::ManualFunctionRangeChanged {
    addr: function_addr,
    start,
    end,
});
apply_refresh_plan(project.file_mut(), plan)?;
```

Do not call `apply_refresh_plan` from `rename`, `comment`, `info`, `disasm`, `xrefs`, `strings`, or `diagnostics`.

- [ ] **Step 5: Run focused tests and verify they pass**

Run:

```bash
cargo test -p ura-core --test refresh_policy
cargo test -p ura-core --test analysis_smoke set_function_range_refreshes_only_the_graph_window
```

Expected: all refresh policy tests pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add crates/ura-core/src/commands.rs crates/ura-core/tests/refresh_policy.rs crates/ura-core/tests/analysis_smoke.rs
git commit -m "feat: refresh graph windows for manual functions"
```

---

### Task 7: Build Code Xrefs From CFG Edges

**Files:**
- Modify: `crates/ura-core/src/analysis/xrefs.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`

- [ ] **Step 1: Add xref test that depends on CFG edge kind**

In `crates/ura-core/tests/analysis_smoke.rs`, add:

```rust
#[test]
fn call_xrefs_are_derived_from_cfg_edges() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x94000002u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let xrefs = commands::xrefs(&project, 0x400088)?;

    assert!(xrefs.iter().any(|xref| {
        xref.from_addr == 0x400080
            && xref.to_addr == 0x400088
            && xref.kind == ura_core::model::XrefKind::Call
    }));
    Ok(())
}
```

- [ ] **Step 2: Run the test and verify current behavior**

Run:

```bash
cargo test -p ura-core --test analysis_smoke call_xrefs_are_derived_from_cfg_edges -- --nocapture
```

Expected: this may already pass through instruction target scanning. Keep the test because the next step changes the source of truth to CFG edges.

- [ ] **Step 3: Replace code xrefs with CFG-edge xrefs**

In `crates/ura-core/src/analysis/xrefs.rs`, update the imports:

```rust
use crate::model::{CfgEdge, CfgEdgeKind, Instruction, StringRef, Xref, XrefKind};
```

Replace the first half of `build_xrefs` with CFG-edge extraction:

```rust
pub fn build_xrefs(
    instructions: &[Instruction],
    strings: &[StringRef],
    cfg_edges: &[CfgEdge],
) -> Vec<Xref> {
    let mut out = Vec::new();
    for edge in cfg_edges {
        let Some(to_addr) = edge.to_addr else {
            continue;
        };
        let kind = match edge.kind {
            CfgEdgeKind::Call => XrefKind::Call,
            CfgEdgeKind::Branch | CfgEdgeKind::ConditionalTrue | CfgEdgeKind::ConditionalFalse => {
                XrefKind::Code
            }
            CfgEdgeKind::Fallthrough | CfgEdgeKind::Return | CfgEdgeKind::Indirect => continue,
        };
        out.push(Xref {
            from_addr: edge.from_addr,
            to_addr,
            kind,
        });
    }

    let strings_by_operand = strings_by_operand(strings);
    for insn in instructions {
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
```

Keep the existing `strings_by_operand`, `hex_address_tokens`, and unit test helper functions. Update the unit test call to pass an empty CFG edge slice:

```rust
let xrefs = build_xrefs(&instructions, &strings, &[]);
```

- [ ] **Step 4: Run xref tests**

Run:

```bash
cargo test -p ura-core analysis::xrefs::tests::string_xrefs_match_whole_hex_operands
cargo test -p ura-core --test analysis_smoke call_xrefs_are_derived_from_cfg_edges
cargo test -p ura-core --test analysis_smoke branch_and_call_xrefs_use_decoder_flow
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-core/src/analysis/xrefs.rs crates/ura-core/tests/analysis_smoke.rs
git commit -m "feat: derive code xrefs from cfg"
```

---

### Task 8: Add Graph Diagnostics

**Files:**
- Modify: `crates/ura-core/src/analysis/diagnostics.rs`
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Modify: `crates/ura-core/src/commands.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`

- [ ] **Step 1: Add diagnostics tests**

In `crates/ura-core/tests/analysis_smoke.rs`, add:

```rust
#[test]
fn invalid_user_function_root_is_retained_and_diagnosed() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    commands::make_function(&project, 0x500000)?;

    let funcs = commands::functions(&project)?;
    let diagnostics = commands::diagnostics(&project)?;

    assert!(funcs.iter().any(|func| {
        func.addr == 0x500000 && func.source == ura_core::model::FunctionSource::User
    }));
    assert!(diagnostics.iter().any(|diag| {
        diag.addr == Some(0x500000) && diag.message.contains("manual function root is not in disassembly")
    }));
    Ok(())
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```bash
cargo test -p ura-core --test analysis_smoke invalid_user_function_root_is_retained_and_diagnosed -- --nocapture
```

Expected: fails because invalid user function roots are not diagnosed.

- [ ] **Step 3: Add graph diagnostic helpers**

In `crates/ura-core/src/analysis/diagnostics.rs`, replace the imports and add graph helpers:

```rust
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
                "empty mnemonic".to_string()
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
```

- [ ] **Step 4: Wire graph diagnostics into import and graph refresh**

In `crates/ura-core/src/analysis/mod.rs`, replace:

```rust
let diagnostics = diagnostics::collect_diagnostics(&instructions);
```

with:

```rust
let mut diagnostics = diagnostics::collect_diagnostics(&instructions);
diagnostics.extend(diagnostics::collect_graph_diagnostics(&cfg.cfg_edges));
diagnostics.extend(diagnostics::collect_user_function_diagnostics(
    &functions,
    &instructions,
));
```

In `crates/ura-core/src/commands.rs`, inside `refresh_graph_window`, replace:

```rust
project_file.diagnostics = analysis::diagnostics::collect_diagnostics(&project_file.instructions);
```

with:

```rust
let mut diagnostics = analysis::diagnostics::collect_diagnostics(&project_file.instructions);
diagnostics.extend(analysis::diagnostics::collect_graph_diagnostics(
    &project_file.cfg_edges,
));
diagnostics.extend(analysis::diagnostics::collect_user_function_diagnostics(
    &project_file.functions,
    &project_file.instructions,
));
project_file.diagnostics = diagnostics;
```

- [ ] **Step 5: Run diagnostics tests**

Run:

```bash
cargo test -p ura-core --test analysis_smoke invalid_user_function_root_is_retained_and_diagnosed
cargo test -p ura-core --test analysis_smoke unknown_instruction_is_recorded_and_diagnosed
```

Expected: both tests pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add crates/ura-core/src/analysis/diagnostics.rs crates/ura-core/src/analysis/mod.rs crates/ura-core/src/commands.rs crates/ura-core/tests/analysis_smoke.rs
git commit -m "feat: add graph diagnostics"
```

---

### Task 9: Add Corpus Structural Metrics

**Files:**
- Modify: `crates/ura-corpus-gate/src/main.rs`

- [ ] **Step 1: Add corpus report fields**

In `crates/ura-corpus-gate/src/main.rs`, add fields to `SampleReport` after `decoded_instruction_count`:

```rust
basic_block_count: usize,
cfg_edge_count: usize,
```

and after `diagnostic_count`:

```rust
cfg_failure_count: usize,
```

In the error path inside `run_sample`, initialize them:

```rust
basic_block_count: 0,
cfg_edge_count: 0,
cfg_failure_count: 1,
```

- [ ] **Step 2: Read graph metrics from projects**

In `analyze_sample`, after reading `instructions`, add:

```rust
let basic_blocks = ura_core::commands::basic_blocks(&project)?;
let cfg_edges = ura_core::commands::cfg_edges(&project)?;
```

Then set the report fields:

```rust
basic_block_count: basic_blocks.len(),
cfg_edge_count: cfg_edges.len(),
cfg_failure_count: 0,
```

- [ ] **Step 3: Add metrics to the markdown summary**

In `render_summary`, replace the table header with:

```rust
out.push_str("| Sample | OK | Instructions | Blocks | Edges | Unknown Rate | Failure |\n");
out.push_str("| --- | --- | ---: | ---: | ---: | ---: | --- |\n");
```

Replace the row format with:

```rust
out.push_str(&format!(
    "| {} | {} | {} | {} | {} | {:.4} | {} |\n",
    sample.id,
    sample.ok,
    sample.decoded_instruction_count,
    sample.basic_block_count,
    sample.cfg_edge_count,
    sample.unknown_rate,
    sample.failure_reason.clone().unwrap_or_default()
));
```

- [ ] **Step 4: Run compile and available corpus-gate tests**

Run:

```bash
cargo test -p ura-corpus-gate
cargo check -p ura-corpus-gate
```

Expected: both commands pass. The real corpus gate still runs only in GitHub Actions.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-corpus-gate/src/main.rs
git commit -m "feat: report corpus cfg metrics"
```

---

### Task 10: Final Workspace Verification

**Files:**
- No source edits unless a verification command exposes a real issue.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt --check
```

Expected: pass.

If formatting fails, run:

```bash
cargo fmt
```

Then rerun:

```bash
cargo fmt --check
```

Expected: pass.

- [ ] **Step 2: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: pass.

- [ ] **Step 3: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: pass.

- [ ] **Step 4: Review git status**

Run:

```bash
git status --short
```

Expected: clean. If formatting changed files after the last task commit, commit them:

```bash
git add .
git commit -m "chore: format cfg analysis core"
```

Only run that commit if `git status --short` shows formatting-only changes.
