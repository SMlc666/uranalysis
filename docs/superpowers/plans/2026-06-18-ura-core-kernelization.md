# Ura Core Kernelization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `ura-core` into a pure session-based analysis kernel, move project persistence into `urastore`, and replace fake reanalysis with scheduler-driven refresh over truth plus cache.

**Architecture:** Keep the current decode/string/CFG/function/xref/diagnostic logic, but route it through a new `AnalysisSession` plus declarative pass graph. Introduce `urastore` as the only owner of on-disk truth/cache encoding, then rewire CLI and daemon to orchestrate `urastore` plus `ura-core` instead of calling file-IO helpers inside the core.

**Tech Stack:** Rust 2021, Cargo workspace, existing `urloader`/`urcodec`, `serde`, `bincode`, current CLI and daemon smoke tests, current handwritten ELF/PE fixtures.

---

## Scope Notes

This plan implements `docs/superpowers/specs/2026-06-18-ura-core-kernelization-design.md`.

Keep the first kernelized landing single-threaded. Do not add `rayon`, worker pools, or async runtime changes in this plan.

Do not preserve backward compatibility with pre-`urastore` project snapshots in this plan. Reject them with a clear compatibility error and add tests for that failure mode.

## File Structure

- Modify `Cargo.toml`: add `crates/urastore` workspace member and workspace dependency.
- Create `crates/urastore/Cargo.toml`: package metadata and dependencies.
- Create `crates/urastore/src/lib.rs`: public store API exports.
- Create `crates/urastore/src/error.rs`: `StoreError` and crate `Result`.
- Create `crates/urastore/src/model.rs`: `ProjectSource`, `UserTruth`, `AnalysisCache`, `CacheMetadata`, and `StoredProject`.
- Create `crates/urastore/src/store.rs`: binary container encode/decode and read/write helpers.
- Create `crates/urastore/tests/store_roundtrip.rs`: truth/cache roundtrip, stale-cache metadata, and legacy-format rejection tests.
- Modify `crates/ura-core/src/lib.rs`: export new session/pass modules and remove storage/project exports.
- Modify `crates/ura-core/src/model.rs`: add `UserFacts`, `AnalysisState`, `PassId`, and pass-status types used by the kernel.
- Create `crates/ura-core/src/analysis/pass.rs`: declarative pass definitions and dependency metadata.
- Create `crates/ura-core/src/analysis/session.rs`: `AnalysisInputs`, `AnalysisSession`, `RefreshSummary`, and session mutation/query methods.
- Create `crates/ura-core/src/analysis/invalidation.rs`: `DirtyInputs`, `InvalidationSet`, and invalidation helpers.
- Create `crates/ura-core/src/analysis/scheduler.rs`: pass planning and refresh execution order.
- Modify `crates/ura-core/src/analysis/mod.rs`: keep the existing pass implementations but expose state builders used by `AnalysisSession`.
- Delete `crates/ura-core/src/analysis/refresh.rs`: superseded by `analysis/invalidation.rs`.
- Delete `crates/ura-core/src/project.rs`: file-backed project wrapper no longer belongs in the core.
- Delete `crates/ura-core/src/store.rs`: on-disk container moves to `urastore`.
- Modify `crates/ura-core/src/commands.rs`: replace file-IO helpers with in-memory query/mutation helpers over `AnalysisSession` for the transition period before the module is deleted.
- Create `crates/ura-core/tests/session_refresh.rs`: scheduler, invalidation, and real reanalysis tests.
- Modify `crates/ura-core/tests/analysis_smoke.rs`: exercise session-backed refresh and user-fact influence without file IO.
- Delete `crates/ura-core/tests/project_store.rs`: storage tests move to `urastore`.
- Delete `crates/ura-core/tests/project_roundtrip.rs`: roundtrip responsibility moves to `urastore`.
- Delete `crates/ura-core/tests/refresh_policy.rs`: event-style refresh tests are superseded by session invalidation tests.
- Modify `crates/ura-cli/Cargo.toml`: add `urastore`.
- Modify `crates/ura-cli/src/main.rs`: open/save via `urastore` and operate on `AnalysisSession`.
- Modify `crates/ura-cli/src/shell.rs`: route shell commands through `urastore` plus session refresh.
- Modify `crates/ura-cli/tests/cli_smoke.rs`: assert `reanalyze` actually rebuilds stale cache.
- Modify `crates/ura-daemon/Cargo.toml`: add `urastore`.
- Modify `crates/ura-daemon/src/main.rs`: open/save via `urastore` and use kernel session APIs.
- Modify `crates/ura-daemon/tests/daemon_smoke.rs`: keep daemon mutation and reanalysis behavior green with the new storage path.
- Modify `README.md`: update architecture description from `ura-core`-owns-storage to `ura-core` plus `urastore`.

---

### Task 1: Introduce `AnalysisSession`, Pass IDs, And Scheduler Planning

**Files:**
- Modify: `crates/ura-core/src/lib.rs`
- Modify: `crates/ura-core/src/model.rs`
- Create: `crates/ura-core/src/analysis/pass.rs`
- Create: `crates/ura-core/src/analysis/invalidation.rs`
- Create: `crates/ura-core/src/analysis/scheduler.rs`
- Create: `crates/ura-core/src/analysis/session.rs`
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Test: `crates/ura-core/tests/session_refresh.rs`

- [ ] **Step 1: Write the failing scheduler-planning test**

Create `crates/ura-core/tests/session_refresh.rs`:

```rust
mod fixtures;

use ura_core::analysis::{
    invalidation::DirtyInputs,
    session::{AnalysisInputs, AnalysisSession},
};

#[test]
fn refresh_plan_marks_cfg_and_downstream_passes_dirty_for_manual_function_range() {
    let loaded = fixtures::load_minimal_aarch64_image();
    let mut session = AnalysisSession::new(AnalysisInputs::from_loaded(&loaded));

    session.mark_dirty(DirtyInputs::manual_function_ranges());
    let plan = session.refresh_plan().expect("plan should build");

    assert_eq!(
        plan.pass_ids(),
        vec!["cfg", "functions", "xrefs", "diagnostics"]
    );
}
```

Add this helper to `crates/ura-core/tests/fixtures.rs`:

```rust
pub fn load_minimal_aarch64_image() -> urloader::LoadedImage {
    urloader::load(&minimal_elf64_aarch64_executable()).expect("fixture should load")
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
cargo test -p ura-core --test session_refresh refresh_plan_marks_cfg_and_downstream_passes_dirty_for_manual_function_range -- --nocapture
```

Expected: compile fails because `analysis::session`, `analysis::invalidation`, and `AnalysisInputs::from_loaded` do not exist.

- [ ] **Step 3: Add the new kernel-planning types**

In `crates/ura-core/src/model.rs`, append these types near the other shared analysis models:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UserFacts {
    pub renames: BTreeMap<u64, String>,
    pub comments: BTreeMap<u64, String>,
    pub manual_function_roots: BTreeSet<u64>,
    pub manual_function_ranges: BTreeMap<u64, (u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PassId {
    Decode,
    Strings,
    Cfg,
    Functions,
    Xrefs,
    Diagnostics,
}

impl PassId {
    pub fn as_str(self) -> &'static str {
        match self {
            PassId::Decode => "decode",
            PassId::Strings => "strings",
            PassId::Cfg => "cfg",
            PassId::Functions => "functions",
            PassId::Xrefs => "xrefs",
            PassId::Diagnostics => "diagnostics",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AnalysisState {
    pub instructions: Vec<Instruction>,
    pub strings: Vec<StringRef>,
    pub basic_blocks: Vec<BasicBlock>,
    pub cfg_edges: Vec<CfgEdge>,
    pub functions: Vec<Function>,
    pub xrefs: Vec<Xref>,
    pub diagnostics: Vec<Diagnostic>,
}
```

Create `crates/ura-core/src/analysis/invalidation.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirtyInputs {
    pub source_bytes: bool,
    pub target_metadata: bool,
    pub renames: bool,
    pub comments: bool,
    pub manual_function_roots: bool,
    pub manual_function_ranges: bool,
}

impl DirtyInputs {
    pub fn manual_function_ranges() -> Self {
        Self {
            manual_function_ranges: true,
            ..Self::default()
        }
    }
}
```

Create `crates/ura-core/src/analysis/pass.rs`:

```rust
use crate::model::PassId;

#[derive(Debug, Clone)]
pub struct PassSpec {
    pub id: PassId,
    pub deps: &'static [PassId],
}

pub const PASS_SPECS: &[PassSpec] = &[
    PassSpec { id: PassId::Decode, deps: &[] },
    PassSpec { id: PassId::Strings, deps: &[] },
    PassSpec { id: PassId::Cfg, deps: &[PassId::Decode] },
    PassSpec { id: PassId::Functions, deps: &[PassId::Decode, PassId::Cfg] },
    PassSpec { id: PassId::Xrefs, deps: &[PassId::Decode, PassId::Strings, PassId::Cfg] },
    PassSpec { id: PassId::Diagnostics, deps: &[PassId::Decode, PassId::Cfg, PassId::Functions] },
];
```

Create `crates/ura-core/src/analysis/scheduler.rs`:

```rust
use crate::{
    analysis::{invalidation::DirtyInputs, pass::PASS_SPECS},
    model::PassId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshPlan {
    pass_ids: Vec<PassId>,
}

impl RefreshPlan {
    pub fn pass_ids(&self) -> Vec<&'static str> {
        self.pass_ids.iter().map(|id| id.as_str()).collect()
    }
}

pub fn build_refresh_plan(dirty: DirtyInputs) -> RefreshPlan {
    let mut pass_ids = Vec::new();
    for spec in PASS_SPECS {
        let include = dirty.source_bytes
            || dirty.target_metadata
            || matches!(spec.id, PassId::Cfg | PassId::Functions | PassId::Xrefs | PassId::Diagnostics)
                && (dirty.manual_function_roots || dirty.manual_function_ranges)
            || matches!(spec.id, PassId::Functions | PassId::Diagnostics)
                && dirty.renames
            || matches!(spec.id, PassId::Diagnostics)
                && dirty.comments;
        if include {
            pass_ids.push(spec.id);
        }
    }
    RefreshPlan { pass_ids }
}
```

Create `crates/ura-core/src/analysis/session.rs`:

```rust
use urloader::LoadedImage;

use crate::{
    analysis::{invalidation::DirtyInputs, scheduler::{build_refresh_plan, RefreshPlan}},
    model::{AnalysisState, UserFacts},
};

#[derive(Debug, Clone)]
pub struct AnalysisInputs {
    pub loaded: LoadedImage,
    pub user_facts: UserFacts,
}

impl AnalysisInputs {
    pub fn from_loaded(loaded: &LoadedImage) -> Self {
        Self {
            loaded: loaded.clone(),
            user_facts: UserFacts::default(),
        }
    }
}

pub struct AnalysisSession {
    pub inputs: AnalysisInputs,
    pub state: AnalysisState,
    dirty: DirtyInputs,
}

impl AnalysisSession {
    pub fn new(inputs: AnalysisInputs) -> Self {
        Self {
            inputs,
            state: AnalysisState::default(),
            dirty: DirtyInputs {
                source_bytes: true,
                ..DirtyInputs::default()
            },
        }
    }

    pub fn mark_dirty(&mut self, dirty: DirtyInputs) {
        self.dirty = dirty;
    }

    pub fn refresh_plan(&self) -> crate::Result<RefreshPlan> {
        Ok(build_refresh_plan(self.dirty))
    }
}
```

Update `crates/ura-core/src/analysis/mod.rs` and `crates/ura-core/src/lib.rs` to export the new modules:

```rust
pub mod invalidation;
pub mod pass;
pub mod scheduler;
pub mod session;
```

- [ ] **Step 4: Run the focused test and verify it passes**

Run:

```bash
cargo test -p ura-core --test session_refresh refresh_plan_marks_cfg_and_downstream_passes_dirty_for_manual_function_range -- --nocapture
```

Expected: PASS with one test green.

- [ ] **Step 5: Commit the scheduler scaffolding**

Run:

```bash
git add crates/ura-core/src/lib.rs crates/ura-core/src/model.rs crates/ura-core/src/analysis/pass.rs crates/ura-core/src/analysis/invalidation.rs crates/ura-core/src/analysis/scheduler.rs crates/ura-core/src/analysis/session.rs crates/ura-core/src/analysis/mod.rs crates/ura-core/tests/session_refresh.rs crates/ura-core/tests/fixtures.rs
git commit -m "refactor: add ura-core session planning types"
```

Expected: commit succeeds and only the session-planning scaffolding is included.

---

### Task 2: Route Existing Analysis Through `AnalysisSession` And Make Reanalysis Real

**Files:**
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Modify: `crates/ura-core/src/analysis/functions.rs`
- Modify: `crates/ura-core/src/analysis/session.rs`
- Modify: `crates/ura-core/src/analysis/scheduler.rs`
- Modify: `crates/ura-core/src/commands.rs`
- Modify: `crates/ura-core/tests/session_refresh.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`

- [ ] **Step 1: Write the failing real-reanalysis test**

Append this test to `crates/ura-core/tests/session_refresh.rs`:

```rust
#[test]
fn refresh_rebuilds_functions_after_manual_range_change() {
    let loaded = fixtures::load_minimal_aarch64_image();
    let mut session = AnalysisSession::new(AnalysisInputs::from_loaded(&loaded));

    session.refresh().expect("initial refresh");
    session
        .update_manual_function_range(0x400080, 0x400080, 0x400084)
        .expect("manual range update");
    let summary = session.refresh().expect("second refresh");

    assert!(summary.ran("cfg"));
    assert!(summary.ran("functions"));
    assert!(session
        .state
        .functions
        .iter()
        .any(|func| func.addr == 0x400080 && func.start == 0x400080 && func.end == 0x400084));
}
```

In `crates/ura-core/tests/analysis_smoke.rs`, replace the existing file-backed `user_edits_persist_across_reanalysis` test with a session-based version:

```rust
#[test]
fn session_reanalysis_preserves_user_truth() -> Result<()> {
    let loaded = urloader::load(&fixtures::minimal_elf64_aarch64_executable())?;
    let mut session = ura_core::analysis::session::AnalysisSession::new(
        ura_core::analysis::session::AnalysisInputs::from_loaded(&loaded),
    );

    session.refresh()?;
    session.rename(0x400080, "manual_ret")?;
    session.comment(0x400080, "manual function")?;
    session.update_manual_function_range(0x400080, 0x400080, 0x400084)?;
    session.refresh()?;

    assert!(session
        .state
        .functions
        .iter()
        .any(|func| func.addr == 0x400080 && func.name == "manual_ret"));
    assert_eq!(
        session.inputs.user_facts.comments.get(&0x400080),
        Some(&"manual function".to_string())
    );
    Ok(())
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p ura-core --test session_refresh refresh_rebuilds_functions_after_manual_range_change -- --nocapture
cargo test -p ura-core --test analysis_smoke session_reanalysis_preserves_user_truth -- --nocapture
```

Expected: compile fails because `refresh`, `update_manual_function_range`, `rename`, `comment`, and `RefreshSummary::ran` do not exist.

- [ ] **Step 3: Implement session-backed refresh and user-fact mutations**

In `crates/ura-core/src/analysis/mod.rs`, add a helper that builds `AnalysisState` from loaded input plus user facts:

```rust
fn segments_from_loaded(segments: &[urloader::Segment]) -> Vec<crate::model::Segment> {
    segments
        .iter()
        .map(|segment| crate::model::Segment {
            id: segment.id,
            name: segment.name.clone(),
            vaddr: segment.vaddr,
            file_offset: segment.file_offset,
            file_size: segment.file_size,
            mem_size: segment.mem_size,
            permissions: segment.permissions.clone(),
        })
        .collect()
}

pub fn build_state_from_loaded(
    loaded: &urloader::LoadedImage,
    user_facts: &crate::model::UserFacts,
) -> Result<crate::model::AnalysisState> {
    let segments = segments_from_loaded(&loaded.segments);
    let target = target::AnalysisTarget::from_loaded(loaded)?;
    let image = AnalysisImage {
        target,
        entry: loaded.entry,
        bytes: &loaded.bytes,
        segments: &segments,
    };
    let user_functions = super::functions::manual_functions_from_facts(user_facts);
    let output = run_initial_analysis(&image, &user_functions)?;

    Ok(crate::model::AnalysisState {
        instructions: output.instructions,
        strings: output.strings,
        basic_blocks: output.basic_blocks,
        cfg_edges: output.cfg_edges,
        functions: output.functions,
        xrefs: output.xrefs,
        diagnostics: output.diagnostics,
    })
}
```

In `crates/ura-core/src/analysis/functions.rs`, add a helper that turns manual facts into user functions:

```rust
pub fn manual_functions_from_facts(user_facts: &crate::model::UserFacts) -> Vec<crate::model::Function> {
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
        out.push(crate::model::Function {
            addr: *addr,
            name,
            start,
            end,
            source: crate::model::FunctionSource::User,
        });
    }
    out.sort_by_key(|func| func.addr);
    out
}
```

In `crates/ura-core/src/analysis/session.rs`, extend the session API:

```rust
pub struct RefreshSummary {
    ran: Vec<crate::model::PassId>,
}

impl RefreshSummary {
    pub fn ran(&self, name: &str) -> bool {
        self.ran.iter().any(|id| id.as_str() == name)
    }
}

impl AnalysisSession {
    pub fn from_parts(inputs: AnalysisInputs, state: AnalysisState, stale: bool) -> Self {
        let mut session = Self::new(inputs);
        session.state = state;
        if stale {
            session.dirty = DirtyInputs {
                source_bytes: true,
                ..DirtyInputs::default()
            };
        }
        session
    }

    pub fn refresh(&mut self) -> crate::Result<RefreshSummary> {
        let plan = build_refresh_plan(self.dirty);
        let ran = if plan.pass_ids().is_empty() {
            Vec::new()
        } else {
            self.state = crate::analysis::build_state_from_loaded(&self.inputs.loaded, &self.inputs.user_facts)?;
            plan.clone_ids()
        };
        self.dirty = DirtyInputs::default();
        Ok(RefreshSummary { ran })
    }

    pub fn rename(&mut self, addr: u64, name: &str) -> crate::Result<()> {
        self.inputs.user_facts.renames.insert(addr, name.to_string());
        self.dirty.renames = true;
        Ok(())
    }

    pub fn comment(&mut self, addr: u64, text: &str) -> crate::Result<()> {
        self.inputs.user_facts.comments.insert(addr, text.to_string());
        self.dirty.comments = true;
        Ok(())
    }

    pub fn update_manual_function_range(
        &mut self,
        addr: u64,
        start: u64,
        end: u64,
    ) -> crate::Result<()> {
        self.inputs.user_facts.manual_function_roots.insert(addr);
        self.inputs.user_facts.manual_function_ranges.insert(addr, (start, end));
        self.dirty.manual_function_ranges = true;
        Ok(())
    }

    pub fn pass_fingerprints(&self) -> std::collections::BTreeMap<String, String> {
        std::collections::BTreeMap::from([
            ("decode".to_string(), self.state.instructions.len().to_string()),
            ("strings".to_string(), self.state.strings.len().to_string()),
            ("cfg".to_string(), self.state.basic_blocks.len().to_string()),
            ("functions".to_string(), self.state.functions.len().to_string()),
            ("xrefs".to_string(), self.state.xrefs.len().to_string()),
            ("diagnostics".to_string(), self.state.diagnostics.len().to_string()),
        ])
    }
}
```

In `crates/ura-core/src/analysis/scheduler.rs`, add:

```rust
impl RefreshPlan {
    pub fn clone_ids(&self) -> Vec<PassId> {
        self.pass_ids.clone()
    }
}
```

In `crates/ura-core/src/commands.rs`, replace file-oriented helper bodies with in-memory helpers over `AnalysisSession`. For example:

```rust
pub fn reanalyze(session: &mut AnalysisSession) -> Result<RefreshSummary> {
    session.refresh()
}
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```bash
cargo test -p ura-core --test session_refresh -- --nocapture
cargo test -p ura-core --test analysis_smoke session_reanalysis_preserves_user_truth -- --nocapture
```

Expected: PASS with session refresh, user-fact mutation, and manual range assertions green.

- [ ] **Step 5: Commit the real-refresh kernel path**

Run:

```bash
git add crates/ura-core/src/analysis/mod.rs crates/ura-core/src/analysis/session.rs crates/ura-core/src/analysis/scheduler.rs crates/ura-core/src/commands.rs crates/ura-core/tests/session_refresh.rs crates/ura-core/tests/analysis_smoke.rs
git commit -m "refactor: run ura-core analysis through sessions"
```

Expected: commit succeeds with the first real `AnalysisSession::refresh` path in place.

---

### Task 3: Add The `urastore` Truth-Plus-Cache Container

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/urastore/Cargo.toml`
- Create: `crates/urastore/src/lib.rs`
- Create: `crates/urastore/src/error.rs`
- Create: `crates/urastore/src/model.rs`
- Create: `crates/urastore/src/store.rs`
- Test: `crates/urastore/tests/store_roundtrip.rs`

- [ ] **Step 1: Write the failing store roundtrip tests**

Create `crates/urastore/tests/store_roundtrip.rs`:

```rust
use tempfile::tempdir;
use urastore::{
    load_project, save_project, AnalysisCache, CacheMetadata, ProjectSource, StoredProject,
    StoreError, UserTruth,
};

#[test]
fn stored_project_roundtrips_truth_and_cache() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sample.ura");
    let project = StoredProject {
        source: ProjectSource {
            source_bytes: vec![0x7f, b'E', b'L', b'F'],
            source_hash: "hash".to_string(),
            format: "elf".to_string(),
            architecture: "aarch64".to_string(),
            profile: "executable".to_string(),
            entry: 0x400080,
        },
        user_truth: UserTruth::default(),
        cache: AnalysisCache::default(),
        cache_metadata: CacheMetadata::fresh("0.1.0", "kernel-v1", "hash", 0),
    };

    save_project(&path, &project).unwrap();
    let loaded = load_project(&path).unwrap();

    assert_eq!(loaded.source.source_hash, "hash");
    assert_eq!(loaded.cache_metadata.source_hash_at_cache_time, "hash");
    assert!(loaded.cache_metadata.pass_fingerprints.is_empty());
}

#[test]
fn legacy_core_snapshot_is_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("legacy.ura");
    std::fs::write(&path, b"URA0legacy-body").unwrap();

    let err = load_project(&path).unwrap_err();
    assert!(matches!(err, StoreError::UnsupportedFormat(_)));
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p urastore --test store_roundtrip -- --nocapture
```

Expected: fails because package `urastore` is not in the workspace.

- [ ] **Step 3: Create `urastore` and its persistence model**

Modify root `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/urcodec",
    "crates/urdis2il",
    "crates/urloader",
    "crates/urastore",
    "crates/ura-core",
    "crates/ura-cli",
    "crates/ura-daemon",
    "crates/ura-corpus-gate",
]

[workspace.dependencies]
anyhow = "1.0"
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
bincode = "1.3"
goblin = "0.8"
urcodec = { path = "crates/urcodec" }
urdis2il = { path = "crates/urdis2il" }
urloader = { path = "crates/urloader" }
urastore = { path = "crates/urastore" }
```

Create `crates/urastore/Cargo.toml`:

```toml
[package]
name = "urastore"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
bincode.workspace = true
thiserror.workspace = true
ura-core = { path = "../ura-core" }
```

Create `crates/urastore/src/error.rs`:

```rust
use thiserror::Error;

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported project format: {0}")]
    UnsupportedFormat(String),
    #[error("decode project payload: {0}")]
    Decode(String),
    #[error("encode project payload: {0}")]
    Encode(String),
}
```

Create `crates/urastore/src/model.rs`:

```rust
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ura_core::model::{AnalysisState, UserFacts};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSource {
    pub source_bytes: Vec<u8>,
    pub source_hash: String,
    pub format: String,
    pub architecture: String,
    pub profile: String,
    pub entry: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UserTruth {
    pub facts: UserFacts,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AnalysisCache {
    pub state: AnalysisState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub schema_version: u32,
    pub engine_version: String,
    pub pass_graph_version: String,
    pub source_hash_at_cache_time: String,
    pub user_truth_revision: u64,
    pub pass_fingerprints: BTreeMap<String, String>,
}

impl CacheMetadata {
    pub fn fresh(engine_version: &str, pass_graph_version: &str, source_hash: &str, revision: u64) -> Self {
        Self {
            schema_version: 1,
            engine_version: engine_version.to_string(),
            pass_graph_version: pass_graph_version.to_string(),
            source_hash_at_cache_time: source_hash.to_string(),
            user_truth_revision: revision,
            pass_fingerprints: BTreeMap::new(),
        }
    }

    pub fn is_stale_for(&self, source: &ProjectSource, user_truth: &UserTruth) -> bool {
        self.source_hash_at_cache_time != source.source_hash
            || self.user_truth_revision != user_truth.revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredProject {
    pub source: ProjectSource,
    pub user_truth: UserTruth,
    pub cache: AnalysisCache,
    pub cache_metadata: CacheMetadata,
}
```

Create `crates/urastore/src/store.rs`:

```rust
use std::{fs, path::Path};

use crate::{error::{Result, StoreError}, model::StoredProject};

const MAGIC: &[u8; 4] = b"URS1";

pub fn save_project(path: &Path, project: &StoredProject) -> Result<()> {
    let mut out = Vec::from(*MAGIC);
    let payload = bincode::serialize(project).map_err(|err| StoreError::Encode(err.to_string()))?;
    out.extend_from_slice(&payload);
    fs::write(path, out)?;
    Ok(())
}

pub fn load_project(path: &Path) -> Result<StoredProject> {
    let bytes = fs::read(path)?;
    if bytes.get(0..4) != Some(MAGIC.as_slice()) {
        return Err(StoreError::UnsupportedFormat("expected URS1 container".to_string()));
    }
    bincode::deserialize(&bytes[4..]).map_err(|err| StoreError::Decode(err.to_string()))
}
```

Create `crates/urastore/src/lib.rs`:

```rust
pub mod error;
pub mod model;
mod store;

pub use error::{Result, StoreError};
pub use model::{AnalysisCache, CacheMetadata, ProjectSource, StoredProject, UserTruth};
pub use store::{load_project, save_project};
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```bash
cargo test -p urastore --test store_roundtrip -- --nocapture
```

Expected: PASS with roundtrip and legacy-rejection tests green.

- [ ] **Step 5: Commit the new storage crate**

Run:

```bash
git add Cargo.toml crates/urastore/Cargo.toml crates/urastore/src/lib.rs crates/urastore/src/error.rs crates/urastore/src/model.rs crates/urastore/src/store.rs crates/urastore/tests/store_roundtrip.rs
git commit -m "feat: add urastore truth and cache container"
```

Expected: commit succeeds with only the new store crate and workspace wiring.

---

### Task 4: Move CLI And Daemon Onto `urastore` Plus `AnalysisSession`

**Files:**
- Modify: `crates/ura-cli/Cargo.toml`
- Modify: `crates/ura-cli/src/main.rs`
- Modify: `crates/ura-cli/src/shell.rs`
- Modify: `crates/ura-cli/tests/cli_smoke.rs`
- Modify: `crates/ura-daemon/Cargo.toml`
- Modify: `crates/ura-daemon/src/main.rs`
- Modify: `crates/ura-daemon/tests/daemon_smoke.rs`

- [ ] **Step 1: Write the failing CLI reanalysis test**

Append this test to `crates/ura-cli/tests/cli_smoke.rs`:

```rust
#[test]
fn cli_reanalyze_rebuilds_stale_cache() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    assert_cmd::Command::cargo_bin("ura")?
        .args(["new", input.to_str().unwrap(), "-o", project.to_str().unwrap()])
        .assert()
        .success();

    let mut stored = urastore::load_project(&project)?;
    stored.cache.state.functions.clear();
    urastore::save_project(&project, &stored)?;

    assert_cmd::Command::cargo_bin("ura")?
        .args(["analyze", project.to_str().unwrap()])
        .assert()
        .success();

    let rebuilt = urastore::load_project(&project)?;
    assert!(!rebuilt.cache.state.functions.is_empty());
    Ok(())
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
cargo test -p ura-cli --test cli_smoke cli_reanalyze_rebuilds_stale_cache -- --nocapture
```

Expected: compile fails because `ura-cli` does not depend on `urastore`, and `ura analyze` still routes to file-backed `ura_core::commands::reanalyze`.

- [ ] **Step 3: Rewire CLI and daemon storage flow**

In `crates/ura-cli/Cargo.toml` and `crates/ura-daemon/Cargo.toml`, add:

```toml
urastore.workspace = true
urloader.workspace = true
```

In `crates/ura-cli/src/main.rs`, replace the file-backed `Analyze` path with session orchestration:

```rust
struct SessionProject {
    stored: urastore::StoredProject,
    session: ura_core::analysis::session::AnalysisSession,
}

fn load_session_project(project: &Path) -> Result<SessionProject> {
    let stored = urastore::load_project(project)?;
    let loaded = urloader::load(&stored.source.source_bytes)?;
    let session = ura_core::analysis::session::AnalysisSession::from_parts(
        ura_core::analysis::session::AnalysisInputs {
            loaded,
            user_facts: stored.user_truth.facts.clone(),
        },
        stored.cache.state.clone(),
        stored.cache_metadata.is_stale_for(&stored.source, &stored.user_truth),
    );
    Ok(SessionProject { stored, session })
}

fn save_session_project(project: &Path, session_project: &mut SessionProject) -> Result<()> {
    if session_project.stored.user_truth.facts != session_project.session.inputs.user_facts {
        session_project.stored.user_truth.revision += 1;
    }
    session_project.stored.cache.state = session_project.session.state.clone();
    session_project.stored.user_truth.facts = session_project.session.inputs.user_facts.clone();
    session_project.stored.cache_metadata = urastore::CacheMetadata::fresh(
        env!("CARGO_PKG_VERSION"),
        "kernel-v1",
        &session_project.stored.source.source_hash,
        session_project.stored.user_truth.revision,
    );
    session_project.stored.cache_metadata.pass_fingerprints = session_project.session.pass_fingerprints();
    urastore::save_project(project, &session_project.stored)?;
    Ok(())
}

fn analyze_project(project: &Path) -> Result<()> {
    let mut session_project = load_session_project(project)?;
    session_project.session.refresh()?;
    save_session_project(project, &mut session_project)?;
    Ok(())
}

fn rename_project_symbol(project: &Path, addr: u64, name: &str) -> Result<()> {
    let mut session_project = load_session_project(project)?;
    session_project.session.rename(addr, name)?;
    session_project.session.refresh()?;
    save_session_project(project, &mut session_project)?;
    Ok(())
}

fn print_project_info(project: &Path) -> Result<()> {
    let session_project = load_session_project(project)?;
    println!("{:#?}", session_project.session.state.functions);
    Ok(())
}
```

Replace the CLI match arms with exact helper calls in this shape:

```rust
match cli.command {
    Command::Analyze { project } => analyze_project(&project)?,
    Command::Rename { project, addr, name } => {
        rename_project_symbol(&project, parse_addr(&addr)?, &name)?
    }
    Command::Info { project, json: _ } => print_project_info(&project)?,
    Command::Funcs { project, json: _ } => {
        let session_project = load_session_project(&project)?;
        println!("{:#?}", session_project.session.state.functions);
    }
    Command::Disasm { project, addr, count, json: _ } => {
        let session_project = load_session_project(&project)?;
        let addr = parse_addr(&addr)?;
        let rows = session_project
            .session
            .state
            .instructions
            .iter()
            .filter(|insn| insn.addr >= addr)
            .take(count)
            .cloned()
            .collect::<Vec<_>>();
        println!("{:#?}", rows);
    }
    Command::Comment { project, addr, text } => {
        let mut session_project = load_session_project(&project)?;
        session_project.session.comment(parse_addr(&addr)?, &text)?;
        session_project.session.refresh()?;
        save_session_project(&project, &mut session_project)?;
    }
}
```

Add the remaining `new`, `xrefs`, `strings`, `diagnostics`, `make-func`, `set-func-range`, and `shell` arms immediately below the shown examples. Each arm must use one of these exact shapes:

- analyze-only: load session project, call `refresh()`, then save
- mutation: load session project, mutate `session`, call `refresh()`, then save
- read-only query: load session project and print/query the current `session.state`

In `crates/ura-cli/src/main.rs`, implement `new` with explicit truth creation:

```rust
fn new_project(input: &Path, output: &Path) -> Result<()> {
    let source_bytes = std::fs::read(input)?;
    let loaded = urloader::load(&source_bytes)?;
    let source_hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        source_bytes.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    };
    let mut session_project = SessionProject {
        stored: urastore::StoredProject {
            source: urastore::ProjectSource {
                source_bytes,
                source_hash: source_hash.clone(),
                format: format!("{:?}", loaded.format).to_lowercase(),
                architecture: format!("{:?}", loaded.architecture).to_lowercase(),
                profile: format!("{:?}", loaded.profile).to_lowercase(),
                entry: loaded.entry,
            },
            user_truth: urastore::UserTruth::default(),
            cache: urastore::AnalysisCache::default(),
            cache_metadata: urastore::CacheMetadata::fresh(
                env!("CARGO_PKG_VERSION"),
                "kernel-v1",
                &source_hash,
                0,
            ),
        },
        session: ura_core::analysis::session::AnalysisSession::new(
            ura_core::analysis::session::AnalysisInputs::from_loaded(&loaded),
        ),
    };
    session_project.session.mark_dirty(ura_core::analysis::invalidation::DirtyInputs {
        source_bytes: true,
        ..Default::default()
    });
    session_project.session.refresh()?;
    save_session_project(output, &mut session_project)?;
    Ok(())
}
```

In `crates/ura-cli/src/shell.rs`, replace the current direct `ura_core::commands::*` calls with a thin `ShellProject` wrapper:

```rust
struct ShellProject {
    path: PathBuf,
    stored: urastore::StoredProject,
    session: ura_core::analysis::session::AnalysisSession,
}
```

Add exact methods on `ShellProject`:

```rust
impl ShellProject {
    fn load(path: PathBuf) -> Result<Self> {
        let stored = urastore::load_project(&path)?;
        let loaded = urloader::load(&stored.source.source_bytes)?;
        let session = ura_core::analysis::session::AnalysisSession::from_parts(
            ura_core::analysis::session::AnalysisInputs {
                loaded,
                user_facts: stored.user_truth.facts.clone(),
            },
            stored.cache.state.clone(),
            stored.cache_metadata.is_stale_for(&stored.source, &stored.user_truth),
        );
        Ok(Self { path, stored, session })
    }

    fn save(&mut self) -> Result<()> {
        if self.stored.user_truth.facts != self.session.inputs.user_facts {
            self.stored.user_truth.revision += 1;
        }
        self.stored.cache.state = self.session.state.clone();
        self.stored.user_truth.facts = self.session.inputs.user_facts.clone();
        self.stored.cache_metadata = urastore::CacheMetadata::fresh(
            env!("CARGO_PKG_VERSION"),
            "kernel-v1",
            &self.stored.source.source_hash,
            self.stored.user_truth.revision,
        );
        self.stored.cache_metadata.pass_fingerprints = self.session.pass_fingerprints();
        urastore::save_project(&self.path, &self.stored)?;
        Ok(())
    }

    fn refresh_if_needed(&mut self) -> Result<()> {
        self.session.refresh()?;
        Ok(())
    }
}
```

Rewrite each shell command in this exact style:

```rust
"rename" => {
    let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
    let name = parts.next().ok_or_else(|| anyhow::anyhow!("missing name"))?;
    project.session.rename(addr, name)?;
    project.refresh_if_needed()?;
    project.save()?;
}
"info" => {
    project.refresh_if_needed()?;
    println!("{:#?}", project.session.state.functions);
}
```

In `crates/ura-daemon/src/main.rs`, replace `with_project(... ura_core::commands::...)` closures with closures that load a `SessionProject` from `urastore`, mutate or query `project.session`, and then save through `save_session_project`.
Add a concrete helper in the daemon:

```rust
fn with_session_project<F>(id: u64, path: &PathBuf, f: F) -> String
where
    F: FnOnce(&mut SessionProject) -> Result<serde_json::Value>,
{
    match load_session_project(path) {
        Ok(mut project) => match f(&mut project) {
            Ok(value) => {
                save_session_project(path, &mut project).expect("session project should save");
                serde_json::to_string(&Response::ok(id, value)).unwrap()
            }
            Err(err) => serde_json::to_string(&Response::<serde_json::Value>::err(id, err)).unwrap(),
        },
        Err(err) => serde_json::to_string(&Response::<serde_json::Value>::err(id, err)).unwrap(),
    }
}
```

Then replace each request arm with explicit session calls. Example:

```rust
Request::SetComment { id, session_id, addr, text } => with_project(id, session_id, sessions, |path| {
    with_session_project(id, path, |project| {
        project.session.comment(addr, &text)?;
        project.session.refresh()?;
        Ok(serde_json::json!({ "commented": true }))
    })
}),
```

- [ ] **Step 4: Run the focused client tests and verify they pass**

Run:

```bash
cargo test -p ura-cli --test cli_smoke -- --nocapture
cargo test -p ura-daemon --test daemon_smoke -- --nocapture
```

Expected: PASS with CLI create/analyze/info flow still working and daemon comment-writing flow still green.

- [ ] **Step 5: Commit the client rewiring**

Run:

```bash
git add crates/ura-cli/Cargo.toml crates/ura-cli/src/main.rs crates/ura-cli/src/shell.rs crates/ura-cli/tests/cli_smoke.rs crates/ura-daemon/Cargo.toml crates/ura-daemon/src/main.rs crates/ura-daemon/tests/daemon_smoke.rs
git commit -m "refactor: route cli and daemon through urastore"
```

Expected: commit succeeds and removes client dependence on file-IO helpers inside `ura-core`.

---

### Task 5: Remove Core Storage Modules And Convert Remaining Tests

**Files:**
- Delete: `crates/ura-core/src/commands.rs`
- Delete: `crates/ura-core/src/analysis/refresh.rs`
- Delete: `crates/ura-core/src/project.rs`
- Delete: `crates/ura-core/src/store.rs`
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Modify: `crates/ura-core/src/lib.rs`
- Modify: `crates/ura-core/src/error.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`
- Delete: `crates/ura-core/tests/project_roundtrip.rs`
- Delete: `crates/ura-core/tests/project_store.rs`
- Delete: `crates/ura-core/tests/refresh_policy.rs`
- Modify: `crates/urastore/tests/store_roundtrip.rs`

- [ ] **Step 1: Add the stale-cache regression test in `urastore`**

Append this test to `crates/urastore/tests/store_roundtrip.rs`:

```rust
#[test]
fn stale_cache_hash_is_reported_without_touching_user_truth() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("stale.ura");
    let mut project = StoredProject {
        source: ProjectSource {
            source_bytes: vec![0x7f, b'E', b'L', b'F'],
            source_hash: "hash-a".to_string(),
            format: "elf".to_string(),
            architecture: "aarch64".to_string(),
            profile: "executable".to_string(),
            entry: 0x400080,
        },
        user_truth: UserTruth::default(),
        cache: AnalysisCache::default(),
        cache_metadata: CacheMetadata::fresh("0.1.0", "kernel-v1", "hash-a", 0),
    };
    project.user_truth.facts.comments.insert(0x400080, "keep me".to_string());
    save_project(&path, &project).unwrap();

    let mut loaded = load_project(&path).unwrap();
    loaded.cache_metadata.source_hash_at_cache_time = "old-hash".to_string();
    save_project(&path, &loaded).unwrap();

    let reopened = load_project(&path).unwrap();
    assert!(reopened.cache_metadata.is_stale_for(&reopened.source, &reopened.user_truth));
    assert_eq!(
        reopened.user_truth.facts.comments.get(&0x400080),
        Some(&"keep me".to_string())
    );
}
```

- [ ] **Step 2: Run the focused test and verify it passes before cleanup**

Run:

```bash
cargo test -p urastore --test store_roundtrip stale_cache_hash_is_reported_without_touching_user_truth -- --nocapture
```

Expected: PASS. This regression test should stay green while the old storage path is being deleted.

- [ ] **Step 3: Delete the old file-backed core path and update tests**

Delete `crates/ura-core/src/commands.rs`, `crates/ura-core/src/analysis/refresh.rs`, `crates/ura-core/src/project.rs`, and `crates/ura-core/src/store.rs`.

In `crates/ura-core/src/lib.rs`, remove:

```rust
pub mod commands;
pub mod project;
pub mod store;
```

and replace with:

```rust
pub mod analysis;
pub mod error;
pub mod model;
```

In `crates/ura-core/src/analysis/mod.rs`, remove:

```rust
pub mod refresh;
```

Replace storage-only error variants in `crates/ura-core/src/error.rs` with these kernel errors:

```rust
#[derive(Debug, Error)]
pub enum UraError {
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("loader error: {0}")]
    Loader(String),
}
```

Delete `crates/ura-core/tests/project_roundtrip.rs`, `crates/ura-core/tests/project_store.rs`, and `crates/ura-core/tests/refresh_policy.rs`.

Move any assertions about persisted truth/cache semantics into `crates/urastore/tests/store_roundtrip.rs`. Keep `crates/ura-core/tests/analysis_smoke.rs` focused on in-memory analysis behavior only.

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```bash
cargo test -p ura-core --test analysis_smoke -- --nocapture
cargo test -p urastore --test store_roundtrip -- --nocapture
```

Expected: PASS with `ura-core` no longer compiling or testing any direct persistence code.

- [ ] **Step 5: Commit the pure-kernel boundary**

Run:

```bash
git add crates/ura-core/src/lib.rs crates/ura-core/src/analysis/mod.rs crates/ura-core/src/error.rs crates/ura-core/tests/analysis_smoke.rs crates/urastore/tests/store_roundtrip.rs
git rm crates/ura-core/src/commands.rs crates/ura-core/src/analysis/refresh.rs crates/ura-core/src/project.rs crates/ura-core/src/store.rs crates/ura-core/tests/project_roundtrip.rs crates/ura-core/tests/project_store.rs crates/ura-core/tests/refresh_policy.rs
git commit -m "refactor: remove storage from ura-core"
```

Expected: commit succeeds and leaves `ura-core` as a pure in-memory analysis crate.

---

### Task 6: Finish Verification And Update Architecture Docs

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Write the failing README architecture expectation**

Append this assertion to the end of `crates/ura-cli/tests/cli_smoke.rs`:

```rust
#[test]
fn cli_new_writes_urastore_container_magic() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    assert_cmd::Command::cargo_bin("ura")?
        .args(["new", input.to_str().unwrap(), "-o", project.to_str().unwrap()])
        .assert()
        .success();

    let bytes = std::fs::read(&project)?;
    assert_eq!(&bytes[..4], b"URS1");
    Ok(())
}
```

- [ ] **Step 2: Run the final focused test and verify it fails if docs/output drifted**

Run:

```bash
cargo test -p ura-cli --test cli_smoke cli_new_writes_urastore_container_magic -- --nocapture
```

Expected: PASS. If this test is red, fix `new` before touching the README.

- [ ] **Step 3: Update README to the new architecture**

In `README.md`, change the workspace table row and architecture text from:

```md
| `ura-core` | Stores projects and runs analysis passes. |
```

to:

```md
| `ura-core` | Pure analysis kernel: sessions, passes, invalidation, and derived analysis queries. |
| `urastore` | Persists project truth, analysis cache, and compatibility metadata. |
```

Add this paragraph below the workspace table:

```md
`ura-core` no longer owns on-disk project files. CLI and daemon entrypoints load project truth and cache through `urastore`, construct an `AnalysisSession`, refresh stale products, and then persist updated cache back through `urastore`.
```

- [ ] **Step 4: Run the full verification suite**

Run:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all three commands succeed. If `cargo clippy` reports dead-code or unused-import fallout from the kernel split, fix those before committing.

- [ ] **Step 5: Commit the documentation and final green state**

Run:

```bash
git add README.md crates/ura-cli/tests/cli_smoke.rs
git commit -m "docs: describe urastore-backed kernel architecture"
```

Expected: final commit succeeds on top of a green workspace.
