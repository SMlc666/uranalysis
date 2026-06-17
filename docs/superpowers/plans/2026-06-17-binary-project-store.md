# Binary Project Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove SQLite from Ura project persistence and replace it with a trait-backed binary `*.ura` store.

**Architecture:** `ura-core` gains a serializable `ProjectFile` model, a `ProjectStore` trait, and a `BinaryProjectStore` implementation. `Project` owns an in-memory `ProjectFile`; `commands.rs` loads, queries, mutates, and saves projects through that model while CLI and daemon APIs remain unchanged.

**Tech Stack:** Rust 2021, `serde`, `bincode`, existing `urdisassembly`, `goblin`, `clap`, `rustyline`, `serde_json` for CLI/daemon output only.

---

## File Structure

- Modify `Cargo.toml`: remove `rusqlite`, add `bincode`.
- Modify `crates/ura-core/Cargo.toml`: remove `rusqlite`, add `bincode`.
- Modify `crates/ura-core/src/error.rs`: remove SQLite error conversion and add project-format error variants.
- Modify `crates/ura-core/src/lib.rs`: remove `db` export and export the new `store` module.
- Create `crates/ura-core/src/store.rs`: `ProjectFile`, `ProjectStore`, binary header encode/decode, and `BinaryProjectStore`.
- Rewrite `crates/ura-core/src/project.rs`: replace `Connection` ownership with `ProjectFile` ownership and store-backed open/save.
- Rewrite `crates/ura-core/src/commands.rs`: replace all `db::*` calls with in-memory project operations.
- Delete `crates/ura-core/src/db.rs`: no SQLite-backed project truth remains.
- Create `crates/ura-core/tests/project_store.rs`: binary container and malformed-file tests.
- Modify `crates/ura-core/tests/project_roundtrip.rs`: remove SQLite schema-v1 migration test and keep binary roundtrip metadata tests.
- Existing tests in `crates/ura-core/tests/analysis_smoke.rs`, `crates/ura-cli/tests/cli_smoke.rs`, and `crates/ura-daemon/tests/daemon_smoke.rs` must keep passing without API changes.

---

### Task 1: Add Binary Store Red Tests

**Files:**
- Create: `crates/ura-core/tests/project_store.rs`

- [ ] **Step 1: Write the failing binary store tests**

Create `crates/ura-core/tests/project_store.rs`:

```rust
mod fixtures;

use tempfile::tempdir;
use ura_core::{commands, Result};

#[test]
fn project_file_uses_ura_binary_magic_not_sqlite_header() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    let bytes = std::fs::read(&project)?;

    assert!(bytes.starts_with(b"URA0"));
    assert!(!bytes.starts_with(b"SQLite format 3\0"));
    Ok(())
}

#[test]
fn project_file_persists_user_truth_after_reopen() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    commands::make_function(&project, 0x400080)?;
    commands::rename(&project, 0x400080, "manual_ret")?;
    commands::comment(&project, 0x400080, "manual function")?;
    commands::set_function_range(&project, 0x400080, 0x400080, 0x400084)?;

    let funcs = commands::functions(&project)?;
    let comments = commands::comments(&project, 0x400080)?;

    assert!(funcs.iter().any(|func| {
        func.addr == 0x400080
            && func.name == "manual_ret"
            && func.start == 0x400080
            && func.end == 0x400084
    }));
    assert_eq!(comments, vec!["manual function".to_string()]);
    Ok(())
}

#[test]
fn project_file_rejects_malformed_binary_headers() -> Result<()> {
    let dir = tempdir()?;
    let project = dir.path().join("bad.ura");

    std::fs::write(&project, b"SQLite format 3\0")?;
    let err = commands::info(&project).unwrap_err().to_string();
    assert!(err.contains("invalid project magic"), "{err}");

    std::fs::write(&project, b"URA")?;
    let err = commands::info(&project).unwrap_err().to_string();
    assert!(err.contains("truncated project header"), "{err}");

    let mut unsupported_version = Vec::new();
    unsupported_version.extend_from_slice(b"URA0");
    unsupported_version.extend_from_slice(&2u32.to_le_bytes());
    unsupported_version.extend_from_slice(&0u64.to_le_bytes());
    std::fs::write(&project, unsupported_version)?;
    let err = commands::info(&project).unwrap_err().to_string();
    assert!(err.contains("unsupported project container version"), "{err}");

    let mut mismatched_length = Vec::new();
    mismatched_length.extend_from_slice(b"URA0");
    mismatched_length.extend_from_slice(&1u32.to_le_bytes());
    mismatched_length.extend_from_slice(&4u64.to_le_bytes());
    std::fs::write(&project, mismatched_length)?;
    let err = commands::info(&project).unwrap_err().to_string();
    assert!(err.contains("project payload length mismatch"), "{err}");

    Ok(())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cargo test -p ura-core --test project_store
```

Expected: at least `project_file_uses_ura_binary_magic_not_sqlite_header` fails because current project files still start with the SQLite header, and malformed-header errors do not yet use binary project messages.

- [ ] **Step 3: Keep the red tests uncommitted**

Do not commit at this point. The tests intentionally fail and should be committed only after the implementation makes them pass.

Run:

```bash
git status --short
```

Expected: `crates/ura-core/tests/project_store.rs` is listed as an uncommitted new file.

---

### Task 2: Add Binary Store Primitives

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/ura-core/Cargo.toml`
- Modify: `crates/ura-core/src/error.rs`
- Modify: `crates/ura-core/src/lib.rs`
- Create: `crates/ura-core/src/store.rs`

- [ ] **Step 1: Add `bincode` and remove `rusqlite` from manifests**

In root `Cargo.toml`, change the workspace dependencies to include `bincode` and remove `rusqlite`:

```toml
[workspace.dependencies]
anyhow = "1.0"
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
bincode = "1.3"
goblin = "0.8"
urdisassembly = { path = "crates/urdisassembly" }
clap = { version = "4.5", features = ["derive"] }
rustyline = "14.0"
tempfile = "3.10"
assert_cmd = "2.0"
predicates = "3.1"
```

In `crates/ura-core/Cargo.toml`, change dependencies to:

```toml
[dependencies]
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
bincode.workspace = true
goblin.workspace = true
urdisassembly.workspace = true
```

- [ ] **Step 2: Replace SQLite errors with project-format errors**

Edit `crates/ura-core/src/error.rs` so the enum is:

```rust
use thiserror::Error;

pub type Result<T> = std::result::Result<T, UraError>;

#[derive(Debug, Error)]
pub enum UraError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ELF parse error: {0}")]
    Elf(String),
    #[error("unsupported binary: {0}")]
    Unsupported(String),
    #[error("invalid address: 0x{0:x}")]
    InvalidAddress(u64),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("project format error: {0}")]
    ProjectFormat(String),
}
```

- [ ] **Step 3: Export the store module and stop exporting db**

Edit `crates/ura-core/src/lib.rs` to:

```rust
pub mod analysis;
pub mod commands;
pub mod elf_loader;
pub mod error;
pub mod model;
pub mod project;
pub mod store;

pub use error::{Result, UraError};
```

- [ ] **Step 4: Add `ProjectFile`, `ProjectStore`, and `BinaryProjectStore`**

Create `crates/ura-core/src/store.rs`:

```rust
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    model::{
        Architecture, BinaryFormat, Diagnostic, Function, Instruction, LoadProfile, ProjectInfo,
        Section, Segment, StringRef, Symbol, Xref,
    },
    Result, UraError,
};

pub const PROJECT_MAGIC: [u8; 4] = *b"URA0";
pub const PROJECT_CONTAINER_VERSION: u32 = 1;
pub const PROJECT_SCHEMA_VERSION: i64 = 2;

const HEADER_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectFile {
    pub info: ProjectInfo,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub instructions: Vec<Instruction>,
    pub functions: Vec<Function>,
    pub xrefs: Vec<Xref>,
    pub strings: Vec<StringRef>,
    pub comments: BTreeMap<u64, String>,
    pub renames: BTreeMap<u64, String>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ProjectFile {
    pub fn empty(source_hash: impl Into<String>) -> Self {
        Self {
            info: ProjectInfo {
                schema_version: PROJECT_SCHEMA_VERSION,
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                source_hash: source_hash.into(),
                format: BinaryFormat::Elf64,
                architecture: Architecture::Aarch64,
                profile: LoadProfile::StrippedLike,
            },
            segments: Vec::new(),
            sections: Vec::new(),
            symbols: Vec::new(),
            instructions: Vec::new(),
            functions: Vec::new(),
            xrefs: Vec::new(),
            strings: Vec::new(),
            comments: BTreeMap::new(),
            renames: BTreeMap::new(),
            diagnostics: Vec::new(),
        }
    }
}

pub trait ProjectStore {
    fn load(&self, path: &Path) -> Result<ProjectFile>;
    fn save(&self, path: &Path, project: &ProjectFile) -> Result<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BinaryProjectStore;

impl ProjectStore for BinaryProjectStore {
    fn load(&self, path: &Path) -> Result<ProjectFile> {
        let bytes = fs::read(path)?;
        decode_project_file(&bytes)
    }

    fn save(&self, path: &Path, project: &ProjectFile) -> Result<()> {
        let bytes = encode_project_file(project)?;
        let tmp_path = temporary_path(path);
        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

fn encode_project_file(project: &ProjectFile) -> Result<Vec<u8>> {
    let payload = bincode::serialize(project)
        .map_err(|err| UraError::ProjectFormat(format!("encode project payload: {err}")))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&PROJECT_MAGIC);
    out.extend_from_slice(&PROJECT_CONTAINER_VERSION.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

fn decode_project_file(bytes: &[u8]) -> Result<ProjectFile> {
    if bytes.len() < HEADER_LEN {
        return Err(UraError::ProjectFormat(
            "truncated project header".to_string(),
        ));
    }
    if bytes[0..4] != PROJECT_MAGIC {
        return Err(UraError::ProjectFormat(
            "invalid project magic".to_string(),
        ));
    }

    let version = u32::from_le_bytes(bytes[4..8].try_into().expect("header length checked"));
    if version != PROJECT_CONTAINER_VERSION {
        return Err(UraError::ProjectFormat(format!(
            "unsupported project container version {version}"
        )));
    }

    let payload_len = u64::from_le_bytes(bytes[8..16].try_into().expect("header length checked"));
    let actual_len = bytes.len() - HEADER_LEN;
    if payload_len as usize != actual_len {
        return Err(UraError::ProjectFormat(format!(
            "project payload length mismatch: header={payload_len} actual={actual_len}"
        )));
    }

    bincode::deserialize(&bytes[HEADER_LEN..])
        .map_err(|err| UraError::ProjectFormat(format!("decode project payload: {err}")))
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}
```

- [ ] **Step 5: Run a focused compile check**

Run:

```bash
cargo check -p ura-core
```

Expected: fails because `project.rs` and `commands.rs` still reference `db`/`rusqlite`.

- [ ] **Step 6: Keep store primitives uncommitted until callers are rewired**

Do not commit at this point. The new store code is not useful until `Project` and `commands` stop calling SQLite-backed code.

Run:

```bash
git status --short
```

Expected: manifests, `error.rs`, `lib.rs`, and `store.rs` are listed as uncommitted changes.

---

### Task 3: Rewrite Project and Commands Over `ProjectFile`

**Files:**
- Modify: `crates/ura-core/src/project.rs`
- Modify: `crates/ura-core/src/commands.rs`

- [ ] **Step 1: Replace `Project` with a store-backed in-memory model**

Replace `crates/ura-core/src/project.rs` with:

```rust
use std::path::{Path, PathBuf};

use crate::{
    store::{BinaryProjectStore, ProjectFile, ProjectStore},
    Result, UraError,
};

pub struct Project {
    path: PathBuf,
    file: ProjectFile,
}

impl Project {
    pub fn create_empty(path: impl AsRef<Path>, source_hash: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = ProjectFile::empty(source_hash);
        BinaryProjectStore.save(&path, &file)?;
        Ok(Self { path, file })
    }

    pub fn create(path: impl AsRef<Path>, file: ProjectFile) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        BinaryProjectStore.save(&path, &file)?;
        Ok(Self { path, file })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = BinaryProjectStore.load(&path)?;
        Ok(Self { path, file })
    }

    pub fn save(&self) -> Result<()> {
        BinaryProjectStore.save(&self.path, &self.file)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut ProjectFile {
        &mut self.file
    }

    pub fn source_hash(&self) -> Result<String> {
        Ok(self.file.info.source_hash.clone())
    }

    pub fn schema_version(&self) -> Result<i64> {
        if self.file.info.schema_version <= 0 {
            return Err(UraError::ProjectFormat(format!(
                "invalid schema_version: {}",
                self.file.info.schema_version
            )));
        }
        Ok(self.file.info.schema_version)
    }
}
```

- [ ] **Step 2: Rewrite command operations against `ProjectFile`**

Replace `crates/ura-core/src/commands.rs` with:

```rust
use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::Path,
};

use crate::{
    analysis,
    elf_loader::LoadedElf,
    model::{
        Architecture, BinaryFormat, Diagnostic, Function, FunctionSource, Instruction,
        ProjectInfo, StringRef, Xref,
    },
    project::Project,
    store::{ProjectFile, PROJECT_SCHEMA_VERSION},
    Result,
};

pub fn new_project(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
    let bytes = fs::read(input)?;
    let hash = stable_hash(&bytes);
    let loaded = LoadedElf::parse(&bytes)?;
    let project_file = build_project_file(&hash, &loaded, &[])?;
    Project::create(output, project_file)?;
    Ok(())
}

pub fn info(project_path: impl AsRef<Path>) -> Result<ProjectInfo> {
    Ok(Project::open(project_path)?.file().info.clone())
}

pub fn disasm(project_path: impl AsRef<Path>, addr: u64, count: usize) -> Result<Vec<Instruction>> {
    let project = Project::open(project_path)?;
    Ok(project
        .file()
        .instructions
        .iter()
        .filter(|insn| insn.addr >= addr)
        .take(count)
        .cloned()
        .collect())
}

pub fn strings(project_path: impl AsRef<Path>, filter: Option<&str>) -> Result<Vec<StringRef>> {
    let project = Project::open(project_path)?;
    let filter = filter.unwrap_or("");
    Ok(project
        .file()
        .strings
        .iter()
        .filter(|s| s.value.contains(filter))
        .cloned()
        .collect())
}

pub fn functions(project_path: impl AsRef<Path>) -> Result<Vec<Function>> {
    Ok(Project::open(project_path)?.file().functions.clone())
}

pub fn xrefs(project_path: impl AsRef<Path>, addr: u64) -> Result<Vec<Xref>> {
    let project = Project::open(project_path)?;
    Ok(project
        .file()
        .xrefs
        .iter()
        .filter(|xref| xref.to_addr == addr || xref.from_addr == addr)
        .cloned()
        .collect())
}

pub fn rename(project_path: impl AsRef<Path>, addr: u64, name: &str) -> Result<()> {
    let mut project = Project::open(project_path)?;
    project.file_mut().renames.insert(addr, name.to_string());
    for function in &mut project.file_mut().functions {
        if function.addr == addr {
            function.name = name.to_string();
        }
    }
    project.save()
}

pub fn comment(project_path: impl AsRef<Path>, addr: u64, text: &str) -> Result<()> {
    let mut project = Project::open(project_path)?;
    project.file_mut().comments.insert(addr, text.to_string());
    project.save()
}

pub fn comments(project_path: impl AsRef<Path>, addr: u64) -> Result<Vec<String>> {
    let project = Project::open(project_path)?;
    Ok(project
        .file()
        .comments
        .get(&addr)
        .cloned()
        .into_iter()
        .collect())
}

pub fn diagnostics(project_path: impl AsRef<Path>) -> Result<Vec<Diagnostic>> {
    Ok(Project::open(project_path)?.file().diagnostics.clone())
}

pub fn make_function(project_path: impl AsRef<Path>, addr: u64) -> Result<()> {
    let mut project = Project::open(project_path)?;
    let existing_name = project
        .file()
        .functions
        .iter()
        .find(|func| func.addr == addr)
        .map(|func| func.name.clone())
        .unwrap_or_else(|| format!("sub_{addr:x}"));
    upsert_user_function(
        project.file_mut(),
        Function {
            addr,
            name: existing_name,
            start: addr,
            end: addr + 4,
            source: FunctionSource::User,
        },
    );
    project.save()
}

pub fn set_function_range(
    project_path: impl AsRef<Path>,
    function_addr: u64,
    start: u64,
    end: u64,
) -> Result<()> {
    let mut project = Project::open(project_path)?;
    let name = project
        .file()
        .functions
        .iter()
        .find(|func| func.addr == function_addr)
        .map(|func| func.name.clone())
        .unwrap_or_else(|| format!("sub_{function_addr:x}"));
    upsert_user_function(
        project.file_mut(),
        Function {
            addr: function_addr,
            name,
            start,
            end,
            source: FunctionSource::User,
        },
    );
    project.save()
}

pub fn reanalyze(project_path: impl AsRef<Path>) -> Result<()> {
    let project = Project::open(project_path)?;
    project.save()
}

fn build_project_file(
    source_hash: &str,
    loaded: &LoadedElf,
    user_functions: &[Function],
) -> Result<ProjectFile> {
    let analysis = analysis::run_initial_analysis(loaded, user_functions)?;
    Ok(ProjectFile {
        info: ProjectInfo {
            schema_version: PROJECT_SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            source_hash: source_hash.to_string(),
            format: BinaryFormat::Elf64,
            architecture: Architecture::Aarch64,
            profile: loaded.profile,
        },
        segments: loaded.segments.clone(),
        sections: loaded.sections.clone(),
        symbols: loaded.symbols.clone(),
        instructions: analysis.instructions,
        functions: analysis.functions,
        xrefs: analysis.xrefs,
        strings: analysis.strings,
        comments: Default::default(),
        renames: Default::default(),
        diagnostics: analysis.diagnostics,
    })
}

fn upsert_user_function(project: &mut ProjectFile, function: Function) {
    project.functions.retain(|func| func.addr != function.addr);
    project.functions.push(function);
    project.functions.sort_by_key(|func| func.addr);
}

fn stable_hash(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
```

- [ ] **Step 3: Run the binary store tests**

Run:

```bash
cargo test -p ura-core --test project_store
```

Expected: all tests in `project_store.rs` pass.

- [ ] **Step 4: Run core roundtrip and analysis tests**

Run:

```bash
cargo test -p ura-core --test analysis_smoke --test project_roundtrip
```

Expected: `analysis_smoke` passes. `project_roundtrip` still fails to compile because it contains the old SQLite schema-v1 migration test; that is removed in the next task.

- [ ] **Step 5: Commit the first green binary-store slice**

Run:

```bash
git add Cargo.toml Cargo.lock crates/ura-core/Cargo.toml
git add crates/ura-core/src/error.rs crates/ura-core/src/lib.rs crates/ura-core/src/store.rs
git add crates/ura-core/src/project.rs crates/ura-core/src/commands.rs
git add crates/ura-core/tests/project_store.rs
git commit -m "feat: persist projects through binary store"
```

Expected: commit succeeds after the new binary-store tests pass.

---

### Task 4: Remove SQLite Code and Update Roundtrip Tests

**Files:**
- Delete: `crates/ura-core/src/db.rs`
- Modify: `crates/ura-core/tests/project_roundtrip.rs`

- [ ] **Step 1: Delete the SQLite database module**

Run:

```bash
git rm crates/ura-core/src/db.rs
```

Expected: `crates/ura-core/src/db.rs` is removed from the index.

- [ ] **Step 2: Replace the old migration test with binary container checks**

Replace `crates/ura-core/tests/project_roundtrip.rs` with:

```rust
mod fixtures;

use tempfile::tempdir;
use ura_core::{commands, model::LoadProfile, project::Project, Result};

#[test]
fn creates_and_reopens_empty_project() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("sample.ura");

    let project = Project::create_empty(&path, "hash-for-test")?;
    assert_eq!(project.source_hash()?, "hash-for-test");
    drop(project);

    let reopened = Project::open(&path)?;
    assert_eq!(reopened.source_hash()?, "hash-for-test");
    assert_eq!(reopened.schema_version()?, 2);
    Ok(())
}

#[test]
fn creates_project_from_elf_and_persists_metadata() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project_path = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project_path)?;
    let info = commands::info(&project_path)?;

    assert_eq!(info.profile, LoadProfile::Executable);
    assert_eq!(info.architecture, ura_core::model::Architecture::Aarch64);
    Ok(())
}

#[test]
fn project_schema_v2_records_decode_metadata() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    let info = commands::info(&project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;

    assert_eq!(info.schema_version, 2);
    assert_eq!(disasm[0].text, "ret");
    assert_eq!(disasm[0].kind, "Return");
    assert_eq!(disasm[0].flow, "Return");
    assert_eq!(disasm[0].decode_status, "Complete");
    assert_eq!(disasm[0].decoder, "urdisassembly/aarch64");
    assert_eq!(disasm[0].decoder_version, env!("CARGO_PKG_VERSION"));
    Ok(())
}

#[test]
fn binary_project_rejects_old_sqlite_header() -> Result<()> {
    let dir = tempdir()?;
    let project = dir.path().join("old.ura");
    std::fs::write(&project, b"SQLite format 3\0")?;

    let err = commands::info(&project).unwrap_err().to_string();

    assert!(err.contains("invalid project magic"), "{err}");
    Ok(())
}
```

- [ ] **Step 3: Verify no SQLite references remain in production code**

Run:

```bash
rg -n "rusqlite|db::|pub mod db" Cargo.toml Cargo.lock crates/ura-core/src crates/ura-cli/src crates/ura-daemon/src
```

Expected: no matches in production code, manifests, or lockfile.

- [ ] **Step 4: Run core tests**

Run:

```bash
cargo test -p ura-core
```

Expected: all `ura-core` tests pass.

- [ ] **Step 5: Commit SQLite removal**

Run:

```bash
git add Cargo.toml crates/ura-core/Cargo.toml Cargo.lock crates/ura-core/tests/project_roundtrip.rs
git add -u crates/ura-core/src
git commit -m "refactor: remove sqlite project storage"
```

Expected: commit succeeds and removes `db.rs`.

---

### Task 5: Verify CLI and Daemon Compatibility

**Files:**
- No production files expected.
- Existing tests: `crates/ura-cli/tests/cli_smoke.rs`, `crates/ura-daemon/tests/daemon_smoke.rs`

- [ ] **Step 1: Run CLI smoke test**

Run:

```bash
cargo test -p ura-cli --test cli_smoke
```

Expected: `cli_creates_project_and_prints_info` passes, proving `ura new` and `ura info` still work through the command API.

- [ ] **Step 2: Run daemon smoke test**

Run:

```bash
cargo test -p ura-daemon --test daemon_smoke
```

Expected: `daemon_opens_project_and_writes_comment` passes, proving the daemon can open the new binary `*.ura` and persist a comment through `ura-core`.

- [ ] **Step 3: Run all workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: all workspace tests pass.

- [ ] **Step 4: Commit compatibility confirmation if any tests needed updates**

If CLI or daemon tests required source changes, commit them:

```bash
git add crates/ura-cli crates/ura-daemon Cargo.lock
git commit -m "test: keep clients compatible with binary projects"
```

Expected: commit only if files changed. If no files changed, skip this commit.

---

### Task 6: Final Quality Gate

**Files:**
- No production files expected.

- [ ] **Step 1: Run format check**

Run:

```bash
cargo fmt -- --check
```

Expected: exits successfully with no diff.

- [ ] **Step 2: Run strict clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: exits successfully with no warnings.

- [ ] **Step 3: Run full test suite once more**

Run:

```bash
cargo test --workspace
```

Expected: all tests pass.

- [ ] **Step 4: Confirm dependency graph no longer includes SQLite**

Run:

```bash
cargo tree --workspace | rg "rusqlite" || true
```

Expected: no output, proving `rusqlite` is not present in the workspace dependency graph.

- [ ] **Step 5: Inspect final git status**

Run:

```bash
git status --short
```

Expected: no uncommitted changes unless the user requested no commits during execution.

---

## Self-Review Notes

- Spec coverage: removes SQLite, uses binary `*.ura`, keeps `ProjectStore`, rejects JSON, preserves CLI/daemon command behavior.
- Scope: no SQLite migration, no chunk table, no analysis-quality changes.
- Test order: new binary tests fail before implementation, then implementation makes them pass.
- Type consistency: `ProjectFile`, `ProjectStore`, `BinaryProjectStore`, and `PROJECT_SCHEMA_VERSION` are introduced before use in `Project` and `commands`.
