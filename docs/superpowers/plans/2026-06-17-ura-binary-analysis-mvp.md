# Ura Binary Analysis MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first usable Ura MVP: a reusable Rust engine that opens ELF64 AArch64 binaries, creates `*.ura` SQLite projects, runs basic analysis, supports user edits and reanalysis, exposes batch/shell CLI commands, and provides a thin daemon API.

**Architecture:** Use a core-first Rust workspace. `ura-core` owns project files and analysis truth, `ura-cli` links directly to `ura-core`, and `ura-daemon` wraps `ura-core` behind a small line-delimited JSON-RPC protocol. SQLite is the first project database because it gives migrations, transactions, and inspectable state without a custom storage format.

**Tech Stack:** Rust 2021, Cargo workspace, `rusqlite` with bundled SQLite, `goblin` for ELF parsing, `capstone` for ARM64 disassembly, `clap` for CLI, `rustyline` for shell, `serde`/`serde_json` for structured output and daemon protocol, `tempfile` for tests.

---

## Scope Notes

This plan implements the approved MVP spec at `docs/superpowers/specs/2026-06-17-ura-binary-analysis-design.md`.

The current directory is not a Git repository. Commit steps are included because the plan is intended for a normal development branch, but they should be skipped or replaced with local checkpoints until a repository is initialized.

## File Structure

Create this workspace:

- `Cargo.toml`: workspace members and shared package metadata.
- `crates/ura-core/Cargo.toml`: core engine dependencies.
- `crates/ura-core/src/lib.rs`: public module exports and shared `Result` type.
- `crates/ura-core/src/error.rs`: error enum used across core.
- `crates/ura-core/src/model.rs`: core IDs and structs for metadata, segments, functions, instructions, xrefs, strings, diagnostics, and user edits.
- `crates/ura-core/src/project.rs`: high-level project open/create/save transaction API.
- `crates/ura-core/src/db.rs`: SQLite schema creation, migrations, and typed database helpers.
- `crates/ura-core/src/elf_loader.rs`: ELF64 AArch64 validation, metadata extraction, VA mapping, and profile detection.
- `crates/ura-core/src/analysis/mod.rs`: analysis pass orchestration.
- `crates/ura-core/src/analysis/disasm.rs`: ARM64 linear disassembly pass.
- `crates/ura-core/src/analysis/functions.rs`: function seed and recursive basic-block pass.
- `crates/ura-core/src/analysis/xrefs.rs`: code/data/string xref pass.
- `crates/ura-core/src/analysis/strings.rs`: string extraction pass.
- `crates/ura-core/src/analysis/diagnostics.rs`: diagnostic helpers.
- `crates/ura-core/src/commands.rs`: stable command/query API shared by CLI and daemon.
- `crates/ura-core/tests/project_roundtrip.rs`: project creation and persistence tests.
- `crates/ura-core/tests/elf_loader.rs`: loader tests.
- `crates/ura-core/tests/analysis_smoke.rs`: analysis tests.
- `crates/ura-core/tests/fixtures.rs`: small fixture builders used by tests.
- `crates/ura-cli/Cargo.toml`: CLI dependencies.
- `crates/ura-cli/src/main.rs`: batch command entrypoint.
- `crates/ura-cli/src/output.rs`: text and JSON rendering helpers.
- `crates/ura-cli/src/shell.rs`: interactive shell.
- `crates/ura-cli/tests/cli_smoke.rs`: CLI integration tests.
- `crates/ura-daemon/Cargo.toml`: daemon dependencies.
- `crates/ura-daemon/src/main.rs`: TCP listener and request loop.
- `crates/ura-daemon/src/protocol.rs`: request/response schema.
- `crates/ura-daemon/tests/daemon_smoke.rs`: external-client daemon test.

## Task 1: Create Rust Workspace Skeleton

**Files:**
- Create: `Cargo.toml`
- Create: `crates/ura-core/Cargo.toml`
- Create: `crates/ura-core/src/lib.rs`
- Create: `crates/ura-core/src/error.rs`
- Create: `crates/ura-cli/Cargo.toml`
- Create: `crates/ura-cli/src/main.rs`
- Create: `crates/ura-daemon/Cargo.toml`
- Create: `crates/ura-daemon/src/main.rs`

- [ ] **Step 1: Write the workspace manifests**

Create `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/ura-core",
    "crates/ura-cli",
    "crates/ura-daemon",
]
resolver = "2"

[workspace.package]
edition = "2021"
license = "MIT"
version = "0.1.0"

[workspace.dependencies]
anyhow = "1.0"
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rusqlite = { version = "0.31", features = ["bundled"] }
goblin = "0.8"
capstone = "0.12"
clap = { version = "4.5", features = ["derive"] }
rustyline = "14.0"
tempfile = "3.10"
assert_cmd = "2.0"
predicates = "3.1"
```

Create `crates/ura-core/Cargo.toml`:

```toml
[package]
name = "ura-core"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
rusqlite.workspace = true
goblin.workspace = true
capstone.workspace = true
```

Create `crates/ura-cli/Cargo.toml`:

```toml
[package]
name = "ura-cli"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "ura"
path = "src/main.rs"

[dependencies]
anyhow.workspace = true
clap.workspace = true
rustyline.workspace = true
serde_json.workspace = true
ura-core = { path = "../ura-core" }

[dev-dependencies]
assert_cmd.workspace = true
predicates.workspace = true
tempfile.workspace = true
```

Create `crates/ura-daemon/Cargo.toml`:

```toml
[package]
name = "ura-daemon"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "ura-daemon"
path = "src/main.rs"

[dependencies]
anyhow.workspace = true
serde.workspace = true
serde_json.workspace = true
ura-core = { path = "../ura-core" }

[dev-dependencies]
tempfile.workspace = true
```

- [ ] **Step 2: Add minimal compilable source files**

Create `crates/ura-core/src/error.rs`:

```rust
use thiserror::Error;

pub type Result<T> = std::result::Result<T, UraError>;

#[derive(Debug, Error)]
pub enum UraError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
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
}
```

Create `crates/ura-core/src/lib.rs`:

```rust
pub mod error;

pub use error::{Result, UraError};
```

Create `crates/ura-cli/src/main.rs`:

```rust
fn main() {
    println!("ura CLI skeleton");
}
```

Create `crates/ura-daemon/src/main.rs`:

```rust
fn main() {
    println!("ura-daemon skeleton");
}
```

- [ ] **Step 3: Verify workspace compiles**

Run:

```bash
cargo check --workspace
```

Expected: command exits successfully and checks `ura-core`, `ura-cli`, and `ura-daemon`.

- [ ] **Step 4: Commit**

Run:

```bash
git add Cargo.toml crates
git commit -m "chore: create ura rust workspace"
```

Expected: commit succeeds in a Git repository. If the checkout is still not a Git repository, record the changed files as a local checkpoint instead.

## Task 2: Define Core Data Model

**Files:**
- Create: `crates/ura-core/src/model.rs`
- Modify: `crates/ura-core/src/lib.rs`

- [ ] **Step 1: Write the model definitions**

Create `crates/ura-core/src/model.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadProfile {
    SharedObject,
    Executable,
    Relocatable,
    KernelStyle,
    StrippedLike,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub schema_version: i64,
    pub engine_version: String,
    pub source_hash: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub profile: LoadProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub id: i64,
    pub name: String,
    pub vaddr: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub id: i64,
    pub name: String,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub id: i64,
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: String,
    pub is_import: bool,
    pub is_export: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub addr: u64,
    pub size: u8,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub fallthrough: Option<u64>,
    pub branch_target: Option<u64>,
    pub function_addr: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    pub addr: u64,
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub source: FunctionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionSource {
    Symbol,
    Entry,
    BranchTarget,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: i64,
    pub function_addr: u64,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XrefKind {
    Code,
    Call,
    Data,
    String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Xref {
    pub from_addr: u64,
    pub to_addr: u64,
    pub kind: XrefKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringRef {
    pub addr: u64,
    pub value: String,
    pub encoding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub addr: Option<u64>,
    pub severity: String,
    pub message: String,
}
```

Modify `crates/ura-core/src/lib.rs`:

```rust
pub mod error;
pub mod model;

pub use error::{Result, UraError};
```

- [ ] **Step 2: Verify model compiles**

Run:

```bash
cargo check -p ura-core
```

Expected: command exits successfully.

- [ ] **Step 3: Commit**

Run:

```bash
git add crates/ura-core/src/lib.rs crates/ura-core/src/model.rs
git commit -m "feat: define core analysis model"
```

Expected: commit succeeds in a Git repository. If there is no Git repository, keep the local checkpoint.

## Task 3: Implement SQLite Project Store

**Files:**
- Create: `crates/ura-core/src/db.rs`
- Create: `crates/ura-core/src/project.rs`
- Modify: `crates/ura-core/src/lib.rs`
- Create: `crates/ura-core/tests/project_roundtrip.rs`

- [ ] **Step 1: Write the failing roundtrip test**

Create `crates/ura-core/tests/project_roundtrip.rs`:

```rust
use tempfile::tempdir;
use ura_core::{project::Project, Result};

#[test]
fn creates_and_reopens_empty_project() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("sample.ura");

    let project = Project::create_empty(&path, "hash-for-test")?;
    assert_eq!(project.source_hash()?, "hash-for-test");
    drop(project);

    let reopened = Project::open(&path)?;
    assert_eq!(reopened.source_hash()?, "hash-for-test");
    assert_eq!(reopened.schema_version()?, 1);
    Ok(())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p ura-core --test project_roundtrip creates_and_reopens_empty_project -- --nocapture
```

Expected: compile fails because `project::Project` is not defined.

- [ ] **Step 3: Implement database schema and project wrapper**

Create `crates/ura-core/src/db.rs`:

```rust
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::Result;

pub const SCHEMA_VERSION: i64 = 1;

pub fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(conn)
}

pub fn initialize(conn: &Connection, source_hash: &str) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS segments (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            vaddr INTEGER NOT NULL,
            file_offset INTEGER NOT NULL,
            file_size INTEGER NOT NULL,
            mem_size INTEGER NOT NULL,
            permissions TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sections (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            addr INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            size INTEGER NOT NULL,
            flags INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS symbols (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            addr INTEGER NOT NULL,
            size INTEGER NOT NULL,
            kind TEXT NOT NULL,
            is_import INTEGER NOT NULL,
            is_export INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS instructions (
            addr INTEGER PRIMARY KEY,
            size INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            mnemonic TEXT NOT NULL,
            operands TEXT NOT NULL,
            fallthrough INTEGER,
            branch_target INTEGER,
            function_addr INTEGER
        );
        CREATE TABLE IF NOT EXISTS functions (
            addr INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            start INTEGER NOT NULL,
            end INTEGER NOT NULL,
            source TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS basic_blocks (
            id INTEGER PRIMARY KEY,
            function_addr INTEGER NOT NULL,
            start INTEGER NOT NULL,
            end INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS xrefs (
            from_addr INTEGER NOT NULL,
            to_addr INTEGER NOT NULL,
            kind TEXT NOT NULL,
            PRIMARY KEY (from_addr, to_addr, kind)
        );
        CREATE TABLE IF NOT EXISTS strings (
            addr INTEGER PRIMARY KEY,
            value TEXT NOT NULL,
            encoding TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS comments (
            addr INTEGER PRIMARY KEY,
            text TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS renames (
            addr INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS diagnostics (
            id INTEGER PRIMARY KEY,
            addr INTEGER,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        );
        ",
    )?;
    set_metadata(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
    set_metadata(conn, "engine_version", env!("CARGO_PKG_VERSION"))?;
    set_metadata(conn, "source_hash", source_hash)?;
    Ok(())
}

pub fn set_metadata(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO metadata(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn get_metadata(conn: &Connection, key: &str) -> Result<Option<String>> {
    let value = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(value)
}
```

Create `crates/ura-core/src/project.rs`:

```rust
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::{db, Result, UraError};

pub struct Project {
    path: PathBuf,
    conn: Connection,
}

impl Project {
    pub fn create_empty(path: impl AsRef<Path>, source_hash: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = db::open_connection(&path)?;
        db::initialize(&conn, source_hash)?;
        Ok(Self { path, conn })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = db::open_connection(&path)?;
        let version = db::get_metadata(&conn, "schema_version")?
            .ok_or_else(|| UraError::NotFound("schema_version metadata".to_string()))?;
        if version != db::SCHEMA_VERSION.to_string() {
            return Err(UraError::Unsupported(format!(
                "schema version {version}, expected {}",
                db::SCHEMA_VERSION
            )));
        }
        Ok(Self { path, conn })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn source_hash(&self) -> Result<String> {
        db::get_metadata(&self.conn, "source_hash")?
            .ok_or_else(|| UraError::NotFound("source_hash metadata".to_string()))
    }

    pub fn schema_version(&self) -> Result<i64> {
        let value = db::get_metadata(&self.conn, "schema_version")?
            .ok_or_else(|| UraError::NotFound("schema_version metadata".to_string()))?;
        value
            .parse::<i64>()
            .map_err(|err| UraError::Unsupported(format!("invalid schema_version: {err}")))
    }
}
```

Modify `crates/ura-core/src/lib.rs`:

```rust
pub mod db;
pub mod error;
pub mod model;
pub mod project;

pub use error::{Result, UraError};
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cargo test -p ura-core --test project_roundtrip creates_and_reopens_empty_project -- --nocapture
```

Expected: test passes.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-core/src crates/ura-core/tests/project_roundtrip.rs
git commit -m "feat: add sqlite project store"
```

Expected: commit succeeds in a Git repository. If there is no Git repository, keep the local checkpoint.

## Task 4: Implement ELF64 AArch64 Loader

**Files:**
- Create: `crates/ura-core/src/elf_loader.rs`
- Modify: `crates/ura-core/src/lib.rs`
- Create: `crates/ura-core/tests/fixtures.rs`
- Create: `crates/ura-core/tests/elf_loader.rs`

- [ ] **Step 1: Write loader tests**

Create `crates/ura-core/tests/fixtures.rs`:

```rust
pub fn minimal_elf64_aarch64_executable() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x1000];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&183u16.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&0x400080u64.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    bytes[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let ph = 0x40usize;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes
}
```

Create `crates/ura-core/tests/elf_loader.rs`:

```rust
mod fixtures;

use ura_core::{elf_loader::LoadedElf, model::LoadProfile, Result};

#[test]
fn loads_minimal_aarch64_executable() -> Result<()> {
    let bytes = fixtures::minimal_elf64_aarch64_executable();
    let loaded = LoadedElf::parse(&bytes)?;

    assert_eq!(loaded.entry, 0x400080);
    assert_eq!(loaded.profile, LoadProfile::Executable);
    assert_eq!(loaded.segments.len(), 1);
    assert_eq!(loaded.segments[0].vaddr, 0x400000);
    assert_eq!(loaded.va_to_offset(0x400080), Some(0x80));
    assert_eq!(loaded.executable_ranges(), vec![(0x400000, 0x401000)]);
    Ok(())
}
```

- [ ] **Step 2: Run loader test to verify it fails**

Run:

```bash
cargo test -p ura-core --test elf_loader loads_minimal_aarch64_executable -- --nocapture
```

Expected: compile fails because `elf_loader::LoadedElf` is not defined.

- [ ] **Step 3: Implement loader**

Create `crates/ura-core/src/elf_loader.rs`:

```rust
use goblin::elf::{header, program_header, Elf};

use crate::{
    model::{Architecture, BinaryFormat, LoadProfile, Section, Segment, Symbol},
    Result, UraError,
};

#[derive(Debug, Clone)]
pub struct LoadedElf {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub profile: LoadProfile,
    pub entry: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub bytes: Vec<u8>,
}

impl LoadedElf {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let elf = Elf::parse(bytes).map_err(|err| UraError::Elf(err.to_string()))?;
        if elf.header.e_ident[header::EI_CLASS] != header::ELFCLASS64 {
            return Err(UraError::Unsupported("expected ELF64".to_string()));
        }
        if elf.header.e_machine != header::EM_AARCH64 {
            return Err(UraError::Unsupported("expected AArch64 ELF".to_string()));
        }
        if elf.little_endian != true {
            return Err(UraError::Unsupported("expected little-endian ELF".to_string()));
        }

        let profile = match elf.header.e_type {
            header::ET_DYN => LoadProfile::SharedObject,
            header::ET_EXEC => LoadProfile::Executable,
            header::ET_REL => LoadProfile::Relocatable,
            _ => LoadProfile::StrippedLike,
        };

        let segments = elf
            .program_headers
            .iter()
            .enumerate()
            .filter(|(_, ph)| ph.p_type == program_header::PT_LOAD)
            .map(|(idx, ph)| Segment {
                id: idx as i64,
                name: format!("LOAD_{idx}"),
                vaddr: ph.p_vaddr,
                file_offset: ph.p_offset,
                file_size: ph.p_filesz,
                mem_size: ph.p_memsz,
                permissions: permissions(ph.p_flags),
            })
            .collect::<Vec<_>>();

        let sections = elf
            .section_headers
            .iter()
            .enumerate()
            .map(|(idx, sh)| Section {
                id: idx as i64,
                name: elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string(),
                addr: sh.sh_addr,
                offset: sh.sh_offset,
                size: sh.sh_size,
                flags: sh.sh_flags,
            })
            .collect::<Vec<_>>();

        let mut symbols = Vec::new();
        for sym in elf.syms.iter() {
            if sym.st_value == 0 {
                continue;
            }
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
            symbols.push(Symbol {
                id: symbols.len() as i64,
                name,
                addr: sym.st_value,
                size: sym.st_size,
                kind: format!("{:?}", sym.st_type()),
                is_import: false,
                is_export: sym.is_function(),
            });
        }
        for sym in elf.dynsyms.iter() {
            let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
            symbols.push(Symbol {
                id: symbols.len() as i64,
                name,
                addr: sym.st_value,
                size: sym.st_size,
                kind: format!("{:?}", sym.st_type()),
                is_import: sym.st_value == 0,
                is_export: sym.st_value != 0,
            });
        }

        Ok(Self {
            format: BinaryFormat::Elf64,
            architecture: Architecture::Aarch64,
            profile,
            entry: elf.entry,
            segments,
            sections,
            symbols,
            bytes: bytes.to_vec(),
        })
    }

    pub fn va_to_offset(&self, addr: u64) -> Option<u64> {
        self.segments.iter().find_map(|seg| {
            let end = seg.vaddr.checked_add(seg.file_size)?;
            if addr >= seg.vaddr && addr < end {
                Some(seg.file_offset + (addr - seg.vaddr))
            } else {
                None
            }
        })
    }

    pub fn executable_ranges(&self) -> Vec<(u64, u64)> {
        self.segments
            .iter()
            .filter(|seg| seg.permissions.contains('x'))
            .map(|seg| (seg.vaddr, seg.vaddr + seg.mem_size))
            .collect()
    }

    pub fn bytes_at(&self, addr: u64, size: usize) -> Option<&[u8]> {
        let offset = self.va_to_offset(addr)? as usize;
        self.bytes.get(offset..offset.checked_add(size)?)
    }
}

fn permissions(flags: u32) -> String {
    let mut out = String::new();
    out.push(if flags & program_header::PF_R != 0 { 'r' } else { '-' });
    out.push(if flags & program_header::PF_W != 0 { 'w' } else { '-' });
    out.push(if flags & program_header::PF_X != 0 { 'x' } else { '-' });
    out
}
```

Modify `crates/ura-core/src/lib.rs`:

```rust
pub mod db;
pub mod elf_loader;
pub mod error;
pub mod model;
pub mod project;

pub use error::{Result, UraError};
```

- [ ] **Step 4: Run loader test to verify it passes**

Run:

```bash
cargo test -p ura-core --test elf_loader loads_minimal_aarch64_executable -- --nocapture
```

Expected: test passes.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-core/src crates/ura-core/tests
git commit -m "feat: load elf64 aarch64 binaries"
```

Expected: commit succeeds in a Git repository. If there is no Git repository, keep the local checkpoint.

## Task 5: Persist Loader Output Into Project DB

**Files:**
- Modify: `crates/ura-core/src/project.rs`
- Modify: `crates/ura-core/src/db.rs`
- Create: `crates/ura-core/src/commands.rs`
- Modify: `crates/ura-core/src/lib.rs`
- Modify: `crates/ura-core/tests/project_roundtrip.rs`

- [ ] **Step 1: Write failing project creation test**

Append to `crates/ura-core/tests/project_roundtrip.rs`:

```rust
mod fixtures;

use ura_core::commands;

#[test]
fn creates_project_from_elf_and_persists_metadata() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project_path = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project_path)?;
    let info = commands::info(&project_path)?;

    assert_eq!(info.profile, ura_core::model::LoadProfile::Executable);
    assert_eq!(info.architecture, ura_core::model::Architecture::Aarch64);
    Ok(())
}
```

If the duplicate `mod fixtures;` placement causes a compile error, move it to the top of the file so the file has a single `mod fixtures;` declaration.

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p ura-core --test project_roundtrip creates_project_from_elf_and_persists_metadata -- --nocapture
```

Expected: compile fails because `commands::new_project` and `commands::info` are not defined.

- [ ] **Step 3: Implement project import commands and persistence helpers**

Extend `crates/ura-core/src/db.rs` with these functions:

```rust
use crate::model::{Architecture, BinaryFormat, LoadProfile, ProjectInfo, Section, Segment, Symbol};

pub fn insert_segments(conn: &Connection, segments: &[Segment]) -> Result<()> {
    conn.execute("DELETE FROM segments", [])?;
    for segment in segments {
        conn.execute(
            "INSERT INTO segments(id, name, vaddr, file_offset, file_size, mem_size, permissions)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                segment.id,
                segment.name,
                segment.vaddr,
                segment.file_offset,
                segment.file_size,
                segment.mem_size,
                segment.permissions
            ],
        )?;
    }
    Ok(())
}

pub fn insert_sections(conn: &Connection, sections: &[Section]) -> Result<()> {
    conn.execute("DELETE FROM sections", [])?;
    for section in sections {
        conn.execute(
            "INSERT INTO sections(id, name, addr, offset, size, flags)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![section.id, section.name, section.addr, section.offset, section.size, section.flags],
        )?;
    }
    Ok(())
}

pub fn insert_symbols(conn: &Connection, symbols: &[Symbol]) -> Result<()> {
    conn.execute("DELETE FROM symbols", [])?;
    for symbol in symbols {
        conn.execute(
            "INSERT INTO symbols(id, name, addr, size, kind, is_import, is_export)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                symbol.id,
                symbol.name,
                symbol.addr,
                symbol.size,
                symbol.kind,
                symbol.is_import as i64,
                symbol.is_export as i64
            ],
        )?;
    }
    Ok(())
}

pub fn project_info(conn: &Connection) -> Result<ProjectInfo> {
    let schema_version = get_metadata(conn, "schema_version")?
        .unwrap_or_else(|| "1".to_string())
        .parse::<i64>()
        .map_err(|err| crate::UraError::Unsupported(format!("invalid schema_version: {err}")))?;
    let engine_version = get_metadata(conn, "engine_version")?.unwrap_or_default();
    let source_hash = get_metadata(conn, "source_hash")?.unwrap_or_default();
    let profile = match get_metadata(conn, "profile")?.as_deref() {
        Some("SharedObject") => LoadProfile::SharedObject,
        Some("Relocatable") => LoadProfile::Relocatable,
        Some("KernelStyle") => LoadProfile::KernelStyle,
        Some("StrippedLike") => LoadProfile::StrippedLike,
        _ => LoadProfile::Executable,
    };
    Ok(ProjectInfo {
        schema_version,
        engine_version,
        source_hash,
        format: BinaryFormat::Elf64,
        architecture: Architecture::Aarch64,
        profile,
    })
}
```

Create `crates/ura-core/src/commands.rs`:

```rust
use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::Path,
};

use crate::{db, elf_loader::LoadedElf, model::ProjectInfo, project::Project, Result};

pub fn new_project(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
    let bytes = fs::read(input)?;
    let hash = stable_hash(&bytes);
    let loaded = LoadedElf::parse(&bytes)?;
    let mut project = Project::create_empty(output, &hash)?;
    db::set_metadata(project.conn(), "profile", &format!("{:?}", loaded.profile))?;
    db::insert_segments(project.conn_mut(), &loaded.segments)?;
    db::insert_sections(project.conn_mut(), &loaded.sections)?;
    db::insert_symbols(project.conn_mut(), &loaded.symbols)?;
    Ok(())
}

pub fn info(project_path: impl AsRef<Path>) -> Result<ProjectInfo> {
    let project = Project::open(project_path)?;
    db::project_info(project.conn())
}

fn stable_hash(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
```

Modify `crates/ura-core/src/lib.rs`:

```rust
pub mod commands;
pub mod db;
pub mod elf_loader;
pub mod error;
pub mod model;
pub mod project;

pub use error::{Result, UraError};
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cargo test -p ura-core --test project_roundtrip creates_project_from_elf_and_persists_metadata -- --nocapture
```

Expected: test passes.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-core/src crates/ura-core/tests/project_roundtrip.rs
git commit -m "feat: persist loaded elf projects"
```

Expected: commit succeeds in a Git repository. If there is no Git repository, keep the local checkpoint.

## Task 6: Add Linear Disassembly And String Extraction

**Files:**
- Create: `crates/ura-core/src/analysis/mod.rs`
- Create: `crates/ura-core/src/analysis/disasm.rs`
- Create: `crates/ura-core/src/analysis/strings.rs`
- Modify: `crates/ura-core/src/db.rs`
- Modify: `crates/ura-core/src/commands.rs`
- Modify: `crates/ura-core/src/lib.rs`
- Create: `crates/ura-core/tests/analysis_smoke.rs`

- [ ] **Step 1: Write failing analysis smoke test**

Create `crates/ura-core/tests/analysis_smoke.rs`:

```rust
mod fixtures;

use tempfile::tempdir;
use ura_core::{commands, Result};

#[test]
fn new_project_records_disassembly_and_strings() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x200..0x20c].copy_from_slice(b"hello-ura\0\0\0");
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;
    let strings = commands::strings(&project, Some("hello"))?;

    assert_eq!(disasm[0].addr, 0x400080);
    assert_eq!(disasm[0].mnemonic, "ret");
    assert_eq!(strings[0].value, "hello-ura");
    Ok(())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p ura-core --test analysis_smoke new_project_records_disassembly_and_strings -- --nocapture
```

Expected: compile fails because `commands::disasm` and `commands::strings` are not defined.

- [ ] **Step 3: Implement disassembly and string passes**

Create `crates/ura-core/src/analysis/mod.rs`:

```rust
pub mod disasm;
pub mod strings;

use crate::{elf_loader::LoadedElf, model::{Instruction, StringRef}, Result};

pub struct AnalysisOutput {
    pub instructions: Vec<Instruction>,
    pub strings: Vec<StringRef>,
}

pub fn run_initial_analysis(loaded: &LoadedElf) -> Result<AnalysisOutput> {
    Ok(AnalysisOutput {
        instructions: disasm::linear_disassemble(loaded)?,
        strings: strings::extract_strings(&loaded.bytes),
    })
}
```

Create `crates/ura-core/src/analysis/disasm.rs`:

```rust
use capstone::{arch::arm64::ArchMode, prelude::*};

use crate::{elf_loader::LoadedElf, model::Instruction, Result, UraError};

pub fn linear_disassemble(loaded: &LoadedElf) -> Result<Vec<Instruction>> {
    let cs = Capstone::new()
        .arm64()
        .mode(ArchMode::Arm)
        .build()
        .map_err(|err| UraError::Analysis(err.to_string()))?;
    let mut out = Vec::new();
    for (start, end) in loaded.executable_ranges() {
        let size = (end - start) as usize;
        let Some(bytes) = loaded.bytes_at(start, size) else {
            continue;
        };
        let insns = cs
            .disasm_all(bytes, start)
            .map_err(|err| UraError::Analysis(err.to_string()))?;
        for insn in insns.iter() {
            let addr = insn.address();
            let size = insn.bytes().len() as u8;
            let fallthrough = if is_terminal(insn.mnemonic().unwrap_or("")) {
                None
            } else {
                Some(addr + u64::from(size))
            };
            out.push(Instruction {
                addr,
                size,
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
                fallthrough,
                branch_target: parse_branch_target(insn.op_str().unwrap_or("")),
                function_addr: None,
            });
        }
    }
    Ok(out)
}

fn is_terminal(mnemonic: &str) -> bool {
    matches!(mnemonic, "ret" | "br" | "blr" | "b")
}

fn parse_branch_target(operands: &str) -> Option<u64> {
    let trimmed = operands.trim().strip_prefix('#').unwrap_or(operands.trim());
    u64::from_str_radix(trimmed.strip_prefix("0x")?, 16).ok()
}
```

Create `crates/ura-core/src/analysis/strings.rs`:

```rust
use crate::model::StringRef;

pub fn extract_strings(bytes: &[u8]) -> Vec<StringRef> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < bytes.len() {
        while start < bytes.len() && !is_printable(bytes[start]) {
            start += 1;
        }
        let mut end = start;
        while end < bytes.len() && is_printable(bytes[end]) {
            end += 1;
        }
        if end.saturating_sub(start) >= 4 {
            let value = String::from_utf8_lossy(&bytes[start..end]).to_string();
            out.push(StringRef {
                addr: start as u64,
                value,
                encoding: "ascii".to_string(),
            });
        }
        start = end.saturating_add(1);
    }
    out
}

fn is_printable(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e)
}
```

Extend `crates/ura-core/src/db.rs` with insert/query helpers for instructions and strings:

```rust
use crate::model::{Instruction, StringRef};

pub fn insert_instructions(conn: &Connection, instructions: &[Instruction]) -> Result<()> {
    conn.execute("DELETE FROM instructions", [])?;
    for insn in instructions {
        conn.execute(
            "INSERT INTO instructions(addr, size, bytes, mnemonic, operands, fallthrough, branch_target, function_addr)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                insn.addr,
                insn.size,
                insn.bytes,
                insn.mnemonic,
                insn.operands,
                insn.fallthrough,
                insn.branch_target,
                insn.function_addr
            ],
        )?;
    }
    Ok(())
}

pub fn insert_strings(conn: &Connection, strings: &[StringRef]) -> Result<()> {
    conn.execute("DELETE FROM strings", [])?;
    for s in strings {
        conn.execute(
            "INSERT INTO strings(addr, value, encoding) VALUES(?1, ?2, ?3)",
            params![s.addr, s.value, s.encoding],
        )?;
    }
    Ok(())
}

pub fn query_disasm(conn: &Connection, addr: u64, count: usize) -> Result<Vec<Instruction>> {
    let mut stmt = conn.prepare(
        "SELECT addr, size, bytes, mnemonic, operands, fallthrough, branch_target, function_addr
         FROM instructions WHERE addr >= ?1 ORDER BY addr LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![addr, count as i64], |row| {
        Ok(Instruction {
            addr: row.get(0)?,
            size: row.get::<_, i64>(1)? as u8,
            bytes: row.get(2)?,
            mnemonic: row.get(3)?,
            operands: row.get(4)?,
            fallthrough: row.get(5)?,
            branch_target: row.get(6)?,
            function_addr: row.get(7)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn query_strings(conn: &Connection, filter: Option<&str>) -> Result<Vec<StringRef>> {
    let pattern = format!("%{}%", filter.unwrap_or(""));
    let mut stmt = conn.prepare(
        "SELECT addr, value, encoding FROM strings WHERE value LIKE ?1 ORDER BY addr",
    )?;
    let rows = stmt.query_map(params![pattern], |row| {
        Ok(StringRef {
            addr: row.get(0)?,
            value: row.get(1)?,
            encoding: row.get(2)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}
```

Update `commands::new_project` to run analysis before returning:

```rust
let analysis = crate::analysis::run_initial_analysis(&loaded)?;
db::insert_instructions(project.conn_mut(), &analysis.instructions)?;
db::insert_strings(project.conn_mut(), &analysis.strings)?;
```

Add command functions:

```rust
use crate::model::{Instruction, StringRef};

pub fn disasm(project_path: impl AsRef<Path>, addr: u64, count: usize) -> Result<Vec<Instruction>> {
    let project = Project::open(project_path)?;
    db::query_disasm(project.conn(), addr, count)
}

pub fn strings(project_path: impl AsRef<Path>, filter: Option<&str>) -> Result<Vec<StringRef>> {
    let project = Project::open(project_path)?;
    db::query_strings(project.conn(), filter)
}
```

Modify `crates/ura-core/src/lib.rs`:

```rust
pub mod analysis;
pub mod commands;
pub mod db;
pub mod elf_loader;
pub mod error;
pub mod model;
pub mod project;

pub use error::{Result, UraError};
```

- [ ] **Step 4: Run analysis smoke test**

Run:

```bash
cargo test -p ura-core --test analysis_smoke new_project_records_disassembly_and_strings -- --nocapture
```

Expected: test passes.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-core/src crates/ura-core/tests/analysis_smoke.rs
git commit -m "feat: add arm64 disassembly and strings"
```

Expected: commit succeeds in a Git repository. If there is no Git repository, keep the local checkpoint.

## Task 7: Add Functions, Xrefs, User Edits, And Reanalysis

**Files:**
- Create: `crates/ura-core/src/analysis/functions.rs`
- Create: `crates/ura-core/src/analysis/xrefs.rs`
- Create: `crates/ura-core/src/analysis/diagnostics.rs`
- Modify: `crates/ura-core/src/analysis/mod.rs`
- Modify: `crates/ura-core/src/db.rs`
- Modify: `crates/ura-core/src/commands.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`

- [ ] **Step 1: Write failing user edit and reanalysis test**

Append to `crates/ura-core/tests/analysis_smoke.rs`:

```rust
#[test]
fn user_edits_persist_across_reanalysis() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    commands::make_function(&project, 0x400080)?;
    commands::rename(&project, 0x400080, "manual_ret")?;
    commands::comment(&project, 0x400080, "manual function")?;
    commands::set_function_range(&project, 0x400080, 0x400080, 0x400084)?;
    commands::reanalyze(&project)?;

    let funcs = commands::functions(&project)?;
    let comments = commands::comments(&project, 0x400080)?;

    assert!(funcs.iter().any(|f| f.addr == 0x400080 && f.name == "manual_ret"));
    assert_eq!(comments, vec!["manual function".to_string()]);
    Ok(())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p ura-core --test analysis_smoke user_edits_persist_across_reanalysis -- --nocapture
```

Expected: compile fails because the function/edit commands are not defined.

- [ ] **Step 3: Implement minimal function and xref passes**

Create `crates/ura-core/src/analysis/functions.rs`:

```rust
use std::collections::BTreeSet;

use crate::model::{Function, FunctionSource, Instruction};

pub fn discover_functions(entry: u64, instructions: &[Instruction], user_functions: &[Function]) -> Vec<Function> {
    let mut starts = BTreeSet::new();
    starts.insert((entry, FunctionSource::Entry));
    for insn in instructions {
        if matches!(insn.mnemonic.as_str(), "bl" | "b") {
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
        .find(|insn| matches!(insn.mnemonic.as_str(), "ret" | "br" | "b"))
        .map(|insn| insn.addr + u64::from(insn.size))
}
```

Create `crates/ura-core/src/analysis/xrefs.rs`:

```rust
use crate::model::{Instruction, StringRef, Xref, XrefKind};

pub fn build_xrefs(instructions: &[Instruction], strings: &[StringRef]) -> Vec<Xref> {
    let mut out = Vec::new();
    for insn in instructions {
        if let Some(target) = insn.branch_target {
            let kind = if insn.mnemonic == "bl" { XrefKind::Call } else { XrefKind::Code };
            out.push(Xref {
                from_addr: insn.addr,
                to_addr: target,
                kind,
            });
        }
        for s in strings {
            if insn.operands.contains(&format!("0x{:x}", s.addr)) {
                out.push(Xref {
                    from_addr: insn.addr,
                    to_addr: s.addr,
                    kind: XrefKind::String,
                });
            }
        }
    }
    out
}
```

Create `crates/ura-core/src/analysis/diagnostics.rs`:

```rust
use crate::model::{Diagnostic, Instruction};

pub fn collect_diagnostics(instructions: &[Instruction]) -> Vec<Diagnostic> {
    instructions
        .iter()
        .filter(|insn| insn.mnemonic.is_empty())
        .map(|insn| Diagnostic {
            addr: Some(insn.addr),
            severity: "warning".to_string(),
            message: "instruction decoded without mnemonic".to_string(),
        })
        .collect()
}
```

Update `analysis/mod.rs` to include functions, xrefs, and diagnostics:

```rust
pub mod diagnostics;
pub mod disasm;
pub mod functions;
pub mod strings;
pub mod xrefs;

use crate::{
    elf_loader::LoadedElf,
    model::{Diagnostic, Function, Instruction, StringRef, Xref},
    Result,
};

pub struct AnalysisOutput {
    pub instructions: Vec<Instruction>,
    pub strings: Vec<StringRef>,
    pub functions: Vec<Function>,
    pub xrefs: Vec<Xref>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn run_initial_analysis(loaded: &LoadedElf, user_functions: &[Function]) -> Result<AnalysisOutput> {
    let instructions = disasm::linear_disassemble(loaded)?;
    let strings = strings::extract_strings(&loaded.bytes);
    let functions = functions::discover_functions(loaded.entry, &instructions, user_functions);
    let xrefs = xrefs::build_xrefs(&instructions, &strings);
    let diagnostics = diagnostics::collect_diagnostics(&instructions);
    Ok(AnalysisOutput {
        instructions,
        strings,
        functions,
        xrefs,
        diagnostics,
    })
}
```

- [ ] **Step 4: Implement persistence and command APIs**

Add DB helpers for functions, xrefs, comments, renames, and diagnostics:

```rust
use crate::model::{Diagnostic, Function, FunctionSource, Xref, XrefKind};

pub fn insert_functions(conn: &Connection, functions: &[Function]) -> Result<()> {
    conn.execute("DELETE FROM functions WHERE source != 'User'", [])?;
    for function in functions {
        conn.execute(
            "INSERT INTO functions(addr, name, start, end, source)
             VALUES(?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(addr) DO UPDATE SET name = excluded.name, start = excluded.start, end = excluded.end, source = excluded.source",
            params![
                function.addr,
                function.name,
                function.start,
                function.end,
                format!("{:?}", function.source)
            ],
        )?;
    }
    Ok(())
}

pub fn query_functions(conn: &Connection) -> Result<Vec<Function>> {
    let mut stmt = conn.prepare("SELECT addr, name, start, end, source FROM functions ORDER BY addr")?;
    let rows = stmt.query_map([], |row| {
        let source: String = row.get(4)?;
        Ok(Function {
            addr: row.get(0)?,
            name: row.get(1)?,
            start: row.get(2)?,
            end: row.get(3)?,
            source: parse_function_source(&source),
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn insert_xrefs(conn: &Connection, xrefs: &[Xref]) -> Result<()> {
    conn.execute("DELETE FROM xrefs", [])?;
    for xref in xrefs {
        conn.execute(
            "INSERT OR IGNORE INTO xrefs(from_addr, to_addr, kind) VALUES(?1, ?2, ?3)",
            params![xref.from_addr, xref.to_addr, format!("{:?}", xref.kind)],
        )?;
    }
    Ok(())
}

pub fn query_xrefs(conn: &Connection, addr: u64) -> Result<Vec<Xref>> {
    let mut stmt = conn.prepare("SELECT from_addr, to_addr, kind FROM xrefs WHERE to_addr = ?1 OR from_addr = ?1 ORDER BY from_addr")?;
    let rows = stmt.query_map(params![addr], |row| {
        let kind: String = row.get(2)?;
        Ok(Xref {
            from_addr: row.get(0)?,
            to_addr: row.get(1)?,
            kind: parse_xref_kind(&kind),
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn rename(conn: &Connection, addr: u64, name: &str) -> Result<()> {
    conn.execute("INSERT INTO renames(addr, name) VALUES(?1, ?2) ON CONFLICT(addr) DO UPDATE SET name = excluded.name", params![addr, name])?;
    conn.execute("UPDATE functions SET name = ?2 WHERE addr = ?1", params![addr, name])?;
    Ok(())
}

pub fn set_comment(conn: &Connection, addr: u64, text: &str) -> Result<()> {
    conn.execute("INSERT INTO comments(addr, text) VALUES(?1, ?2) ON CONFLICT(addr) DO UPDATE SET text = excluded.text", params![addr, text])?;
    Ok(())
}

pub fn query_comments(conn: &Connection, addr: u64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT text FROM comments WHERE addr = ?1")?;
    let rows = stmt.query_map(params![addr], |row| row.get::<_, String>(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn upsert_user_function(conn: &Connection, function: &Function) -> Result<()> {
    conn.execute(
        "INSERT INTO functions(addr, name, start, end, source)
         VALUES(?1, ?2, ?3, ?4, 'User')
         ON CONFLICT(addr) DO UPDATE SET start = excluded.start, end = excluded.end, source = 'User'",
        params![function.addr, function.name, function.start, function.end],
    )?;
    Ok(())
}

pub fn insert_diagnostics(conn: &Connection, diagnostics: &[Diagnostic]) -> Result<()> {
    conn.execute("DELETE FROM diagnostics", [])?;
    for diagnostic in diagnostics {
        conn.execute(
            "INSERT INTO diagnostics(addr, severity, message) VALUES(?1, ?2, ?3)",
            params![diagnostic.addr, diagnostic.severity, diagnostic.message],
        )?;
    }
    Ok(())
}

pub fn query_diagnostics(conn: &Connection) -> Result<Vec<Diagnostic>> {
    let mut stmt = conn.prepare("SELECT addr, severity, message FROM diagnostics ORDER BY id")?;
    let rows = stmt.query_map([], |row| {
        Ok(Diagnostic {
            addr: row.get(0)?,
            severity: row.get(1)?,
            message: row.get(2)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

fn parse_function_source(source: &str) -> FunctionSource {
    match source {
        "Entry" => FunctionSource::Entry,
        "BranchTarget" => FunctionSource::BranchTarget,
        "User" => FunctionSource::User,
        _ => FunctionSource::Symbol,
    }
}

fn parse_xref_kind(kind: &str) -> XrefKind {
    match kind {
        "Call" => XrefKind::Call,
        "Data" => XrefKind::Data,
        "String" => XrefKind::String,
        _ => XrefKind::Code,
    }
}
```

Add command wrappers in `commands.rs`:

```rust
use crate::model::{Diagnostic, Function, FunctionSource, Xref};

pub fn functions(project_path: impl AsRef<Path>) -> Result<Vec<Function>> {
    let project = Project::open(project_path)?;
    db::query_functions(project.conn())
}

pub fn xrefs(project_path: impl AsRef<Path>, addr: u64) -> Result<Vec<Xref>> {
    let project = Project::open(project_path)?;
    db::query_xrefs(project.conn(), addr)
}

pub fn rename(project_path: impl AsRef<Path>, addr: u64, name: &str) -> Result<()> {
    let project = Project::open(project_path)?;
    db::rename(project.conn(), addr, name)
}

pub fn comment(project_path: impl AsRef<Path>, addr: u64, text: &str) -> Result<()> {
    let project = Project::open(project_path)?;
    db::set_comment(project.conn(), addr, text)
}

pub fn comments(project_path: impl AsRef<Path>, addr: u64) -> Result<Vec<String>> {
    let project = Project::open(project_path)?;
    db::query_comments(project.conn(), addr)
}

pub fn diagnostics(project_path: impl AsRef<Path>) -> Result<Vec<Diagnostic>> {
    let project = Project::open(project_path)?;
    db::query_diagnostics(project.conn())
}

pub fn make_function(project_path: impl AsRef<Path>, addr: u64) -> Result<()> {
    let project = Project::open(project_path)?;
    let function = Function {
        addr,
        name: format!("sub_{addr:x}"),
        start: addr,
        end: addr + 4,
        source: FunctionSource::User,
    };
    db::upsert_user_function(project.conn(), &function)
}

pub fn set_function_range(project_path: impl AsRef<Path>, function_addr: u64, start: u64, end: u64) -> Result<()> {
    let project = Project::open(project_path)?;
    let mut functions = db::query_functions(project.conn())?;
    let name = functions
        .iter_mut()
        .find(|func| func.addr == function_addr)
        .map(|func| func.name.clone())
        .unwrap_or_else(|| format!("sub_{function_addr:x}"));
    db::upsert_user_function(project.conn(), &Function {
        addr: function_addr,
        name,
        start,
        end,
        source: FunctionSource::User,
    })
}

pub fn reanalyze(project_path: impl AsRef<Path>) -> Result<()> {
    let project_path = project_path.as_ref();
    let project = Project::open(project_path)?;
    let user_functions = db::query_functions(project.conn())?
        .into_iter()
        .filter(|func| func.source == FunctionSource::User)
        .collect::<Vec<_>>();
    drop(project);
    let source_hash = info(project_path)?.source_hash;
    let project = Project::open(project_path)?;
    db::set_metadata(project.conn(), "last_reanalysis_source_hash", &source_hash)?;
    let functions = db::query_functions(project.conn())?;
    db::insert_functions(project.conn(), &functions)?;
    for func in user_functions {
        db::upsert_user_function(project.conn(), &func)?;
    }
    Ok(())
}
```

Also update `new_project` to insert functions, xrefs, and diagnostics from `AnalysisOutput`.

- [ ] **Step 5: Run user edit test**

Run:

```bash
cargo test -p ura-core --test analysis_smoke user_edits_persist_across_reanalysis -- --nocapture
```

Expected: test passes.

- [ ] **Step 6: Commit**

Run:

```bash
git add crates/ura-core/src crates/ura-core/tests/analysis_smoke.rs
git commit -m "feat: add functions xrefs and user edits"
```

Expected: commit succeeds in a Git repository. If there is no Git repository, keep the local checkpoint.

## Task 8: Implement Batch CLI

**Files:**
- Modify: `crates/ura-cli/src/main.rs`
- Create: `crates/ura-cli/src/output.rs`
- Create: `crates/ura-cli/tests/cli_smoke.rs`

- [ ] **Step 1: Write failing CLI smoke test**

Create `crates/ura-cli/tests/cli_smoke.rs`:

```rust
use assert_cmd::Command;
use tempfile::tempdir;

fn minimal_elf64_aarch64_executable() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x1000];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&183u16.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&0x400080u64.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    bytes[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let ph = 0x40usize;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes
}

#[test]
fn cli_creates_project_and_prints_info() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, minimal_elf64_aarch64_executable()).unwrap();

    Command::cargo_bin("ura")
        .unwrap()
        .args(["new", input.to_str().unwrap(), "-o", project.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("ura")
        .unwrap()
        .args(["info", project.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Aarch64"));
}
```

- [ ] **Step 2: Run CLI test to verify it fails**

Run:

```bash
cargo test -p ura-cli --test cli_smoke cli_creates_project_and_prints_info -- --nocapture
```

Expected: test fails because the CLI skeleton does not implement `new` or `info`.

- [ ] **Step 3: Implement CLI commands**

Create `crates/ura-cli/src/output.rs`:

```rust
use anyhow::Result;
use serde::Serialize;

pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
```

Replace `crates/ura-cli/src/main.rs`:

```rust
mod output;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ura")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    New { input: PathBuf, #[arg(short, long)] output: PathBuf },
    Analyze { project: PathBuf },
    Info { project: PathBuf, #[arg(long)] json: bool },
    Funcs { project: PathBuf, #[arg(long)] json: bool },
    Disasm { project: PathBuf, addr: String, #[arg(long, default_value_t = 16)] count: usize, #[arg(long)] json: bool },
    Xrefs { project: PathBuf, addr: String, #[arg(long)] json: bool },
    Strings { project: PathBuf, #[arg(long)] filter: Option<String>, #[arg(long)] json: bool },
    Diagnostics { project: PathBuf, #[arg(long)] json: bool },
    Rename { project: PathBuf, addr: String, name: String },
    Comment { project: PathBuf, addr: String, text: String },
    MakeFunc { project: PathBuf, addr: String },
    SetFuncRange { project: PathBuf, func_addr: String, start: String, end: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::New { input, output } => ura_core::commands::new_project(input, output)?,
        Command::Analyze { project } => ura_core::commands::reanalyze(project)?,
        Command::Info { project, json } => {
            let info = ura_core::commands::info(project)?;
            if json {
                output::print_json(&info)?;
            } else {
                println!("{info:#?}");
            }
        }
        Command::Funcs { project, json } => {
            let funcs = ura_core::commands::functions(project)?;
            if json { output::print_json(&funcs)?; } else { println!("{funcs:#?}"); }
        }
        Command::Disasm { project, addr, count, json } => {
            let rows = ura_core::commands::disasm(project, parse_addr(&addr)?, count)?;
            if json { output::print_json(&rows)?; } else { println!("{rows:#?}"); }
        }
        Command::Xrefs { project, addr, json } => {
            let rows = ura_core::commands::xrefs(project, parse_addr(&addr)?)?;
            if json { output::print_json(&rows)?; } else { println!("{rows:#?}"); }
        }
        Command::Strings { project, filter, json } => {
            let rows = ura_core::commands::strings(project, filter.as_deref())?;
            if json { output::print_json(&rows)?; } else { println!("{rows:#?}"); }
        }
        Command::Diagnostics { project, json } => {
            let rows = ura_core::commands::diagnostics(project)?;
            if json { output::print_json(&rows)?; } else { println!("{rows:#?}"); }
        }
        Command::Rename { project, addr, name } => ura_core::commands::rename(project, parse_addr(&addr)?, &name)?,
        Command::Comment { project, addr, text } => ura_core::commands::comment(project, parse_addr(&addr)?, &text)?,
        Command::MakeFunc { project, addr } => ura_core::commands::make_function(project, parse_addr(&addr)?)?,
        Command::SetFuncRange { project, func_addr, start, end } => {
            ura_core::commands::set_function_range(project, parse_addr(&func_addr)?, parse_addr(&start)?, parse_addr(&end)?)?;
        }
    }
    Ok(())
}

fn parse_addr(value: &str) -> Result<u64> {
    Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
}
```

- [ ] **Step 4: Run CLI test**

Run:

```bash
cargo test -p ura-cli --test cli_smoke cli_creates_project_and_prints_info -- --nocapture
```

Expected: test passes.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/ura-cli/src crates/ura-cli/tests/cli_smoke.rs
git commit -m "feat: add batch cli commands"
```

Expected: commit succeeds in a Git repository. If there is no Git repository, keep the local checkpoint.

## Task 9: Implement Interactive Shell

**Files:**
- Create: `crates/ura-cli/src/lib.rs`
- Create: `crates/ura-cli/src/shell.rs`
- Modify: `crates/ura-cli/src/main.rs`

- [ ] **Step 1: Add shell library module**

Create `crates/ura-cli/src/lib.rs`:

```rust
pub mod shell;
```

Create `crates/ura-cli/src/shell.rs`:

```rust
use std::path::PathBuf;

use anyhow::{bail, Result};
use rustyline::DefaultEditor;

pub fn run(project: PathBuf) -> Result<()> {
    let mut rl = DefaultEditor::new()?;
    let mut current_addr = 0u64;
    loop {
        let line = rl.readline("ura> ")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _ = rl.add_history_entry(trimmed);
        let mut parts = trimmed.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        match cmd {
            "quit" | "exit" => break,
            "info" => println!("{:#?}", ura_core::commands::info(&project)?),
            "funcs" => println!("{:#?}", ura_core::commands::functions(&project)?),
            "strings" => println!("{:#?}", ura_core::commands::strings(&project, parts.next())?),
            "disasm" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                current_addr = addr;
                println!("{:#?}", ura_core::commands::disasm(&project, addr, 16)?);
            }
            "xrefs" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                current_addr = addr;
                println!("{:#?}", ura_core::commands::xrefs(&project, addr)?);
            }
            "rename" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let name = parts.next().ok_or_else(|| anyhow::anyhow!("missing name"))?;
                ura_core::commands::rename(&project, addr, name)?;
            }
            "comment" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let text = parts.collect::<Vec<_>>().join(" ");
                ura_core::commands::comment(&project, addr, &text)?;
            }
            "make-func" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                ura_core::commands::make_function(&project, addr)?;
            }
            "set-func-range" => {
                let func_addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let start = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let end = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                ura_core::commands::set_function_range(&project, func_addr, start, end)?;
            }
            "reanalyze" => ura_core::commands::reanalyze(&project)?,
            "save" => println!("saved"),
            "revert" => println!("revert skipped: edits are saved transactionally by command"),
            "diagnostics" => println!("{:#?}", ura_core::commands::diagnostics(&project)?),
            other => bail!("unknown command: {other}"),
        }
    }
    Ok(())
}

fn parse_shell_addr(value: &str, current_addr: u64) -> Result<u64> {
    if let Some(offset) = value.strip_prefix("+0x") {
        return Ok(current_addr + u64::from_str_radix(offset, 16)?);
    }
    if let Some(hex) = value.strip_prefix("0x") {
        return Ok(u64::from_str_radix(hex, 16)?);
    }
    bail!("unsupported address expression: {value}")
}
```

- [ ] **Step 2: Wire shell in main**

In `crates/ura-cli/src/main.rs`, add:

```rust
use ura_cli::shell;
```

Add the shell variant to the `Command` enum:

```rust
Shell { project: PathBuf },
```

Change the shell command arm to:

```rust
Command::Shell { project } => shell::run(project)?,
```

- [ ] **Step 3: Verify CLI compiles**

Run:

```bash
cargo check -p ura-cli
```

Expected: command exits successfully.

- [ ] **Step 4: Commit**

Run:

```bash
git add crates/ura-cli/src
git commit -m "feat: add interactive analysis shell"
```

Expected: commit succeeds in a Git repository. If there is no Git repository, keep the local checkpoint.

## Task 10: Implement Thin Daemon

**Files:**
- Create: `crates/ura-daemon/src/protocol.rs`
- Modify: `crates/ura-daemon/src/main.rs`
- Create: `crates/ura-daemon/tests/daemon_smoke.rs`

- [ ] **Step 1: Write protocol schema**

Create `crates/ura-daemon/src/protocol.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    OpenProject { id: u64, path: String },
    CloseProject { id: u64, session_id: u64 },
    GetInfo { id: u64, session_id: u64 },
    ListFunctions { id: u64, session_id: u64 },
    GetDisassembly { id: u64, session_id: u64, addr: u64, count: usize },
    ListXrefs { id: u64, session_id: u64, addr: u64 },
    RenameSymbol { id: u64, session_id: u64, addr: u64, name: String },
    SetComment { id: u64, session_id: u64, addr: u64, text: String },
    MakeFunction { id: u64, session_id: u64, addr: u64 },
    Reanalyze { id: u64, session_id: u64 },
}

#[derive(Debug, Serialize)]
pub struct Response<T: Serialize> {
    pub id: u64,
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<String>,
}

impl<T: Serialize> Response<T> {
    pub fn ok(id: u64, result: T) -> Self {
        Self { id, ok: true, result: Some(result), error: None }
    }

    pub fn err(id: u64, error: impl ToString) -> Self {
        Self { id, ok: false, result: None, error: Some(error.to_string()) }
    }
}
```

- [ ] **Step 2: Implement line-delimited JSON daemon**

Replace `crates/ura-daemon/src/main.rs`:

```rust
mod protocol;

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
};

use anyhow::Result;
use protocol::{Request, Response};

fn main() -> Result<()> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:7878".to_string());
    let listener = TcpListener::bind(&addr)?;
    println!("ura-daemon listening on {addr}");
    for stream in listener.incoming() {
        handle_client(stream?)?;
    }
    Ok(())
}

fn handle_client(stream: TcpStream) -> Result<()> {
    let mut writer = stream.try_clone()?;
    let reader = BufReader::new(stream);
    let mut sessions: HashMap<u64, PathBuf> = HashMap::new();
    let mut next_session = 1u64;
    for line in reader.lines() {
        let line = line?;
        let request: Request = serde_json::from_str(&line)?;
        let response = handle_request(request, &mut sessions, &mut next_session);
        writeln!(writer, "{response}")?;
    }
    Ok(())
}

fn handle_request(request: Request, sessions: &mut HashMap<u64, PathBuf>, next_session: &mut u64) -> String {
    match request {
        Request::OpenProject { id, path } => {
            let session_id = *next_session;
            *next_session += 1;
            sessions.insert(session_id, PathBuf::from(path));
            serde_json::to_string(&Response::ok(id, serde_json::json!({ "session_id": session_id }))).unwrap()
        }
        Request::CloseProject { id, session_id } => {
            sessions.remove(&session_id);
            serde_json::to_string(&Response::ok(id, serde_json::json!({ "closed": true }))).unwrap()
        }
        Request::GetInfo { id, session_id } => with_project(id, session_id, sessions, |path| {
            serde_json::to_value(ura_core::commands::info(path)?) .map_err(anyhow::Error::from)
        }),
        Request::ListFunctions { id, session_id } => with_project(id, session_id, sessions, |path| {
            serde_json::to_value(ura_core::commands::functions(path)?) .map_err(anyhow::Error::from)
        }),
        Request::GetDisassembly { id, session_id, addr, count } => with_project(id, session_id, sessions, |path| {
            serde_json::to_value(ura_core::commands::disasm(path, addr, count)?) .map_err(anyhow::Error::from)
        }),
        Request::ListXrefs { id, session_id, addr } => with_project(id, session_id, sessions, |path| {
            serde_json::to_value(ura_core::commands::xrefs(path, addr)?) .map_err(anyhow::Error::from)
        }),
        Request::RenameSymbol { id, session_id, addr, name } => with_project(id, session_id, sessions, |path| {
            ura_core::commands::rename(path, addr, &name)?;
            Ok(serde_json::json!({ "renamed": true }))
        }),
        Request::SetComment { id, session_id, addr, text } => with_project(id, session_id, sessions, |path| {
            ura_core::commands::comment(path, addr, &text)?;
            Ok(serde_json::json!({ "commented": true }))
        }),
        Request::MakeFunction { id, session_id, addr } => with_project(id, session_id, sessions, |path| {
            ura_core::commands::make_function(path, addr)?;
            Ok(serde_json::json!({ "made_function": true }))
        }),
        Request::Reanalyze { id, session_id } => with_project(id, session_id, sessions, |path| {
            ura_core::commands::reanalyze(path)?;
            Ok(serde_json::json!({ "reanalyzed": true }))
        }),
    }
}

fn with_project<F>(id: u64, session_id: u64, sessions: &HashMap<u64, PathBuf>, f: F) -> String
where
    F: FnOnce(&PathBuf) -> Result<serde_json::Value>,
{
    let Some(path) = sessions.get(&session_id) else {
        return serde_json::to_string(&Response::<serde_json::Value>::err(id, "unknown session")).unwrap();
    };
    match f(path) {
        Ok(value) => serde_json::to_string(&Response::ok(id, value)).unwrap(),
        Err(err) => serde_json::to_string(&Response::<serde_json::Value>::err(id, err)).unwrap(),
    }
}
```

- [ ] **Step 3: Verify daemon compiles**

Run:

```bash
cargo check -p ura-daemon
```

Expected: command exits successfully.

- [ ] **Step 4: Commit**

Run:

```bash
git add crates/ura-daemon/src
git commit -m "feat: add thin daemon rpc wrapper"
```

Expected: commit succeeds in a Git repository. If there is no Git repository, keep the local checkpoint.

## Task 11: Final Verification And Spec Coverage

**Files:**
- Modify only files needed to fix verification failures.

- [ ] **Step 1: Run formatter**

Run:

```bash
cargo fmt --all -- --check
```

Expected: formatting check passes. If it fails, run `cargo fmt --all`, inspect the diff, then rerun the check.

- [ ] **Step 2: Run full tests**

Run:

```bash
cargo test --workspace -- --nocapture
```

Expected: all workspace tests pass.

- [ ] **Step 3: Run full compile check**

Run:

```bash
cargo check --workspace
```

Expected: all crates compile.

- [ ] **Step 4: Verify MVP commands manually**

Run these commands with a generated or checked-in ELF64 AArch64 fixture:

```bash
cargo run -p ura-cli -- new /tmp/sample-aarch64.elf -o /tmp/sample.ura
cargo run -p ura-cli -- info /tmp/sample.ura
cargo run -p ura-cli -- funcs /tmp/sample.ura
cargo run -p ura-cli -- disasm /tmp/sample.ura 0x400080 --count 4
cargo run -p ura-cli -- strings /tmp/sample.ura
cargo run -p ura-cli -- make-func /tmp/sample.ura 0x400080
cargo run -p ura-cli -- rename /tmp/sample.ura 0x400080 manual_ret
cargo run -p ura-cli -- comment /tmp/sample.ura 0x400080 "manual function"
cargo run -p ura-cli -- set-func-range /tmp/sample.ura 0x400080 0x400080 0x400084
cargo run -p ura-cli -- analyze /tmp/sample.ura
```

Expected: every command exits successfully, and `funcs` shows `manual_ret` after reanalysis.

- [ ] **Step 5: Commit verification fixes**

Run:

```bash
git status --short
git add Cargo.toml crates docs/superpowers
git commit -m "test: verify ura mvp foundation"
```

Expected: commit succeeds if verification required changes. If there are no changes, no commit is needed. If there is no Git repository, record the verification output in the final handoff instead.

## Self-Review

Spec coverage:

- Reusable engine: covered by `ura-core` in Tasks 1-7.
- Engine-owned project DB: covered by Tasks 3, 5, and 7.
- ELF64 AArch64 loader: covered by Task 4.
- Initial analysis passes: covered by Tasks 6 and 7.
- Batch CLI and interactive shell: covered by Tasks 8 and 9.
- Thin daemon API: covered by Task 10.
- MVP verification: covered by Task 11.

Scope intentionally deferred:

- Decompiler, debugger, GUI/Web client, collaboration, PE/Mach-O, non-ARM64 architectures, full type recovery, advanced jump-table recovery, and obfuscation recovery remain outside this MVP.

Plan consistency notes:

- All mutating operations go through `ura_core::commands`.
- CLI and daemon both call the same core command API.
- User edits are persisted in SQLite and reanalysis is required to preserve them.
- Daemon protocol is intentionally line-delimited JSON to keep the MVP small while preserving process decoupling.
