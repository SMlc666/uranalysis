# Urdisassembly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone `urdisassembly` Rust crate, replace `capstone` in `ura-core`, and migrate Ura projects to schema version 2 with structured decode metadata.

**Architecture:** `urdisassembly` owns decoding, formatting, and instruction semantics. `ura-core` owns ELF range iteration, project persistence, function discovery, xrefs, and schema migration. AArch64 support is implemented with focused mask/match decoders and a coverage matrix that makes missing instruction groups visible.

**Tech Stack:** Rust 2021, Cargo workspace, `goblin` for the development coverage example, `rusqlite` for Ura project schema migration, existing `ura-core`/`ura-cli`/`ura-daemon` tests.

---

## Scope Notes

This plan implements `docs/superpowers/specs/2026-06-17-urdisassembly-design.md`.

Keep commits frequent. Each task below ends with a commit command. If a test fails for an unrelated dirty workspace issue, stop and inspect before continuing.

## File Structure

- `Cargo.toml`: add `crates/urdisassembly` as a workspace member and shared path dependency; remove `capstone`.
- `Cargo.lock`: update after dependency changes.
- `crates/urdisassembly/Cargo.toml`: standalone crate manifest.
- `crates/urdisassembly/src/lib.rs`: public exports.
- `crates/urdisassembly/src/error.rs`: `DecodeError` and `Result`.
- `crates/urdisassembly/src/model.rs`: public instruction, operand, flow, status, register, and memory models.
- `crates/urdisassembly/src/decoder.rs`: architecture-neutral `Decoder`.
- `crates/urdisassembly/src/bits.rs`: bit extraction and sign-extension helpers.
- `crates/urdisassembly/src/arch/mod.rs`: architecture module root.
- `crates/urdisassembly/src/arch/aarch64/mod.rs`: AArch64 module root.
- `crates/urdisassembly/src/arch/aarch64/registers.rs`: AArch64 register formatting.
- `crates/urdisassembly/src/arch/aarch64/decode.rs`: mask/match AArch64 decoder.
- `crates/urdisassembly/src/arch/aarch64/format.rs`: operand and instruction text formatting.
- `crates/urdisassembly/examples/coverage.rs`: development coverage tool for ELF64 AArch64 corpus checks.
- `crates/urdisassembly/tests/aarch64_decode.rs`: golden tests for implemented instructions.
- `crates/urdisassembly/tests/aarch64_unknown.rs`: unknown fallback tests.
- `docs/urdisassembly/aarch64-coverage.md`: coverage matrix.
- `crates/ura-core/Cargo.toml`: replace `capstone` with `urdisassembly`.
- `crates/ura-core/src/model.rs`: extend `Instruction` with text, kind, flow, decode status, decoder, and decoder version.
- `crates/ura-core/src/db.rs`: schema version 2, migration, instruction insert/query changes.
- `crates/ura-core/src/project.rs`: run migrations on open.
- `crates/ura-core/src/analysis/disasm.rs`: call `urdisassembly` instead of Capstone.
- `crates/ura-core/src/analysis/functions.rs`: use `flow`/`kind` instead of mnemonic for control-flow truth.
- `crates/ura-core/src/analysis/xrefs.rs`: use `flow`/`kind` instead of mnemonic for call/code xref classification.
- `crates/ura-core/src/analysis/diagnostics.rs`: report unknown decode status.
- `crates/ura-core/tests/analysis_smoke.rs`: add branch, conditional branch, unknown decode tests.
- `crates/ura-core/tests/project_roundtrip.rs`: add schema migration/user-truth preservation test.

## Task 1: Add `urdisassembly` Workspace Skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/urdisassembly/Cargo.toml`
- Create: `crates/urdisassembly/src/lib.rs`
- Create: `crates/urdisassembly/src/error.rs`
- Create: `crates/urdisassembly/src/model.rs`
- Create: `crates/urdisassembly/src/decoder.rs`

- [ ] **Step 1: Add a failing crate-level test for the public API**

Create `crates/urdisassembly/tests/public_api.rs`:

```rust
use urdisassembly::{Architecture, DecodeOptions, Decoder, Endian};

#[test]
fn decoder_constructs_for_aarch64_little_endian() {
    let decoder = Decoder::new(
        Architecture::Aarch64,
        DecodeOptions {
            endian: Endian::Little,
        },
    )
    .expect("AArch64 little-endian decoder should be supported");

    assert_eq!(decoder.architecture(), Architecture::Aarch64);
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```bash
cargo test -p urdisassembly --test public_api
```

Expected: Cargo fails because package `urdisassembly` does not exist.

- [ ] **Step 3: Add the workspace member and crate manifest**

Modify the root `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/urdisassembly",
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
urdisassembly = { path = "crates/urdisassembly" }
clap = { version = "4.5", features = ["derive"] }
rustyline = "14.0"
tempfile = "3.10"
assert_cmd = "2.0"
predicates = "3.1"
```

Create `crates/urdisassembly/Cargo.toml`:

```toml
[package]
name = "urdisassembly"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
thiserror.workspace = true
serde.workspace = true

[dev-dependencies]
goblin.workspace = true
tempfile.workspace = true
```

- [ ] **Step 4: Add the minimal public modules**

Create `crates/urdisassembly/src/lib.rs`:

```rust
pub mod decoder;
pub mod error;
pub mod model;

pub use decoder::Decoder;
pub use error::{DecodeError, Result};
pub use model::{
    Architecture, DecodeOptions, DecodeStatus, Endian, FlowKind, Instruction, InstructionKind,
    MemoryOperand, Operand, Register,
};
```

Create `crates/urdisassembly/src/error.rs`:

```rust
use thiserror::Error;

pub type Result<T> = std::result::Result<T, DecodeError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unsupported architecture/endian combination")]
    UnsupportedTarget,
    #[error("expected at least {expected} bytes, got {actual}")]
    TruncatedInstruction { expected: usize, actual: usize },
}
```

Create `crates/urdisassembly/src/model.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodeOptions {
    pub endian: Endian,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            endian: Endian::Little,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub size: u8,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Vec<Operand>,
    pub text: String,
    pub kind: InstructionKind,
    pub flow: FlowKind,
    pub branch_target: Option<u64>,
    pub status: DecodeStatus,
}

impl Instruction {
    pub fn operand_text(&self) -> String {
        self.text
            .strip_prefix(&self.mnemonic)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operand {
    Register(Register),
    Immediate(i64),
    AbsoluteAddress(u64),
    Memory(MemoryOperand),
    Condition(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryOperand {
    pub base: Register,
    pub offset: i64,
    pub writeback: bool,
    pub post_index: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstructionKind {
    Branch,
    Call,
    Return,
    Compare,
    Load,
    Store,
    Address,
    Arithmetic,
    Logical,
    Move,
    System,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowKind {
    Fallthrough,
    Branch,
    ConditionalBranch,
    Call,
    Return,
    IndirectBranch,
    IndirectCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodeStatus {
    Complete,
    Partial,
    Unknown,
}
```

Create `crates/urdisassembly/src/decoder.rs`:

```rust
use crate::{
    error::{DecodeError, Result},
    model::{Architecture, DecodeOptions, Endian},
};

#[derive(Debug, Clone)]
pub struct Decoder {
    architecture: Architecture,
    options: DecodeOptions,
}

impl Decoder {
    pub fn new(architecture: Architecture, options: DecodeOptions) -> Result<Self> {
        match (architecture, options.endian) {
            (Architecture::Aarch64, Endian::Little) => Ok(Self {
                architecture,
                options,
            }),
        }
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn options(&self) -> DecodeOptions {
        self.options
    }

    pub fn require_word(bytes: &[u8]) -> Result<u32> {
        let word = bytes
            .get(..4)
            .ok_or(DecodeError::TruncatedInstruction {
                expected: 4,
                actual: bytes.len(),
            })?;
        Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
    }
}
```

- [ ] **Step 5: Run the public API test**

Run:

```bash
cargo test -p urdisassembly --test public_api
```

Expected: test passes.

- [ ] **Step 6: Commit**

Run:

```bash
git add Cargo.toml crates/urdisassembly
git commit -m "feat: add urdisassembly crate skeleton"
```

Expected: commit succeeds.

## Task 2: Add Bit Helpers And Register Formatting

**Files:**
- Create: `crates/urdisassembly/src/bits.rs`
- Create: `crates/urdisassembly/src/arch/mod.rs`
- Create: `crates/urdisassembly/src/arch/aarch64/mod.rs`
- Create: `crates/urdisassembly/src/arch/aarch64/registers.rs`
- Modify: `crates/urdisassembly/src/lib.rs`

- [ ] **Step 1: Write failing unit tests for bit helpers and registers**

Create `crates/urdisassembly/src/bits.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_inclusive_bit_ranges() {
        assert_eq!(bits(0b1101_0110, 1, 3), 0b011);
        assert_eq!(bits(0b1101_0110, 4, 7), 0b1101);
    }

    #[test]
    fn sign_extends_values() {
        assert_eq!(sign_extend(0b0111, 4), 7);
        assert_eq!(sign_extend(0b1000, 4), -8);
        assert_eq!(sign_extend(0b1111, 4), -1);
    }
}
```

Create `crates/urdisassembly/src/arch/aarch64/registers.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_general_registers() {
        assert_eq!(x(0).name, "x0");
        assert_eq!(w(1).name, "w1");
        assert_eq!(x(30).name, "lr");
    }

    #[test]
    fn formats_zero_and_stack_registers_by_context() {
        assert_eq!(x_or_sp(31).name, "sp");
        assert_eq!(w_or_sp(31).name, "wsp");
        assert_eq!(x_or_zr(31).name, "xzr");
        assert_eq!(w_or_zr(31).name, "wzr");
    }
}
```

- [ ] **Step 2: Run tests and verify they fail to compile**

Run:

```bash
cargo test -p urdisassembly bits arch::aarch64::registers
```

Expected: compile errors because helper functions do not exist.

- [ ] **Step 3: Implement helper modules**

Replace `crates/urdisassembly/src/bits.rs` with:

```rust
pub fn bits(word: u32, lo: u8, hi: u8) -> u32 {
    debug_assert!(lo <= hi);
    debug_assert!(hi < 32);
    let width = u32::from(hi - lo + 1);
    let mask = if width == 32 {
        u32::MAX
    } else {
        (1u32 << width) - 1
    };
    (word >> lo) & mask
}

pub fn sign_extend(value: u32, width: u8) -> i64 {
    debug_assert!((1..=32).contains(&width));
    let shift = 64 - width;
    ((i64::from(value)) << shift) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_inclusive_bit_ranges() {
        assert_eq!(bits(0b1101_0110, 1, 3), 0b011);
        assert_eq!(bits(0b1101_0110, 4, 7), 0b1101);
    }

    #[test]
    fn sign_extends_values() {
        assert_eq!(sign_extend(0b0111, 4), 7);
        assert_eq!(sign_extend(0b1000, 4), -8);
        assert_eq!(sign_extend(0b1111, 4), -1);
    }
}
```

Create `crates/urdisassembly/src/arch/mod.rs`:

```rust
pub mod aarch64;
```

Create `crates/urdisassembly/src/arch/aarch64/mod.rs`:

```rust
pub mod registers;
```

Replace `crates/urdisassembly/src/arch/aarch64/registers.rs` with:

```rust
use crate::model::Register;

pub fn x(reg: u32) -> Register {
    Register {
        name: match reg {
            30 => "lr".to_string(),
            _ => format!("x{reg}"),
        },
    }
}

pub fn w(reg: u32) -> Register {
    Register {
        name: format!("w{reg}"),
    }
}

pub fn x_or_sp(reg: u32) -> Register {
    Register {
        name: if reg == 31 {
            "sp".to_string()
        } else {
            format!("x{reg}")
        },
    }
}

pub fn w_or_sp(reg: u32) -> Register {
    Register {
        name: if reg == 31 {
            "wsp".to_string()
        } else {
            format!("w{reg}")
        },
    }
}

pub fn x_or_zr(reg: u32) -> Register {
    Register {
        name: if reg == 31 {
            "xzr".to_string()
        } else {
            format!("x{reg}")
        },
    }
}

pub fn w_or_zr(reg: u32) -> Register {
    Register {
        name: if reg == 31 {
            "wzr".to_string()
        } else {
            format!("w{reg}")
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_general_registers() {
        assert_eq!(x(0).name, "x0");
        assert_eq!(w(1).name, "w1");
        assert_eq!(x(30).name, "lr");
    }

    #[test]
    fn formats_zero_and_stack_registers_by_context() {
        assert_eq!(x_or_sp(31).name, "sp");
        assert_eq!(w_or_sp(31).name, "wsp");
        assert_eq!(x_or_zr(31).name, "xzr");
        assert_eq!(w_or_zr(31).name, "wzr");
    }
}
```

Modify `crates/urdisassembly/src/lib.rs`:

```rust
pub mod arch;
pub mod bits;
pub mod decoder;
pub mod error;
pub mod model;

pub use decoder::Decoder;
pub use error::{DecodeError, Result};
pub use model::{
    Architecture, DecodeOptions, DecodeStatus, Endian, FlowKind, Instruction, InstructionKind,
    MemoryOperand, Operand, Register,
};
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p urdisassembly bits arch::aarch64::registers
```

Expected: helper and register tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/urdisassembly/src
git commit -m "feat: add aarch64 bit and register helpers"
```

Expected: commit succeeds.

## Task 3: Implement Unknown Fallback And Formatter Foundation

**Files:**
- Create: `crates/urdisassembly/src/arch/aarch64/decode.rs`
- Create: `crates/urdisassembly/src/arch/aarch64/format.rs`
- Modify: `crates/urdisassembly/src/arch/aarch64/mod.rs`
- Modify: `crates/urdisassembly/src/decoder.rs`
- Modify: `crates/urdisassembly/tests/aarch64_unknown.rs`

- [ ] **Step 1: Write failing unknown fallback tests**

Create `crates/urdisassembly/tests/aarch64_unknown.rs`:

```rust
use urdisassembly::{
    Architecture, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind,
};

#[test]
fn unknown_word_decodes_as_word_directive() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let insn = decoder
        .decode_one(&0xffff_ffffu32.to_le_bytes(), 0x400080)
        .unwrap();

    assert_eq!(insn.address, 0x400080);
    assert_eq!(insn.size, 4);
    assert_eq!(insn.mnemonic, ".word");
    assert_eq!(insn.operand_text(), "0xffffffff");
    assert_eq!(insn.text, ".word 0xffffffff");
    assert_eq!(insn.kind, InstructionKind::Unknown);
    assert_eq!(insn.flow, FlowKind::Fallthrough);
    assert_eq!(insn.branch_target, None);
    assert_eq!(insn.status, DecodeStatus::Unknown);
}

#[test]
fn truncated_input_is_a_hard_error() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let err = decoder.decode_one(&[0xc0, 0x03, 0x5f], 0x400080).unwrap_err();

    assert_eq!(
        err.to_string(),
        "expected at least 4 bytes, got 3"
    );
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p urdisassembly --test aarch64_unknown
```

Expected: compile error because `Decoder::decode_one` does not exist.

- [ ] **Step 3: Implement formatter foundation and unknown decode**

Modify `crates/urdisassembly/src/arch/aarch64/mod.rs`:

```rust
pub mod decode;
pub mod format;
pub mod registers;
```

Create `crates/urdisassembly/src/arch/aarch64/format.rs`:

```rust
use crate::model::{MemoryOperand, Operand, Register};

pub fn render_instruction(mnemonic: &str, operands: &[Operand]) -> String {
    let operand_text = render_operands(operands);
    if operand_text.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{mnemonic} {operand_text}")
    }
}

pub fn render_operands(operands: &[Operand]) -> String {
    operands
        .iter()
        .map(render_operand)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn render_operand(operand: &Operand) -> String {
    match operand {
        Operand::Register(reg) => reg.name.clone(),
        Operand::Immediate(value) => format!("#0x{:x}", value),
        Operand::AbsoluteAddress(addr) => format!("0x{addr:x}"),
        Operand::Memory(mem) => render_memory(mem),
        Operand::Condition(cond) => cond.clone(),
    }
}

fn render_memory(mem: &MemoryOperand) -> String {
    if mem.offset == 0 && !mem.writeback && !mem.post_index {
        format!("[{}]", mem.base.name)
    } else if mem.post_index {
        format!("[{}], #0x{:x}", mem.base.name, mem.offset)
    } else if mem.writeback {
        format!("[{}, #0x{:x}]!", mem.base.name, mem.offset)
    } else {
        format!("[{}, #0x{:x}]", mem.base.name, mem.offset)
    }
}

pub fn reg(name: impl Into<String>) -> Operand {
    Operand::Register(Register { name: name.into() })
}
```

Create `crates/urdisassembly/src/arch/aarch64/decode.rs`:

```rust
use crate::{
    arch::aarch64::format::render_instruction,
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

pub fn decode_word(word: u32, address: u64) -> Instruction {
    unknown(word, address)
}

pub fn unknown(word: u32, address: u64) -> Instruction {
    let operands = vec![Operand::AbsoluteAddress(u64::from(word))];
    Instruction {
        address,
        size: 4,
        bytes: word.to_le_bytes().to_vec(),
        mnemonic: ".word".to_string(),
        text: render_instruction(".word", &operands),
        operands,
        kind: InstructionKind::Unknown,
        flow: FlowKind::Fallthrough,
        branch_target: None,
        status: DecodeStatus::Unknown,
    }
}
```

Modify `crates/urdisassembly/src/decoder.rs`:

```rust
use crate::{
    arch::aarch64,
    error::{DecodeError, Result},
    model::{Architecture, DecodeOptions, Endian, Instruction},
};

#[derive(Debug, Clone)]
pub struct Decoder {
    architecture: Architecture,
    options: DecodeOptions,
}

impl Decoder {
    pub fn new(architecture: Architecture, options: DecodeOptions) -> Result<Self> {
        match (architecture, options.endian) {
            (Architecture::Aarch64, Endian::Little) => Ok(Self {
                architecture,
                options,
            }),
        }
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn options(&self) -> DecodeOptions {
        self.options
    }

    pub fn decode_one(&self, bytes: &[u8], address: u64) -> Result<Instruction> {
        let word = Self::require_word(bytes)?;
        match self.architecture {
            Architecture::Aarch64 => Ok(aarch64::decode::decode_word(word, address)),
        }
    }

    pub fn require_word(bytes: &[u8]) -> Result<u32> {
        let word = bytes
            .get(..4)
            .ok_or(DecodeError::TruncatedInstruction {
                expected: 4,
                actual: bytes.len(),
            })?;
        Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
    }
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p urdisassembly --test aarch64_unknown
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/urdisassembly
git commit -m "feat: add aarch64 unknown fallback"
```

Expected: commit succeeds.

## Task 4: Decode AArch64 Control Flow

**Files:**
- Modify: `crates/urdisassembly/src/arch/aarch64/decode.rs`
- Modify: `crates/urdisassembly/tests/aarch64_decode.rs`

- [ ] **Step 1: Write golden tests for control-flow instructions**

Create `crates/urdisassembly/tests/aarch64_decode.rs`:

```rust
use urdisassembly::{
    Architecture, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind,
};

fn decode(word: u32, address: u64) -> urdisassembly::Instruction {
    Decoder::new(Architecture::Aarch64, DecodeOptions::default())
        .unwrap()
        .decode_one(&word.to_le_bytes(), address)
        .unwrap()
}

#[test]
fn decodes_return_and_indirect_branches() {
    let ret = decode(0xd65f03c0, 0x400080);
    assert_eq!(ret.mnemonic, "ret");
    assert_eq!(ret.operand_text(), "");
    assert_eq!(ret.flow, FlowKind::Return);
    assert_eq!(ret.kind, InstructionKind::Return);
    assert_eq!(ret.status, DecodeStatus::Complete);

    let br = decode(0xd61f0000, 0x400084);
    assert_eq!(br.text, "br x0");
    assert_eq!(br.flow, FlowKind::IndirectBranch);

    let blr = decode(0xd63f0020, 0x400088);
    assert_eq!(blr.text, "blr x1");
    assert_eq!(blr.flow, FlowKind::IndirectCall);
}

#[test]
fn decodes_unconditional_branch_immediates() {
    let b = decode(0x14000004, 0x400100);
    assert_eq!(b.text, "b 0x400110");
    assert_eq!(b.branch_target, Some(0x400110));
    assert_eq!(b.flow, FlowKind::Branch);

    let bl = decode(0x97fffffc, 0x400100);
    assert_eq!(bl.text, "bl 0x4000f0");
    assert_eq!(bl.branch_target, Some(0x4000f0));
    assert_eq!(bl.flow, FlowKind::Call);
    assert_eq!(bl.kind, InstructionKind::Call);
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p urdisassembly --test aarch64_decode
```

Expected: tests fail because all words still decode as `.word`.

- [ ] **Step 3: Implement mask/match control-flow patterns**

Modify `crates/urdisassembly/src/arch/aarch64/decode.rs`:

```rust
use crate::{
    arch::aarch64::{
        format::render_instruction,
        registers::{x, x_or_zr},
    },
    bits::{bits, sign_extend},
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

struct Pattern {
    name: &'static str,
    mask: u32,
    value: u32,
    decode: fn(u32, u64) -> Instruction,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        name: "ret",
        mask: 0xffff_fc1f,
        value: 0xd65f_0000,
        decode: decode_ret,
    },
    Pattern {
        name: "br",
        mask: 0xffff_fc1f,
        value: 0xd61f_0000,
        decode: decode_br,
    },
    Pattern {
        name: "blr",
        mask: 0xffff_fc1f,
        value: 0xd63f_0000,
        decode: decode_blr,
    },
    Pattern {
        name: "b_bl",
        mask: 0x7c00_0000,
        value: 0x1400_0000,
        decode: decode_b_bl,
    },
];

pub fn decode_word(word: u32, address: u64) -> Instruction {
    for pattern in PATTERNS {
        if word & pattern.mask == pattern.value {
            return (pattern.decode)(word, address);
        }
    }
    unknown(word, address)
}

fn base(
    word: u32,
    address: u64,
    mnemonic: &str,
    operands: Vec<Operand>,
    kind: InstructionKind,
    flow: FlowKind,
    branch_target: Option<u64>,
) -> Instruction {
    Instruction {
        address,
        size: 4,
        bytes: word.to_le_bytes().to_vec(),
        mnemonic: mnemonic.to_string(),
        text: render_instruction(mnemonic, &operands),
        operands,
        kind,
        flow,
        branch_target,
        status: DecodeStatus::Complete,
    }
}

fn decode_ret(word: u32, address: u64) -> Instruction {
    let rn = bits(word, 5, 9);
    let operands = if rn == 30 {
        Vec::new()
    } else {
        vec![Operand::Register(x(rn))]
    };
    base(
        word,
        address,
        "ret",
        operands,
        InstructionKind::Return,
        FlowKind::Return,
        None,
    )
}

fn decode_br(word: u32, address: u64) -> Instruction {
    let rn = bits(word, 5, 9);
    base(
        word,
        address,
        "br",
        vec![Operand::Register(x_or_zr(rn))],
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
        None,
    )
}

fn decode_blr(word: u32, address: u64) -> Instruction {
    let rn = bits(word, 5, 9);
    base(
        word,
        address,
        "blr",
        vec![Operand::Register(x_or_zr(rn))],
        InstructionKind::Call,
        FlowKind::IndirectCall,
        None,
    )
}

fn decode_b_bl(word: u32, address: u64) -> Instruction {
    let link = bits(word, 31, 31) == 1;
    let imm26 = bits(word, 0, 25);
    let offset = sign_extend(imm26 << 2, 28);
    let target = address.wrapping_add_signed(offset);
    base(
        word,
        address,
        if link { "bl" } else { "b" },
        vec![Operand::AbsoluteAddress(target)],
        if link {
            InstructionKind::Call
        } else {
            InstructionKind::Branch
        },
        if link { FlowKind::Call } else { FlowKind::Branch },
        Some(target),
    )
}

pub fn unknown(word: u32, address: u64) -> Instruction {
    let operands = vec![Operand::AbsoluteAddress(u64::from(word))];
    Instruction {
        address,
        size: 4,
        bytes: word.to_le_bytes().to_vec(),
        mnemonic: ".word".to_string(),
        text: render_instruction(".word", &operands),
        operands,
        kind: InstructionKind::Unknown,
        flow: FlowKind::Fallthrough,
        branch_target: None,
        status: DecodeStatus::Unknown,
    }
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p urdisassembly --test aarch64_decode
```

Expected: control-flow golden tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/urdisassembly
git commit -m "feat: decode aarch64 control flow"
```

Expected: commit succeeds.

## Task 5: Decode Conditional Branches And PC-Relative Addressing

**Files:**
- Modify: `crates/urdisassembly/src/arch/aarch64/decode.rs`
- Modify: `crates/urdisassembly/tests/aarch64_decode.rs`

- [ ] **Step 1: Add golden tests**

Append to `crates/urdisassembly/tests/aarch64_decode.rs`:

```rust
#[test]
fn decodes_conditional_compare_and_test_branches() {
    let b_eq = decode(0x54000080, 0x400100);
    assert_eq!(b_eq.text, "b.eq 0x400110");
    assert_eq!(b_eq.flow, FlowKind::ConditionalBranch);
    assert_eq!(b_eq.branch_target, Some(0x400110));

    let cbz = decode(0xb4000080, 0x400100);
    assert_eq!(cbz.text, "cbz x0, 0x400110");
    assert_eq!(cbz.flow, FlowKind::ConditionalBranch);

    let cbnz = decode(0xb50000a1, 0x400100);
    assert_eq!(cbnz.text, "cbnz x1, 0x400114");
    assert_eq!(cbnz.flow, FlowKind::ConditionalBranch);

    let tbz = decode(0x36000082, 0x400100);
    assert_eq!(tbz.text, "tbz w2, #0x0, 0x400110");
    assert_eq!(tbz.flow, FlowKind::ConditionalBranch);

    let tbnz = decode(0x370000a3, 0x400100);
    assert_eq!(tbnz.text, "tbnz w3, #0x0, 0x400114");
    assert_eq!(tbnz.flow, FlowKind::ConditionalBranch);
}

#[test]
fn decodes_pc_relative_addressing() {
    let adr = decode(0x10000080, 0x400100);
    assert_eq!(adr.text, "adr x0, 0x400110");
    assert_eq!(adr.kind, InstructionKind::Address);
    assert_eq!(adr.flow, FlowKind::Fallthrough);

    let adrp = decode(0x90000080, 0x400100);
    assert_eq!(adrp.text, "adrp x0, 0x401000");
    assert_eq!(adrp.kind, InstructionKind::Address);
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p urdisassembly --test aarch64_decode
```

Expected: the new tests fail because the new groups decode as `.word`.

- [ ] **Step 3: Add condition names and decoders**

Modify `crates/urdisassembly/src/arch/aarch64/decode.rs` by adding patterns before `b_bl`:

```rust
    Pattern {
        name: "b_cond",
        mask: 0xff00_0010,
        value: 0x5400_0000,
        decode: decode_b_cond,
    },
    Pattern {
        name: "cbz_cbnz",
        mask: 0x7e00_0000,
        value: 0x3400_0000,
        decode: decode_cbz_cbnz,
    },
    Pattern {
        name: "tbz_tbnz",
        mask: 0x7e00_0000,
        value: 0x3600_0000,
        decode: decode_tbz_tbnz,
    },
    Pattern {
        name: "adr_adrp",
        mask: 0x1f00_0000,
        value: 0x1000_0000,
        decode: decode_adr_adrp,
    },
```

Add these helper functions:

```rust
fn condition_name(cond: u32) -> &'static str {
    match cond {
        0x0 => "eq",
        0x1 => "ne",
        0x2 => "cs",
        0x3 => "cc",
        0x4 => "mi",
        0x5 => "pl",
        0x6 => "vs",
        0x7 => "vc",
        0x8 => "hi",
        0x9 => "ls",
        0xa => "ge",
        0xb => "lt",
        0xc => "gt",
        0xd => "le",
        0xe => "al",
        _ => "nv",
    }
}

fn decode_b_cond(word: u32, address: u64) -> Instruction {
    let imm19 = bits(word, 5, 23);
    let offset = sign_extend(imm19 << 2, 21);
    let target = address.wrapping_add_signed(offset);
    let mnemonic = format!("b.{}", condition_name(bits(word, 0, 3)));
    base(
        word,
        address,
        &mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    )
}

fn decode_cbz_cbnz(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let nonzero = bits(word, 24, 24) == 1;
    let rt = bits(word, 0, 4);
    let imm19 = bits(word, 5, 23);
    let offset = sign_extend(imm19 << 2, 21);
    let target = address.wrapping_add_signed(offset);
    let reg = if is_64 {
        crate::arch::aarch64::registers::x(rt)
    } else {
        crate::arch::aarch64::registers::w(rt)
    };
    base(
        word,
        address,
        if nonzero { "cbnz" } else { "cbz" },
        vec![Operand::Register(reg), Operand::AbsoluteAddress(target)],
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        Some(target),
    )
}

fn decode_tbz_tbnz(word: u32, address: u64) -> Instruction {
    let nonzero = bits(word, 24, 24) == 1;
    let b5 = bits(word, 31, 31);
    let b40 = bits(word, 19, 23);
    let bit = (b5 << 5) | b40;
    let rt = bits(word, 0, 4);
    let imm14 = bits(word, 5, 18);
    let offset = sign_extend(imm14 << 2, 16);
    let target = address.wrapping_add_signed(offset);
    let reg = if b5 == 1 {
        crate::arch::aarch64::registers::x(rt)
    } else {
        crate::arch::aarch64::registers::w(rt)
    };
    base(
        word,
        address,
        if nonzero { "tbnz" } else { "tbz" },
        vec![
            Operand::Register(reg),
            Operand::Immediate(i64::from(bit)),
            Operand::AbsoluteAddress(target),
        ],
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        Some(target),
    )
}

fn decode_adr_adrp(word: u32, address: u64) -> Instruction {
    let page = bits(word, 31, 31) == 1;
    let rd = bits(word, 0, 4);
    let immlo = bits(word, 29, 30);
    let immhi = bits(word, 5, 23);
    let imm = (immhi << 2) | immlo;
    let target = if page {
        let offset = sign_extend(imm << 12, 33);
        (address & !0xfff).wrapping_add_signed(offset)
    } else {
        let offset = sign_extend(imm, 21);
        address.wrapping_add_signed(offset)
    };
    base(
        word,
        address,
        if page { "adrp" } else { "adr" },
        vec![Operand::Register(x(rd)), Operand::AbsoluteAddress(target)],
        InstructionKind::Address,
        FlowKind::Fallthrough,
        None,
    )
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p urdisassembly --test aarch64_decode
```

Expected: all current decode tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/urdisassembly
git commit -m "feat: decode aarch64 conditional branches"
```

Expected: commit succeeds.

## Task 6: Decode Common Arithmetic, Move, And System Hint Instructions

**Files:**
- Modify: `crates/urdisassembly/src/arch/aarch64/decode.rs`
- Modify: `crates/urdisassembly/tests/aarch64_decode.rs`

- [ ] **Step 1: Add golden tests**

Append to `crates/urdisassembly/tests/aarch64_decode.rs`:

```rust
#[test]
fn decodes_common_arithmetic_move_and_hint_forms() {
    assert_eq!(decode(0xd503201f, 0x400100).text, "nop");

    let add = decode(0x91002000, 0x400100);
    assert_eq!(add.text, "add x0, x0, #0x8");
    assert_eq!(add.kind, InstructionKind::Arithmetic);

    let sub = decode(0xd1002000, 0x400100);
    assert_eq!(sub.text, "sub x0, x0, #0x8");

    let cmp = decode(0xf100201f, 0x400100);
    assert_eq!(cmp.text, "cmp x0, #0x8");
    assert_eq!(cmp.kind, InstructionKind::Compare);

    let movz = decode(0xd2800020, 0x400100);
    assert_eq!(movz.text, "mov x0, #0x1");
    assert_eq!(movz.kind, InstructionKind::Move);

    let movk = decode(0xf2800041, 0x400100);
    assert_eq!(movk.text, "movk x1, #0x2");

    let mov_reg = decode(0xaa0103e0, 0x400100);
    assert_eq!(mov_reg.text, "mov x0, x1");
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p urdisassembly --test aarch64_decode
```

Expected: new cases fail as `.word`.

- [ ] **Step 3: Implement patterns and decoders**

Add patterns in `crates/urdisassembly/src/arch/aarch64/decode.rs` before unknown fallback:

```rust
    Pattern {
        name: "nop",
        mask: 0xffff_ffff,
        value: 0xd503_201f,
        decode: decode_nop,
    },
    Pattern {
        name: "add_sub_imm",
        mask: 0x1f00_0000,
        value: 0x1100_0000,
        decode: decode_add_sub_imm,
    },
    Pattern {
        name: "move_wide",
        mask: 0x1f80_0000,
        value: 0x1280_0000,
        decode: decode_move_wide,
    },
    Pattern {
        name: "logical_shifted_register",
        mask: 0x1f00_0000,
        value: 0x0a00_0000,
        decode: decode_logical_shifted_register,
    },
```

Add decoder functions:

```rust
fn decode_nop(word: u32, address: u64) -> Instruction {
    base(
        word,
        address,
        "nop",
        Vec::new(),
        InstructionKind::System,
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_add_sub_imm(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let sub = bits(word, 30, 30) == 1;
    let set_flags = bits(word, 29, 29) == 1;
    let shift = if bits(word, 22, 22) == 1 { 12 } else { 0 };
    let imm = i64::from(bits(word, 10, 21) << shift);
    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);
    let dst = if is_64 {
        crate::arch::aarch64::registers::x_or_sp(rd)
    } else {
        crate::arch::aarch64::registers::w_or_sp(rd)
    };
    let src = if is_64 {
        crate::arch::aarch64::registers::x_or_sp(rn)
    } else {
        crate::arch::aarch64::registers::w_or_sp(rn)
    };
    let mnemonic = match (sub, set_flags, rd == 31) {
        (true, true, true) => "cmp",
        (false, true, true) => "cmn",
        (true, true, false) => "subs",
        (false, true, false) => "adds",
        (true, false, _) => "sub",
        (false, false, _) => "add",
    };
    let operands = if matches!(mnemonic, "cmp" | "cmn") {
        vec![Operand::Register(src), Operand::Immediate(imm)]
    } else {
        vec![Operand::Register(dst), Operand::Register(src), Operand::Immediate(imm)]
    };
    base(
        word,
        address,
        mnemonic,
        operands,
        if matches!(mnemonic, "cmp" | "cmn") {
            InstructionKind::Compare
        } else {
            InstructionKind::Arithmetic
        },
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_move_wide(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let opc = bits(word, 29, 30);
    let hw = bits(word, 21, 22);
    let imm = i64::from(bits(word, 5, 20) << (hw * 16));
    let rd = bits(word, 0, 4);
    let reg = if is_64 {
        crate::arch::aarch64::registers::x(rd)
    } else {
        crate::arch::aarch64::registers::w(rd)
    };
    let mnemonic = match opc {
        0b00 => "movn",
        0b10 => "mov",
        0b11 => "movk",
        _ => "movz",
    };
    base(
        word,
        address,
        mnemonic,
        vec![Operand::Register(reg), Operand::Immediate(imm)],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_logical_shifted_register(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let opc = bits(word, 29, 30);
    let rn = bits(word, 5, 9);
    let rm = bits(word, 16, 20);
    let rd = bits(word, 0, 4);
    let dst = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rd)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rd)
    };
    let src1 = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rn)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rn)
    };
    let src2 = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rm)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rm)
    };
    let mnemonic = if opc == 0b01 && rn == 31 {
        "mov"
    } else {
        match opc {
            0b00 => "and",
            0b01 => "orr",
            0b10 => "eor",
            _ => "ands",
        }
    };
    let operands = if mnemonic == "mov" {
        vec![Operand::Register(dst), Operand::Register(src2)]
    } else {
        vec![Operand::Register(dst), Operand::Register(src1), Operand::Register(src2)]
    };
    base(
        word,
        address,
        mnemonic,
        operands,
        if mnemonic == "mov" {
            InstructionKind::Move
        } else {
            InstructionKind::Logical
        },
        FlowKind::Fallthrough,
        None,
    )
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p urdisassembly --test aarch64_decode
```

Expected: new arithmetic, move, and hint tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/urdisassembly
git commit -m "feat: decode common aarch64 data instructions"
```

Expected: commit succeeds.

## Task 7: Decode Common Load/Store Forms

**Files:**
- Modify: `crates/urdisassembly/src/arch/aarch64/decode.rs`
- Modify: `crates/urdisassembly/tests/aarch64_decode.rs`

- [ ] **Step 1: Add golden tests**

Append to `crates/urdisassembly/tests/aarch64_decode.rs`:

```rust
#[test]
fn decodes_common_load_store_forms() {
    let ldr = decode(0xf9400420, 0x400100);
    assert_eq!(ldr.text, "ldr x0, [x1, #0x8]");
    assert_eq!(ldr.kind, InstructionKind::Load);

    let str_ = decode(0xf9000822, 0x400100);
    assert_eq!(str_.text, "str x2, [x1, #0x10]");
    assert_eq!(str_.kind, InstructionKind::Store);

    let ldr_pre = decode(0xf8408c20, 0x400100);
    assert_eq!(ldr_pre.text, "ldr x0, [x1, #0x8]!");

    let str_post = decode(0xf8008422, 0x400100);
    assert_eq!(str_post.text, "str x2, [x1], #0x8");
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p urdisassembly --test aarch64_decode
```

Expected: load/store cases fail as `.word`.

- [ ] **Step 3: Implement load/store decoders**

Add patterns:

```rust
    Pattern {
        name: "load_store_unsigned",
        mask: 0x3b00_0000,
        value: 0x3900_0000,
        decode: decode_load_store_unsigned,
    },
    Pattern {
        name: "load_store_unscaled",
        mask: 0x3b20_0400,
        value: 0x3800_0400,
        decode: decode_load_store_unscaled,
    },
```

Add functions:

```rust
fn access_size_bytes(word: u32) -> i64 {
    1i64 << bits(word, 30, 31)
}

fn decode_load_store_unsigned(word: u32, address: u64) -> Instruction {
    let load = bits(word, 22, 22) == 1;
    let size = bits(word, 30, 31);
    let imm = i64::from(bits(word, 10, 21)) * access_size_bytes(word);
    let rn = bits(word, 5, 9);
    let rt = bits(word, 0, 4);
    let reg = if size == 0b11 {
        crate::arch::aarch64::registers::x(rt)
    } else {
        crate::arch::aarch64::registers::w(rt)
    };
    let base_reg = crate::arch::aarch64::registers::x_or_sp(rn);
    base(
        word,
        address,
        if load { "ldr" } else { "str" },
        vec![
            Operand::Register(reg),
            Operand::Memory(crate::model::MemoryOperand {
                base: base_reg,
                offset: imm,
                writeback: false,
                post_index: false,
            }),
        ],
        if load {
            InstructionKind::Load
        } else {
            InstructionKind::Store
        },
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_load_store_unscaled(word: u32, address: u64) -> Instruction {
    let load = bits(word, 22, 22) == 1;
    let size = bits(word, 30, 31);
    let post_index = bits(word, 10, 11) == 0b01;
    let pre_index = bits(word, 10, 11) == 0b11;
    let imm = sign_extend(bits(word, 12, 20), 9);
    let rn = bits(word, 5, 9);
    let rt = bits(word, 0, 4);
    let reg = if size == 0b11 {
        crate::arch::aarch64::registers::x(rt)
    } else {
        crate::arch::aarch64::registers::w(rt)
    };
    let base_reg = crate::arch::aarch64::registers::x_or_sp(rn);
    base(
        word,
        address,
        if load { "ldr" } else { "str" },
        vec![
            Operand::Register(reg),
            Operand::Memory(crate::model::MemoryOperand {
                base: base_reg,
                offset: imm,
                writeback: pre_index,
                post_index,
            }),
        ],
        if load {
            InstructionKind::Load
        } else {
            InstructionKind::Store
        },
        FlowKind::Fallthrough,
        None,
    )
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p urdisassembly --test aarch64_decode
```

Expected: load/store tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/urdisassembly
git commit -m "feat: decode common aarch64 load store forms"
```

Expected: commit succeeds.

## Task 8: Add Coverage Matrix And Corpus Coverage Example

**Files:**
- Create: `docs/urdisassembly/aarch64-coverage.md`
- Create: `crates/urdisassembly/examples/coverage.rs`

- [ ] **Step 1: Write the coverage matrix**

Create `docs/urdisassembly/aarch64-coverage.md`:

```markdown
# AArch64 Coverage Matrix

| Encoding group | Representative mnemonics | Decode | Format | Flow semantics | Golden tests | Corpus evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Unconditional branch immediate | `b`, `bl` | Implemented | Implemented | Implemented | Yes | Not measured | Direct targets use absolute addresses. |
| Unconditional branch register | `br`, `blr`, `ret` | Implemented | Implemented | Implemented | Yes | Not measured | `ret` omits `lr`. |
| Conditional branch immediate | `b.cond` | Implemented | Implemented | Implemented | Yes | Not measured | All condition suffixes are named. |
| Compare and branch | `cbz`, `cbnz` | Implemented | Implemented | Implemented | Yes | Not measured | 32-bit and 64-bit register forms supported. |
| Test and branch | `tbz`, `tbnz` | Implemented | Implemented | Implemented | Yes | Not measured | 32-bit and 64-bit register forms supported. |
| PC-relative addressing | `adr`, `adrp` | Implemented | Implemented | Implemented | Yes | Not measured | Targets are absolute. |
| Load/store unsigned immediate | `ldr`, `str` | Partial | Partial | Implemented | Yes | Not measured | Common integer register forms only. |
| Load/store pre/post index | `ldr`, `str` | Partial | Partial | Implemented | Yes | Not measured | Common integer register forms only. |
| Add/sub immediate | `add`, `adds`, `sub`, `subs`, `cmp`, `cmn` | Implemented | Implemented | Implemented | Yes | Not measured | Immediate shift supported. |
| Logical shifted register | `and`, `orr`, `eor`, `ands`, `mov` | Partial | Partial | Implemented | Yes | Not measured | Shift display is not emitted in first pass. |
| Move wide | `movz`, `movn`, `movk`, `mov` | Partial | Implemented | Implemented | Yes | Not measured | `movz` is displayed as `mov`. |
| Logical immediate | `and`, `orr`, `eor`, `ands` | Not implemented | Not implemented | Not implemented | No | Not measured | Add after corpus evidence shows priority. |
| Data processing register | `add`, `sub`, `mul`, `lsl`, `lsr` | Partial | Partial | Implemented | Limited | Not measured | Only logical shifted register subset is covered. |
| System hints | `nop` | Partial | Implemented | Implemented | Yes | Not measured | Other hints remain unknown. |
| SIMD/FP | `fmov`, `fadd`, `ldr q0` | Not implemented | Not implemented | Not implemented | No | Not measured | Track via corpus unknown clusters. |
| System registers | `mrs`, `msr`, `sys` | Not implemented | Not implemented | Not implemented | No | Not measured | Track via corpus unknown clusters. |
```

- [ ] **Step 2: Add the coverage example**

Create `crates/urdisassembly/examples/coverage.rs`:

```rust
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

use goblin::{elf::program_header, Object};
use urdisassembly::{Architecture, DecodeOptions, DecodeStatus, Decoder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = env::args()
        .nth(1)
        .ok_or("usage: cargo run -p urdisassembly --example coverage -- <file-or-directory>")?;
    let mut files = Vec::new();
    collect_files(Path::new(&root), &mut files)?;

    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default())?;
    let mut decoded = 0u64;
    let mut unknown = 0u64;
    let mut clusters: BTreeMap<u32, Vec<(u64, u32)>> = BTreeMap::new();

    for path in files {
        let bytes = fs::read(&path)?;
        let Ok(Object::Elf(elf)) = Object::parse(&bytes) else {
            continue;
        };
        if elf.header.e_machine != goblin::elf::header::EM_AARCH64 {
            continue;
        }
        for ph in elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == program_header::PT_LOAD && ph.p_flags & program_header::PF_X != 0)
        {
            let start = ph.p_offset as usize;
            let end = start.saturating_add(ph.p_filesz as usize).min(bytes.len());
            for (idx, chunk) in bytes[start..end].chunks_exact(4).enumerate() {
                let addr = ph.p_vaddr + (idx as u64 * 4);
                let insn = decoder.decode_one(chunk, addr)?;
                decoded += 1;
                if insn.status == DecodeStatus::Unknown {
                    unknown += 1;
                    let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let key = word & 0x1fe0_0000;
                    clusters.entry(key).or_default().push((addr, word));
                }
            }
        }
    }

    let unknown_rate = if decoded == 0 {
        0.0
    } else {
        (unknown as f64 / decoded as f64) * 100.0
    };
    println!("decoded: {decoded}");
    println!("unknown: {unknown}");
    println!("unknown_rate: {unknown_rate:.2}%");
    println!();
    println!("top_unknown_patterns:");

    let mut ranked = clusters.into_iter().collect::<Vec<_>>();
    ranked.sort_by_key(|(_, examples)| std::cmp::Reverse(examples.len()));
    for (key, examples) in ranked.into_iter().take(10) {
        let rendered = examples
            .iter()
            .take(3)
            .map(|(addr, word)| format!("0x{addr:x}:0x{word:08x}"))
            .collect::<Vec<_>>()
            .join(",");
        println!("  key=0x{key:08x} count={} examples={rendered}", examples.len());
    }

    Ok(())
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}
```

- [ ] **Step 3: Run coverage example help-path failure**

Run:

```bash
cargo run -p urdisassembly --example coverage
```

Expected: command exits with an error containing `usage: cargo run -p urdisassembly --example coverage -- <file-or-directory>`.

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p urdisassembly
```

Expected: all `urdisassembly` tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add docs/urdisassembly crates/urdisassembly/examples
git commit -m "docs: add aarch64 coverage tracking"
```

Expected: commit succeeds.

## Task 9: Migrate Ura Instruction Model And Schema To Version 2

**Files:**
- Modify: `crates/ura-core/src/model.rs`
- Modify: `crates/ura-core/src/db.rs`
- Modify: `crates/ura-core/src/project.rs`
- Modify: `crates/ura-core/tests/project_roundtrip.rs`

- [ ] **Step 1: Add failing schema v2 roundtrip and migration tests**

Append to `crates/ura-core/tests/project_roundtrip.rs`:

```rust
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
fn opening_schema_v1_project_migrates_and_preserves_user_truth() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    {
        let conn = rusqlite::Connection::open(&project)?;
        conn.execute(
            "UPDATE metadata SET value = '1' WHERE key = 'schema_version'",
            [],
        )?;
        conn.execute("ALTER TABLE instructions RENAME TO instructions_v2", [])?;
        conn.execute(
            "CREATE TABLE instructions (
                addr INTEGER PRIMARY KEY,
                size INTEGER NOT NULL,
                bytes BLOB NOT NULL,
                mnemonic TEXT NOT NULL,
                operands TEXT NOT NULL,
                fallthrough INTEGER,
                branch_target INTEGER,
                function_addr INTEGER
            )",
            [],
        )?;
        conn.execute(
            "INSERT INTO instructions(addr, size, bytes, mnemonic, operands, fallthrough, branch_target, function_addr)
             SELECT addr, size, bytes, mnemonic, operands, fallthrough, branch_target, function_addr FROM instructions_v2",
            [],
        )?;
        conn.execute("DROP TABLE instructions_v2", [])?;
    }

    commands::make_function(&project, 0x400080)?;
    commands::rename(&project, 0x400080, "manual_ret")?;
    commands::comment(&project, 0x400080, "manual function")?;

    let funcs = commands::functions(&project)?;
    let comments = commands::comments(&project, 0x400080)?;
    let info = commands::info(&project)?;

    assert_eq!(info.schema_version, 2);
    assert!(funcs
        .iter()
        .any(|func| func.addr == 0x400080 && func.name == "manual_ret"));
    assert_eq!(comments, vec!["manual function".to_string()]);
    Ok(())
}
```

Add `rusqlite.workspace = true` under `[dev-dependencies]` in `crates/ura-core/Cargo.toml` if the test needs it explicitly.

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p ura-core --test project_roundtrip
```

Expected: compile errors because `Instruction` lacks the new fields and schema version is still 1.

- [ ] **Step 3: Extend `Instruction` model**

Modify `crates/ura-core/src/model.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub addr: u64,
    pub size: u8,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub text: String,
    pub kind: String,
    pub flow: String,
    pub fallthrough: Option<u64>,
    pub branch_target: Option<u64>,
    pub decode_status: String,
    pub decoder: String,
    pub decoder_version: String,
    pub function_addr: Option<u64>,
}
```

- [ ] **Step 4: Update schema initialization and migration**

Modify `crates/ura-core/src/db.rs`:

```rust
pub const SCHEMA_VERSION: i64 = 2;
```

Replace the `CREATE TABLE IF NOT EXISTS instructions` block with:

```sql
        CREATE TABLE IF NOT EXISTS instructions (
            addr INTEGER PRIMARY KEY,
            size INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            mnemonic TEXT NOT NULL,
            operands TEXT NOT NULL,
            text TEXT NOT NULL,
            kind TEXT NOT NULL,
            flow TEXT NOT NULL,
            fallthrough INTEGER,
            branch_target INTEGER,
            decode_status TEXT NOT NULL,
            decoder TEXT NOT NULL,
            decoder_version TEXT NOT NULL,
            function_addr INTEGER
        );
```

Add this migration function near `initialize`:

```rust
pub fn migrate(conn: &Connection) -> Result<()> {
    let Some(version) = get_metadata(conn, "schema_version")? else {
        return Err(UraError::NotFound("schema_version metadata".to_string()));
    };
    let version = version
        .parse::<i64>()
        .map_err(|err| UraError::Unsupported(format!("invalid schema_version: {err}")))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version != 1 {
        return Err(UraError::Unsupported(format!(
            "schema version {version}, expected {SCHEMA_VERSION}"
        )));
    }
    conn.execute("DROP TABLE IF EXISTS instructions", [])?;
    conn.execute(
        "CREATE TABLE instructions (
            addr INTEGER PRIMARY KEY,
            size INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            mnemonic TEXT NOT NULL,
            operands TEXT NOT NULL,
            text TEXT NOT NULL,
            kind TEXT NOT NULL,
            flow TEXT NOT NULL,
            fallthrough INTEGER,
            branch_target INTEGER,
            decode_status TEXT NOT NULL,
            decoder TEXT NOT NULL,
            decoder_version TEXT NOT NULL,
            function_addr INTEGER
        )",
        [],
    )?;
    set_metadata(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
    Ok(())
}
```

Update `insert_instructions` SQL and params:

```rust
"INSERT INTO instructions(addr, size, bytes, mnemonic, operands, text, kind, flow, fallthrough, branch_target, decode_status, decoder, decoder_version, function_addr)
 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"
```

with params:

```rust
params![
    to_i64(insn.addr)?,
    i64::from(insn.size),
    insn.bytes,
    insn.mnemonic,
    insn.operands,
    insn.text,
    insn.kind,
    insn.flow,
    optional_to_i64(insn.fallthrough)?,
    optional_to_i64(insn.branch_target)?,
    insn.decode_status,
    insn.decoder,
    insn.decoder_version,
    optional_to_i64(insn.function_addr)?
]
```

Update `query_disasm` to select and map all fields:

```rust
"SELECT addr, size, bytes, mnemonic, operands, text, kind, flow, fallthrough, branch_target, decode_status, decoder, decoder_version, function_addr
 FROM instructions WHERE addr >= ?1 ORDER BY addr LIMIT ?2"
```

with row mapping:

```rust
Instruction {
    addr: from_i64(row.get(0)?),
    size: row.get::<_, i64>(1)? as u8,
    bytes: row.get(2)?,
    mnemonic: row.get(3)?,
    operands: row.get(4)?,
    text: row.get(5)?,
    kind: row.get(6)?,
    flow: row.get(7)?,
    fallthrough: row.get::<_, Option<i64>>(8)?.map(from_i64),
    branch_target: row.get::<_, Option<i64>>(9)?.map(from_i64),
    decode_status: row.get(10)?,
    decoder: row.get(11)?,
    decoder_version: row.get(12)?,
    function_addr: row.get::<_, Option<i64>>(13)?.map(from_i64),
}
```

- [ ] **Step 5: Run migrations on project open**

Modify `crates/ura-core/src/project.rs` `Project::open`:

```rust
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = db::open_connection(&path)?;
        db::migrate(&conn)?;
        Ok(Self { path, conn })
    }
```

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p ura-core --test project_roundtrip
```

Expected: project roundtrip tests pass after disassembly integration is complete. If they still fail because `analysis/disasm.rs` has not been updated to populate new fields, continue to Task 10 before committing this task.

- [ ] **Step 7: Commit after the tests pass with Task 10 changes**

Run:

```bash
git add crates/ura-core
git commit -m "feat: migrate ura project schema for decoder metadata"
```

Expected: commit succeeds after Task 10 supplies new instruction metadata.

## Task 10: Replace Capstone In `ura-core` Disassembly

**Files:**
- Modify: `crates/ura-core/Cargo.toml`
- Modify: `crates/ura-core/src/analysis/disasm.rs`
- Modify: `crates/ura-core/src/analysis/functions.rs`
- Modify: `crates/ura-core/src/analysis/xrefs.rs`
- Modify: `crates/ura-core/src/analysis/diagnostics.rs`
- Modify: `crates/ura-core/tests/analysis_smoke.rs`

- [ ] **Step 1: Add failing analysis tests for structured flow and unknown decode**

Append to `crates/ura-core/tests/analysis_smoke.rs`:

```rust
#[test]
fn branch_and_call_xrefs_use_decoder_flow() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x94000002u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0x14000003u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x90..0x94].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let xrefs_to_88 = commands::xrefs(&project, 0x400088)?;
    let xrefs_to_90 = commands::xrefs(&project, 0x400090)?;

    assert!(xrefs_to_88.iter().any(|xref| xref.from_addr == 0x400080));
    assert!(xrefs_to_90.iter().any(|xref| xref.from_addr == 0x400084));
    Ok(())
}

#[test]
fn unknown_instruction_is_recorded_and_diagnosed() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0xffffffffu32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;
    let diagnostics = commands::diagnostics(&project)?;

    assert_eq!(disasm[0].text, ".word 0xffffffff");
    assert_eq!(disasm[0].decode_status, "Unknown");
    assert!(diagnostics
        .iter()
        .any(|diag| diag.addr == Some(0x400080) && diag.message.contains("unknown instruction")));
    Ok(())
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p ura-core --test analysis_smoke
```

Expected: compile errors until Task 9 and disassembly integration are complete.

- [ ] **Step 3: Replace dependency**

Modify `crates/ura-core/Cargo.toml`:

```toml
[dependencies]
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
rusqlite.workspace = true
goblin.workspace = true
urdisassembly.workspace = true
```

- [ ] **Step 4: Replace `analysis/disasm.rs`**

Replace `crates/ura-core/src/analysis/disasm.rs`:

```rust
use crate::{elf_loader::LoadedElf, model::Instruction, Result, UraError};

pub fn linear_disassemble(loaded: &LoadedElf) -> Result<Vec<Instruction>> {
    let decoder = urdisassembly::Decoder::new(
        urdisassembly::Architecture::Aarch64,
        urdisassembly::DecodeOptions::default(),
    )
    .map_err(|err| UraError::Analysis(err.to_string()))?;

    let mut out = Vec::new();
    for (start, end) in loaded.executable_ranges() {
        let size = (end - start) as usize;
        let Some(bytes) = loaded.bytes_at(start, size) else {
            continue;
        };
        for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
            let addr = start + (idx as u64 * 4);
            let decoded = decoder
                .decode_one(chunk, addr)
                .map_err(|err| UraError::Analysis(err.to_string()))?;
            let flow = format!("{:?}", decoded.flow);
            let fallthrough = match decoded.flow {
                urdisassembly::FlowKind::Branch | urdisassembly::FlowKind::Return => None,
                urdisassembly::FlowKind::IndirectBranch => None,
                _ => Some(addr + u64::from(decoded.size)),
            };
            out.push(Instruction {
                addr: decoded.address,
                size: decoded.size,
                bytes: decoded.bytes,
                mnemonic: decoded.mnemonic,
                operands: decoded.operand_text(),
                text: decoded.text,
                kind: format!("{:?}", decoded.kind),
                flow,
                fallthrough,
                branch_target: decoded.branch_target,
                decode_status: format!("{:?}", decoded.status),
                decoder: "urdisassembly/aarch64".to_string(),
                decoder_version: env!("CARGO_PKG_VERSION").to_string(),
                function_addr: None,
            });
        }
    }
    Ok(out)
}
```

- [ ] **Step 5: Update functions and xrefs to use structured fields**

Modify `crates/ura-core/src/analysis/functions.rs`:

```rust
        if matches!(insn.flow.as_str(), "Call" | "Branch" | "ConditionalBranch") {
            if let Some(target) = insn.branch_target {
                starts.insert((target, FunctionSource::BranchTarget));
            }
        }
```

Modify `first_terminal_end`:

```rust
        .find(|insn| matches!(insn.flow.as_str(), "Return" | "Branch" | "IndirectBranch"))
```

Modify `crates/ura-core/src/analysis/xrefs.rs`:

```rust
        if let Some(target) = insn.branch_target {
            let kind = if insn.flow == "Call" || insn.flow == "IndirectCall" || insn.kind == "Call" {
                XrefKind::Call
            } else {
                XrefKind::Code
            };
            out.push(Xref {
                from_addr: insn.addr,
                to_addr: target,
                kind,
            });
        }
```

Modify `crates/ura-core/src/analysis/diagnostics.rs`:

```rust
use crate::model::{Diagnostic, Instruction};

pub fn collect_diagnostics(instructions: &[Instruction]) -> Vec<Diagnostic> {
    instructions
        .iter()
        .filter(|insn| insn.decode_status == "Unknown" || insn.mnemonic.is_empty())
        .map(|insn| Diagnostic {
            addr: Some(insn.addr),
            severity: "warning".to_string(),
            message: if insn.decode_status == "Unknown" {
                "unknown instruction".to_string()
            } else {
                "instruction decoded without mnemonic".to_string()
            },
        })
        .collect()
}
```

- [ ] **Step 6: Run core tests**

Run:

```bash
cargo test -p ura-core
```

Expected: all `ura-core` tests pass, including Task 9 tests.

- [ ] **Step 7: Commit Task 9 and Task 10 together if necessary**

If Task 9 was not committed because it needed Task 10, commit both now:

```bash
git add crates/ura-core
git commit -m "feat: replace capstone with urdisassembly"
```

Expected: commit succeeds.

## Task 11: Remove Capstone From The Workspace Dependency Graph

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

- [ ] **Step 1: Verify capstone is still present before cleanup**

Run:

```bash
rg -n "capstone|capstone-sys" Cargo.toml Cargo.lock crates
```

Expected: matches remain in root `Cargo.toml`, `Cargo.lock`, or old code if cleanup is incomplete.

- [ ] **Step 2: Remove capstone workspace dependency**

Ensure root `Cargo.toml` has no `capstone = "0.12"` line and contains:

```toml
urdisassembly = { path = "crates/urdisassembly" }
```

- [ ] **Step 3: Update lockfile**

Run:

```bash
cargo update -p capstone --precise 0.12.0
```

Expected: if Cargo cannot update a removed package directly, run the next command instead:

```bash
cargo check --workspace
```

Expected: workspace checks successfully and `Cargo.lock` is rewritten without unused capstone packages.

- [ ] **Step 4: Verify capstone is gone**

Run:

```bash
rg -n "capstone|capstone-sys" Cargo.toml Cargo.lock crates
cargo tree -p ura-core
```

Expected: `rg` finds no matches. `cargo tree -p ura-core` shows `urdisassembly` and does not show `capstone` or `capstone-sys`.

- [ ] **Step 5: Commit**

Run:

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: remove capstone dependency"
```

Expected: commit succeeds.

## Task 12: Full Workspace Verification

**Files:**
- No source edits expected unless verification finds a defect.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt --all --check
```

Expected: passes. If it fails, run `cargo fmt --all`, inspect the diff, and include formatting changes in the verification commit.

- [ ] **Step 2: Run all tests**

Run:

```bash
cargo test --workspace
```

Expected: all workspace tests pass.

- [ ] **Step 3: Run dependency verification**

Run:

```bash
rg -n "capstone|capstone-sys" Cargo.toml Cargo.lock crates
cargo tree -p ura-core
```

Expected: `rg` finds no matches. `cargo tree -p ura-core` includes `urdisassembly`.

- [ ] **Step 4: Run coverage example on the in-test fixture path if a real corpus is unavailable**

Run:

```bash
cargo run -p urdisassembly --example coverage -- crates/ura-core/tests
```

Expected: command completes and prints `decoded`, `unknown`, `unknown_rate`, and `top_unknown_patterns`. It may report zero decoded instructions if no ELF files exist under the test directory; that is acceptable for command-path verification.

- [ ] **Step 5: Commit final verification fixes if needed**

Run:

```bash
git status --short
```

If files changed during formatting or verification fixes:

```bash
git add <changed-files>
git commit -m "test: verify urdisassembly integration"
```

Expected: either the working tree is clean or the final verification commit succeeds.
