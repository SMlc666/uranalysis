# Urcodec Declarative Forms Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `urdisassembly` with `urcodec`, then add a seed declarative instruction-form layer that drives decode, encode, canonical text, parsing, and roundtrip tests from one form definition.

**Architecture:** First migrate the existing decoder and public instruction model into `urcodec` without behavior changes. Then move consumers to `urcodec`, remove `urdisassembly`, and introduce seed forms inside `urcodec` while keeping generic decode/encode/text engines separate from per-architecture form definitions.

**Tech Stack:** Rust 2021 workspace, `serde`, `thiserror`, existing `cargo fmt`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` verification.

---

## File Structure

Create:

- `crates/urcodec/Cargo.toml` - new codec crate manifest.
- `crates/urcodec/src/lib.rs` - public exports for model, decoder, encoder, text, and errors.
- `crates/urcodec/src/model.rs` - public instruction model moved from `urdisassembly`.
- `crates/urcodec/src/error.rs` - decode, encode, and text parse errors.
- `crates/urcodec/src/decoder.rs` - compatibility decoder facade.
- `crates/urcodec/src/encode.rs` - generic encoder facade.
- `crates/urcodec/src/text.rs` - canonical formatter and parser facade.
- `crates/urcodec/src/form.rs` - declarative form types and matching interfaces.
- `crates/urcodec/src/fields.rs` - shared form field binding helpers.
- `crates/urcodec/src/bits.rs` - AArch64 bit helpers moved from `urdisassembly`.
- `crates/urcodec/src/arch/mod.rs` - architecture module root.
- `crates/urcodec/src/arch/aarch64/mod.rs` - AArch64 module root.
- `crates/urcodec/src/arch/aarch64/decode.rs` - existing AArch64 decode implementation, then seed form integration.
- `crates/urcodec/src/arch/aarch64/forms.rs` - AArch64 seed forms.
- `crates/urcodec/src/arch/aarch64/fields.rs` - AArch64 reusable field encoders/decoders.
- `crates/urcodec/src/arch/aarch64/format.rs` - canonical AArch64 operand formatting.
- `crates/urcodec/src/arch/aarch64/registers.rs` - AArch64 register helpers.
- `crates/urcodec/src/arch/x86_64/mod.rs` - x86-64 module root.
- `crates/urcodec/src/arch/x86_64/decode.rs` - existing x86-64 decode implementation, then seed form integration.
- `crates/urcodec/src/arch/x86_64/forms.rs` - x86-64 seed forms.
- `crates/urcodec/src/arch/x86_64/fields.rs` - x86-64 reusable field encoders/decoders.
- `crates/urcodec/src/arch/x86_64/modrm.rs` - reusable ModRM/SIB helpers.
- `crates/urcodec/src/arch/x86_64/format.rs` - canonical x86-64 operand formatting.
- `crates/urcodec/src/arch/x86_64/registers.rs` - x86-64 register helpers.
- `crates/urcodec/tests/public_api.rs` - public API construction tests.
- `crates/urcodec/tests/model_text.rs` - model and canonical text tests.
- `crates/urcodec/tests/aarch64_decode.rs` - migrated AArch64 decoder tests.
- `crates/urcodec/tests/aarch64_unknown.rs` - migrated AArch64 unknown/truncation tests.
- `crates/urcodec/tests/x86_64_decode.rs` - migrated x86-64 decoder tests.
- `crates/urcodec/tests/seed_forms.rs` - seed form decode/encode/text/parse roundtrip tests.

Modify:

- `Cargo.toml` - replace workspace member and dependency from `urdisassembly` to `urcodec`.
- `README.md` - rename `urdisassembly` references to `urcodec` after migration.
- `docs/urdisassembly/aarch64-coverage.md` - move or rename to codec docs in a later task.
- `docs/urdisassembly/x86_64-coverage.md` - move or rename to codec docs in a later task.
- `docs/urdis2il/coverage.md` - update dependency wording from disassembly to codec.
- `crates/urdis2il/Cargo.toml` - depend on `urcodec`.
- `crates/urdis2il/src/*.rs` - replace `urdisassembly::` model references with `urcodec::`.
- `crates/urdis2il/tests/*.rs` - replace decoder/model imports with `urcodec`.
- `crates/ura-core/Cargo.toml` - depend on `urcodec`.
- `crates/ura-core/src/analysis/disasm.rs` - use `urcodec::Decoder` and convert from `urcodec::Instruction`.
- `crates/ura-core/tests/*.rs` - only update names if compiler requires it.

Delete after migration:

- `crates/urdisassembly/`

---

### Task 1: Add `urcodec` As a Compatibility Copy

**Files:**
- Create: `crates/urcodec/`
- Modify: `Cargo.toml`
- Test: `crates/urcodec/tests/public_api.rs`

- [ ] **Step 1: Write the failing public API test**

Create `crates/urcodec/tests/public_api.rs`:

```rust
use urcodec::{Architecture, DecodeOptions, Decoder, Endian};

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

#[test]
fn decoder_constructs_for_x86_64_little_endian() {
    let decoder = Decoder::new(
        Architecture::X86_64,
        DecodeOptions {
            endian: Endian::Little,
        },
    )
    .expect("x86-64 little-endian decoder should be supported");

    assert_eq!(decoder.architecture(), Architecture::X86_64);
}
```

- [ ] **Step 2: Add `urcodec` to the workspace so the test can compile and fail for missing crate files**

Modify root `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/urdisassembly",
    "crates/urcodec",
    "crates/urdis2il",
    "crates/urloader",
    "crates/ura-core",
    "crates/ura-cli",
    "crates/ura-daemon",
    "crates/ura-corpus-gate",
]
resolver = "2"
```

Do not add `urcodec` to `[workspace.dependencies]` yet.

- [ ] **Step 3: Run the focused test to verify it fails**

Run:

```bash
cargo test -p urcodec --test public_api
```

Expected: FAIL because `crates/urcodec/Cargo.toml` does not exist or the crate has no implementation.

- [ ] **Step 4: Copy the current decoder crate into `urcodec`**

Run:

```bash
cp -a crates/urdisassembly crates/urcodec
```

Then edit `crates/urcodec/Cargo.toml`:

```toml
[package]
name = "urcodec"
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

Keep copied tests for now. They prove compatibility.

- [ ] **Step 5: Run the focused test to verify it passes**

Run:

```bash
cargo test -p urcodec --test public_api
```

Expected: PASS for both public API tests.

- [ ] **Step 6: Run the copied decoder tests under `urcodec`**

Run:

```bash
cargo test -p urcodec
```

Expected: PASS. The copied `aarch64_decode`, `aarch64_unknown`, `x86_64_decode`, and `public_api` tests all pass under the new crate name.

- [ ] **Step 7: Format and commit**

Run:

```bash
cargo fmt --check
git add Cargo.toml crates/urcodec
git commit -m "feat: add urcodec compatibility crate"
```

Expected: commit succeeds.

---

### Task 2: Move `urdis2il` To `urcodec`

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/urdis2il/Cargo.toml`
- Modify: `crates/urdis2il/src/aarch64.rs`
- Modify: `crates/urdis2il/src/error.rs`
- Modify: `crates/urdis2il/src/lifter.rs`
- Modify: `crates/urdis2il/src/model.rs`
- Modify: `crates/urdis2il/src/operand.rs`
- Modify: `crates/urdis2il/src/x86_64.rs`
- Modify: `crates/urdis2il/tests/aarch64_lift.rs`
- Modify: `crates/urdis2il/tests/model.rs`
- Modify: `crates/urdis2il/tests/x86_64_lift.rs`

- [ ] **Step 1: Write the failing dependency assertion**

Modify `crates/urdis2il/tests/model.rs` imports at the top:

```rust
use urcodec::{
    Architecture, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind,
};
use urdis2il::{IlLocation, IlStmt, Lifter};
```

The rest of the file should still use the same test bodies.

- [ ] **Step 2: Run the focused test to verify it fails**

Run:

```bash
cargo test -p urdis2il --test model
```

Expected: FAIL because `urdis2il` does not depend on `urcodec` yet.

- [ ] **Step 3: Add the workspace dependency**

Modify root `Cargo.toml` `[workspace.dependencies]`:

```toml
urcodec = { path = "crates/urcodec" }
urdisassembly = { path = "crates/urdisassembly" }
```

Modify `crates/urdis2il/Cargo.toml`:

```toml
[package]
name = "urdis2il"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
thiserror.workspace = true
serde.workspace = true
urcodec.workspace = true
```

- [ ] **Step 4: Replace `urdisassembly` paths in `urdis2il`**

Run:

```bash
rg -l 'urdisassembly' crates/urdis2il | xargs sed -i 's/urdisassembly/urcodec/g'
```

Then inspect the diff:

```bash
git diff -- crates/urdis2il Cargo.toml
```

Expected: only crate-path replacements and Cargo dependency changes.

- [ ] **Step 5: Run focused `urdis2il` tests**

Run:

```bash
cargo test -p urdis2il
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
cargo fmt --check
git add Cargo.toml crates/urdis2il
git commit -m "refactor: move urdis2il to urcodec"
```

Expected: commit succeeds.

---

### Task 3: Move `ura-core` To `urcodec`

**Files:**
- Modify: `crates/ura-core/Cargo.toml`
- Modify: `crates/ura-core/src/analysis/disasm.rs`

- [ ] **Step 1: Write the failing import change**

Modify `crates/ura-core/src/analysis/disasm.rs` so the decoder construction uses `urcodec`:

```rust
let decoder = urcodec::Decoder::new(
    urcodec::Architecture::Aarch64,
    urcodec::DecodeOptions::default(),
)
.map_err(|err| UraError::Analysis(err.to_string()))?;
```

Apply the same replacement in the x86-64 decoder construction and in conversion functions:

```rust
fn convert_instruction(decoded: urcodec::Instruction, decoder: &str) -> Instruction {
    let operands = decoded.operand_text();
    let fallthrough = match decoded.flow {
        urcodec::FlowKind::Branch
        | urcodec::FlowKind::Return
        | urcodec::FlowKind::IndirectBranch => None,
        _ => Some(decoded.address + u64::from(decoded.size)),
    };
    Instruction {
        addr: decoded.address,
        size: decoded.size,
        bytes: decoded.bytes,
        mnemonic: decoded.mnemonic,
        operands,
        text: decoded.text,
        kind: convert_kind(decoded.kind),
        flow: convert_flow(decoded.flow),
        fallthrough,
        branch_target: decoded.branch_target,
        decode_status: convert_status(decoded.status),
        decoder: decoder.to_string(),
        decoder_version: env!("CARGO_PKG_VERSION").to_string(),
        function_addr: None,
    }
}
```

Also change `convert_kind`, `convert_flow`, and `convert_status` match arms from `urdisassembly::` to `urcodec::`.

- [ ] **Step 2: Run the focused core tests to verify failure**

Run:

```bash
cargo test -p ura-core --test analysis_smoke
```

Expected: FAIL because `ura-core` does not depend on `urcodec` yet.

- [ ] **Step 3: Change the dependency**

Modify `crates/ura-core/Cargo.toml`:

```toml
[dependencies]
bincode.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
urcodec.workspace = true
urloader.workspace = true
```

Remove `urdisassembly.workspace = true` from this crate manifest.

- [ ] **Step 4: Run core tests**

Run:

```bash
cargo test -p ura-core
```

Expected: PASS.

- [ ] **Step 5: Run CLI and daemon smoke tests**

Run:

```bash
cargo test -p ura-cli -p ura-daemon
```

Expected: PASS. This proves the top-level workflows still use decoded instructions correctly through `ura-core`.

- [ ] **Step 6: Commit**

Run:

```bash
cargo fmt --check
git add crates/ura-core crates/ura-cli crates/ura-daemon
git commit -m "refactor: move core analysis to urcodec"
```

Expected: commit succeeds. If `crates/ura-cli` and `crates/ura-daemon` have no changes, `git add` will leave them untouched.

---

### Task 4: Remove `urdisassembly` From Workspace

**Files:**
- Modify: `Cargo.toml`
- Modify: `README.md`
- Create: `docs/urcodec/aarch64-coverage.md`
- Create: `docs/urcodec/x86_64-coverage.md`
- Delete: `docs/urdisassembly/aarch64-coverage.md`
- Delete: `docs/urdisassembly/x86_64-coverage.md`
- Delete: `crates/urdisassembly/`

- [ ] **Step 1: Verify no source references remain**

Run:

```bash
rg -n 'urdisassembly' crates tests README.md docs Cargo.toml
```

Expected: output shows only root workspace entries, README/docs references, and the old crate files.

- [ ] **Step 2: Remove workspace member and dependency**

Modify root `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/urcodec",
    "crates/urdis2il",
    "crates/urloader",
    "crates/ura-core",
    "crates/ura-cli",
    "crates/ura-daemon",
    "crates/ura-corpus-gate",
]
resolver = "2"
```

In `[workspace.dependencies]`, remove:

```toml
urdisassembly = { path = "crates/urdisassembly" }
```

Keep:

```toml
urcodec = { path = "crates/urcodec" }
```

- [ ] **Step 3: Rename coverage docs**

Run:

```bash
mkdir -p docs/urcodec
git mv docs/urdisassembly/aarch64-coverage.md docs/urcodec/aarch64-coverage.md
git mv docs/urdisassembly/x86_64-coverage.md docs/urcodec/x86_64-coverage.md
```

Edit both moved docs so the first sentence says:

```markdown
The CI corpus gate records sample-level codec totals and unknown rates. Per-encoding corpus attribution is still not measured in this matrix.
```

- [ ] **Step 4: Update README workspace table**

Modify the README workspace table row:

```markdown
| `urcodec` | Decodes and encodes AArch64 and x86-64 instruction subsets, owns the shared instruction model, and provides canonical text handling. |
```

Remove the old `urdisassembly` row.

- [ ] **Step 5: Delete old crate**

Run:

```bash
git rm -r crates/urdisassembly
```

- [ ] **Step 6: Verify no references remain**

Run:

```bash
rg -n 'urdisassembly' crates tests README.md docs Cargo.toml
```

Expected: no output.

- [ ] **Step 7: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
cargo fmt --check
git add Cargo.toml README.md docs/urcodec docs/urdisassembly crates/urdisassembly Cargo.lock
git commit -m "refactor: replace urdisassembly with urcodec"
```

Expected: commit succeeds. `Cargo.lock` may be unchanged; adding it is harmless.

---

### Task 5: Add Declarative Form Core Types

**Files:**
- Create: `crates/urcodec/src/form.rs`
- Create: `crates/urcodec/src/fields.rs`
- Modify: `crates/urcodec/src/lib.rs`
- Test: `crates/urcodec/tests/model_text.rs`

- [ ] **Step 1: Write failing model and form tests**

Create `crates/urcodec/tests/model_text.rs`:

```rust
use urcodec::{
    format_instruction, Architecture, DecodeStatus, FlowKind, FormId, Instruction,
    InstructionKind, Operand,
};

#[test]
fn canonical_text_is_derived_from_instruction_fields() {
    let insn = Instruction {
        address: 0x401000,
        size: 1,
        bytes: vec![0xc3],
        mnemonic: "ret".to_string(),
        operands: Vec::new(),
        text: String::new(),
        kind: InstructionKind::Return,
        flow: FlowKind::Return,
        branch_target: None,
        status: DecodeStatus::Complete,
    };

    assert_eq!(format_instruction(&insn), "ret");
}

#[test]
fn form_id_names_are_arch_scoped() {
    assert_eq!(FormId::new(Architecture::X86_64, "ret").name(), "x86_64.ret");
    assert_eq!(FormId::new(Architecture::Aarch64, "ret").name(), "aarch64.ret");
}

#[test]
fn operands_match_expected_count() {
    let operands = [Operand::Immediate(1)];
    assert_eq!(operands.len(), 1);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p urcodec --test model_text
```

Expected: FAIL because `format_instruction` and `FormId` do not exist.

- [ ] **Step 3: Implement `FormId` and field bindings**

Create `crates/urcodec/src/form.rs`:

```rust
use crate::model::Architecture;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FormId {
    architecture: Architecture,
    local_name: &'static str,
}

impl FormId {
    pub const fn new(architecture: Architecture, local_name: &'static str) -> Self {
        Self {
            architecture,
            local_name,
        }
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn local_name(&self) -> &'static str {
        self.local_name
    }

    pub fn name(&self) -> String {
        let arch = match self.architecture {
            Architecture::Aarch64 => "aarch64",
            Architecture::X86_64 => "x86_64",
        };
        format!("{arch}.{}", self.local_name)
    }
}
```

Create `crates/urcodec/src/fields.rs`:

```rust
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    U64(u64),
    I64(i64),
    Register(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FieldBindings {
    values: BTreeMap<&'static str, FieldValue>,
}

impl FieldBindings {
    pub fn insert(&mut self, name: &'static str, value: FieldValue) {
        self.values.insert(name, value);
    }

    pub fn get(&self, name: &'static str) -> Option<&FieldValue> {
        self.values.get(name)
    }
}
```

- [ ] **Step 4: Implement canonical formatter facade**

Create `crates/urcodec/src/text.rs`:

```rust
use crate::model::Instruction;

pub fn format_instruction(instruction: &Instruction) -> String {
    let operands = instruction.operand_text();
    if operands.is_empty() {
        instruction.mnemonic.clone()
    } else {
        format!("{} {operands}", instruction.mnemonic)
    }
}
```

Modify `crates/urcodec/src/lib.rs` to include and export the modules:

```rust
pub mod arch;
pub mod bits;
pub mod decoder;
pub mod error;
pub mod fields;
pub mod form;
pub mod model;
pub mod text;

pub use decoder::Decoder;
pub use error::{DecodeError, Result};
pub use form::FormId;
pub use model::{
    Architecture, DecodeOptions, DecodeStatus, Endian, FlowKind, Instruction, InstructionKind,
    MemoryOperand, Operand, Register,
};
pub use text::format_instruction;
```

- [ ] **Step 5: Run focused test**

Run:

```bash
cargo test -p urcodec --test model_text
```

Expected: PASS.

- [ ] **Step 6: Run codec tests**

Run:

```bash
cargo test -p urcodec
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
cargo fmt --check
git add crates/urcodec/src/form.rs crates/urcodec/src/fields.rs crates/urcodec/src/text.rs crates/urcodec/src/lib.rs crates/urcodec/tests/model_text.rs
git commit -m "feat: add urcodec form primitives"
```

Expected: commit succeeds.

---

### Task 6: Add Generic Encoder and Text Parser Facades

**Files:**
- Create: `crates/urcodec/src/encode.rs`
- Modify: `crates/urcodec/src/error.rs`
- Modify: `crates/urcodec/src/lib.rs`
- Modify: `crates/urcodec/src/text.rs`
- Test: `crates/urcodec/tests/seed_forms.rs`

- [ ] **Step 1: Write failing facade tests**

Create `crates/urcodec/tests/seed_forms.rs`:

```rust
use urcodec::{
    Architecture, DecodeOptions, Decoder, EncodeOptions, Encoder, TextOptions, TextParser,
};

#[test]
fn x86_ret_roundtrips_through_decode_encode_and_text() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let decoded = decoder.decode_one(&[0xc3], 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "ret");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), vec![0xc3]);

    let parsed = parser.parse_one("ret", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), vec![0xc3]);
}

#[test]
fn aarch64_ret_roundtrips_through_decode_encode_and_text() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xd65f03c0u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400080).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "ret");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("ret", 0x400080).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p urcodec --test seed_forms
```

Expected: FAIL because `Encoder`, `EncodeOptions`, `TextParser`, and `TextOptions` are missing.

- [ ] **Step 3: Add encode error and options types**

Modify `crates/urcodec/src/error.rs`:

```rust
use thiserror::Error;

pub type Result<T> = std::result::Result<T, DecodeError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("expected at least {expected} bytes, got {actual}")]
    TruncatedInstruction { expected: usize, actual: usize },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodeError {
    #[error("unsupported instruction form: {0}")]
    UnsupportedForm(String),
    #[error("operand mismatch for {0}")]
    OperandMismatch(String),
    #[error("target out of range for {0}")]
    TargetOutOfRange(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TextError {
    #[error("unknown mnemonic: {0}")]
    UnknownMnemonic(String),
    #[error("invalid operand syntax: {0}")]
    InvalidOperand(String),
}
```

If the existing file already defines `DecodeError`, preserve its exact variant and append `EncodeError` and `TextError`.

- [ ] **Step 4: Add generic encoder facade**

Create `crates/urcodec/src/encode.rs`:

```rust
use crate::{
    error::EncodeError,
    model::{Architecture, Instruction},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOptions;

impl Default for EncodeOptions {
    fn default() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
pub struct Encoder {
    architecture: Architecture,
    options: EncodeOptions,
}

impl Encoder {
    pub fn new(architecture: Architecture, options: EncodeOptions) -> Result<Self, EncodeError> {
        Ok(Self {
            architecture,
            options,
        })
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn options(&self) -> EncodeOptions {
        self.options
    }

    pub fn encode_one(&self, instruction: &Instruction) -> Result<Vec<u8>, EncodeError> {
        match self.architecture {
            Architecture::Aarch64 => crate::arch::aarch64::forms::encode(instruction),
            Architecture::X86_64 => crate::arch::x86_64::forms::encode(instruction),
        }
    }
}
```

- [ ] **Step 5: Add text parser facade**

Modify `crates/urcodec/src/text.rs`:

```rust
use crate::{
    error::TextError,
    model::{Architecture, Instruction},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextOptions;

impl Default for TextOptions {
    fn default() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
pub struct TextParser {
    architecture: Architecture,
    options: TextOptions,
}

impl TextParser {
    pub fn new(architecture: Architecture, options: TextOptions) -> Result<Self, TextError> {
        Ok(Self {
            architecture,
            options,
        })
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn options(&self) -> TextOptions {
        self.options
    }

    pub fn parse_one(&self, text: &str, address: u64) -> Result<Instruction, TextError> {
        match self.architecture {
            Architecture::Aarch64 => crate::arch::aarch64::forms::parse(text, address),
            Architecture::X86_64 => crate::arch::x86_64::forms::parse(text, address),
        }
    }
}

pub fn format_instruction(instruction: &Instruction) -> String {
    let operands = instruction.operand_text();
    if operands.is_empty() {
        instruction.mnemonic.clone()
    } else {
        format!("{} {operands}", instruction.mnemonic)
    }
}
```

- [ ] **Step 6: Export new facades**

Modify `crates/urcodec/src/lib.rs`:

```rust
pub mod arch;
pub mod bits;
pub mod decoder;
pub mod encode;
pub mod error;
pub mod fields;
pub mod form;
pub mod model;
pub mod text;

pub use decoder::Decoder;
pub use encode::{EncodeOptions, Encoder};
pub use error::{DecodeError, EncodeError, Result, TextError};
pub use form::FormId;
pub use model::{
    Architecture, DecodeOptions, DecodeStatus, Endian, FlowKind, Instruction, InstructionKind,
    MemoryOperand, Operand, Register,
};
pub use text::{format_instruction, TextOptions, TextParser};
```

- [ ] **Step 7: Run test to confirm only form functions are missing**

Run:

```bash
cargo test -p urcodec --test seed_forms
```

Expected: FAIL with missing `arch::aarch64::forms` or `arch::x86_64::forms` functions.

---

### Task 7: Implement Seed Forms Without Per-Instruction Decode/Encode Pairs

**Files:**
- Create: `crates/urcodec/src/arch/aarch64/forms.rs`
- Create: `crates/urcodec/src/arch/x86_64/forms.rs`
- Modify: `crates/urcodec/src/arch/aarch64/mod.rs`
- Modify: `crates/urcodec/src/arch/x86_64/mod.rs`

- [ ] **Step 1: Add AArch64 seed form module**

Create `crates/urcodec/src/arch/aarch64/forms.rs`:

```rust
use crate::{
    error::{EncodeError, TextError},
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind},
};

const RET_WORD: u32 = 0xd65f03c0;

pub fn encode(instruction: &Instruction) -> Result<Vec<u8>, EncodeError> {
    if instruction.mnemonic == "ret"
        && instruction.operands.is_empty()
        && instruction.flow == FlowKind::Return
    {
        return Ok(RET_WORD.to_le_bytes().to_vec());
    }
    Err(EncodeError::UnsupportedForm(instruction.mnemonic.clone()))
}

pub fn parse(text: &str, address: u64) -> Result<Instruction, TextError> {
    if text.trim() == "ret" {
        return Ok(Instruction {
            address,
            size: 4,
            bytes: RET_WORD.to_le_bytes().to_vec(),
            mnemonic: "ret".to_string(),
            operands: Vec::new(),
            text: "ret".to_string(),
            kind: InstructionKind::Return,
            flow: FlowKind::Return,
            branch_target: None,
            status: DecodeStatus::Complete,
        });
    }
    Err(TextError::UnknownMnemonic(text.trim().to_string()))
}
```

This is a seed form adapter. It must not grow into many per-instruction functions. The next task replaces this shape with a shared `InstructionForm` table before adding more forms.

- [ ] **Step 2: Add x86-64 seed form module**

Create `crates/urcodec/src/arch/x86_64/forms.rs`:

```rust
use crate::{
    error::{EncodeError, TextError},
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind},
};

pub fn encode(instruction: &Instruction) -> Result<Vec<u8>, EncodeError> {
    if instruction.mnemonic == "ret"
        && instruction.operands.is_empty()
        && instruction.flow == FlowKind::Return
    {
        return Ok(vec![0xc3]);
    }
    Err(EncodeError::UnsupportedForm(instruction.mnemonic.clone()))
}

pub fn parse(text: &str, address: u64) -> Result<Instruction, TextError> {
    if text.trim() == "ret" {
        return Ok(Instruction {
            address,
            size: 1,
            bytes: vec![0xc3],
            mnemonic: "ret".to_string(),
            operands: Vec::new(),
            text: "ret".to_string(),
            kind: InstructionKind::Return,
            flow: FlowKind::Return,
            branch_target: None,
            status: DecodeStatus::Complete,
        });
    }
    Err(TextError::UnknownMnemonic(text.trim().to_string()))
}
```

- [ ] **Step 3: Expose form modules**

Modify `crates/urcodec/src/arch/aarch64/mod.rs`:

```rust
pub mod decode;
pub mod fields;
pub mod format;
pub mod forms;
pub mod registers;
```

Modify `crates/urcodec/src/arch/x86_64/mod.rs`:

```rust
pub mod decode;
pub mod fields;
pub mod format;
pub mod forms;
pub mod modrm;
pub mod registers;
```

If `modrm.rs` has not been split yet, omit `pub mod modrm;` in this task and keep existing decode helpers in `decode.rs`.

- [ ] **Step 4: Run seed form tests**

Run:

```bash
cargo test -p urcodec --test seed_forms
```

Expected: PASS.

- [ ] **Step 5: Run full codec tests**

Run:

```bash
cargo test -p urcodec
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
cargo fmt --check
git add crates/urcodec
git commit -m "feat: add urcodec seed encode and text forms"
```

Expected: commit succeeds.

---

### Task 8: Replace Seed Adapters With Shared `InstructionForm`

**Files:**
- Modify: `crates/urcodec/src/form.rs`
- Modify: `crates/urcodec/src/arch/aarch64/forms.rs`
- Modify: `crates/urcodec/src/arch/x86_64/forms.rs`
- Modify: `crates/urcodec/tests/seed_forms.rs`

- [ ] **Step 1: Extend the seed test to check one form definition drives both encode and parse**

Append to `crates/urcodec/tests/seed_forms.rs`:

```rust
#[test]
fn seed_form_ids_are_exposed_once_per_architecture() {
    let x86_forms = urcodec::arch::x86_64::forms::all_forms();
    let aarch64_forms = urcodec::arch::aarch64::forms::all_forms();

    assert_eq!(x86_forms.iter().filter(|form| form.id().local_name() == "ret").count(), 1);
    assert_eq!(
        aarch64_forms
            .iter()
            .filter(|form| form.id().local_name() == "ret")
            .count(),
        1
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p urcodec --test seed_forms seed_form_ids_are_exposed_once_per_architecture
```

Expected: FAIL because `all_forms` and `InstructionForm` methods do not exist.

- [ ] **Step 3: Add `InstructionForm` type**

Modify `crates/urcodec/src/form.rs`:

```rust
use crate::model::{Architecture, FlowKind, Instruction, InstructionKind};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FormId {
    architecture: Architecture,
    local_name: &'static str,
}

impl FormId {
    pub const fn new(architecture: Architecture, local_name: &'static str) -> Self {
        Self {
            architecture,
            local_name,
        }
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn local_name(&self) -> &'static str {
        self.local_name
    }

    pub fn name(&self) -> String {
        let arch = match self.architecture {
            Architecture::Aarch64 => "aarch64",
            Architecture::X86_64 => "x86_64",
        };
        format!("{arch}.{}", self.local_name)
    }
}

#[derive(Debug, Clone)]
pub struct InstructionForm {
    id: FormId,
    mnemonic: &'static str,
    kind: InstructionKind,
    flow: FlowKind,
    encode: fn(&Instruction) -> Option<Vec<u8>>,
    parse: fn(&str, u64) -> Option<Instruction>,
}

impl InstructionForm {
    pub const fn new(
        id: FormId,
        mnemonic: &'static str,
        kind: InstructionKind,
        flow: FlowKind,
        encode: fn(&Instruction) -> Option<Vec<u8>>,
        parse: fn(&str, u64) -> Option<Instruction>,
    ) -> Self {
        Self {
            id,
            mnemonic,
            kind,
            flow,
            encode,
            parse,
        }
    }

    pub fn id(&self) -> &FormId {
        &self.id
    }

    pub fn mnemonic(&self) -> &'static str {
        self.mnemonic
    }

    pub fn kind(&self) -> InstructionKind {
        self.kind
    }

    pub fn flow(&self) -> FlowKind {
        self.flow
    }

    pub fn encode(&self, instruction: &Instruction) -> Option<Vec<u8>> {
        (self.encode)(instruction)
    }

    pub fn parse(&self, text: &str, address: u64) -> Option<Instruction> {
        (self.parse)(text, address)
    }
}
```

- [ ] **Step 4: Refactor x86-64 `ret` to one form entry**

Modify `crates/urcodec/src/arch/x86_64/forms.rs`:

```rust
use crate::{
    error::{EncodeError, TextError},
    form::{FormId, InstructionForm},
    model::{Architecture, DecodeStatus, FlowKind, Instruction, InstructionKind},
};

static FORMS: &[InstructionForm] = &[InstructionForm::new(
    FormId::new(Architecture::X86_64, "ret"),
    "ret",
    InstructionKind::Return,
    FlowKind::Return,
    encode_ret,
    parse_ret,
)];

pub fn all_forms() -> &'static [InstructionForm] {
    FORMS
}

pub fn encode(instruction: &Instruction) -> Result<Vec<u8>, EncodeError> {
    FORMS
        .iter()
        .find_map(|form| form.encode(instruction))
        .ok_or_else(|| EncodeError::UnsupportedForm(instruction.mnemonic.clone()))
}

pub fn parse(text: &str, address: u64) -> Result<Instruction, TextError> {
    FORMS
        .iter()
        .find_map(|form| form.parse(text, address))
        .ok_or_else(|| TextError::UnknownMnemonic(text.trim().to_string()))
}

fn encode_ret(instruction: &Instruction) -> Option<Vec<u8>> {
    (instruction.mnemonic == "ret"
        && instruction.operands.is_empty()
        && instruction.flow == FlowKind::Return)
        .then(|| vec![0xc3])
}

fn parse_ret(text: &str, address: u64) -> Option<Instruction> {
    (text.trim() == "ret").then(|| Instruction {
        address,
        size: 1,
        bytes: vec![0xc3],
        mnemonic: "ret".to_string(),
        operands: Vec::new(),
        text: "ret".to_string(),
        kind: InstructionKind::Return,
        flow: FlowKind::Return,
        branch_target: None,
        status: DecodeStatus::Complete,
    })
}
```

- [ ] **Step 5: Refactor AArch64 `ret` to one form entry**

Modify `crates/urcodec/src/arch/aarch64/forms.rs`:

```rust
use crate::{
    error::{EncodeError, TextError},
    form::{FormId, InstructionForm},
    model::{Architecture, DecodeStatus, FlowKind, Instruction, InstructionKind},
};

const RET_WORD: u32 = 0xd65f03c0;

static FORMS: &[InstructionForm] = &[InstructionForm::new(
    FormId::new(Architecture::Aarch64, "ret"),
    "ret",
    InstructionKind::Return,
    FlowKind::Return,
    encode_ret,
    parse_ret,
)];

pub fn all_forms() -> &'static [InstructionForm] {
    FORMS
}

pub fn encode(instruction: &Instruction) -> Result<Vec<u8>, EncodeError> {
    FORMS
        .iter()
        .find_map(|form| form.encode(instruction))
        .ok_or_else(|| EncodeError::UnsupportedForm(instruction.mnemonic.clone()))
}

pub fn parse(text: &str, address: u64) -> Result<Instruction, TextError> {
    FORMS
        .iter()
        .find_map(|form| form.parse(text, address))
        .ok_or_else(|| TextError::UnknownMnemonic(text.trim().to_string()))
}

fn encode_ret(instruction: &Instruction) -> Option<Vec<u8>> {
    (instruction.mnemonic == "ret"
        && instruction.operands.is_empty()
        && instruction.flow == FlowKind::Return)
        .then(|| RET_WORD.to_le_bytes().to_vec())
}

fn parse_ret(text: &str, address: u64) -> Option<Instruction> {
    (text.trim() == "ret").then(|| Instruction {
        address,
        size: 4,
        bytes: RET_WORD.to_le_bytes().to_vec(),
        mnemonic: "ret".to_string(),
        operands: Vec::new(),
        text: "ret".to_string(),
        kind: InstructionKind::Return,
        flow: FlowKind::Return,
        branch_target: None,
        status: DecodeStatus::Complete,
    })
}
```

- [ ] **Step 6: Run seed tests**

Run:

```bash
cargo test -p urcodec --test seed_forms
```

Expected: PASS.

- [ ] **Step 7: Run full workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
cargo fmt --check
git add crates/urcodec
git commit -m "refactor: drive seed forms from shared definitions"
```

Expected: commit succeeds.

---

### Task 9: Add Seed Branch and Immediate Forms

**Files:**
- Modify: `crates/urcodec/src/arch/aarch64/forms.rs`
- Modify: `crates/urcodec/src/arch/x86_64/forms.rs`
- Modify: `crates/urcodec/tests/seed_forms.rs`

- [ ] **Step 1: Add failing roundtrip tests for one non-trivial form per architecture**

Append to `crates/urcodec/tests/seed_forms.rs`:

```rust
#[test]
fn x86_call_rel32_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let decoded = decoder
        .decode_one(&[0xe8, 0x05, 0x00, 0x00, 0x00], 0x401000)
        .unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "call 0x40100a");
    assert_eq!(
        encoder.encode_one(&decoded).unwrap(),
        vec![0xe8, 0x05, 0x00, 0x00, 0x00]
    );

    let parsed = parser.parse_one("call 0x40100a", 0x401000).unwrap();
    assert_eq!(
        encoder.encode_one(&parsed).unwrap(),
        vec![0xe8, 0x05, 0x00, 0x00, 0x00]
    );
}

#[test]
fn aarch64_b_roundtrips_through_form() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0x14000004u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "b 0x400110");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("b 0x400110", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p urcodec --test seed_forms x86_call_rel32_roundtrips_through_form aarch64_b_roundtrips_through_form
```

Expected: FAIL because call and branch encode/parse forms are unsupported.

- [ ] **Step 3: Add x86-64 `call rel32` form entry**

Modify `crates/urcodec/src/arch/x86_64/forms.rs` by adding a second form to `FORMS`:

```rust
InstructionForm::new(
    FormId::new(Architecture::X86_64, "call_rel32"),
    "call",
    InstructionKind::Call,
    FlowKind::Call,
    encode_call_rel32,
    parse_call_rel32,
)
```

Add helper functions:

```rust
fn encode_call_rel32(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.mnemonic != "call" || instruction.flow != FlowKind::Call {
        return None;
    }
    let target = instruction.branch_target?;
    let next = instruction.address.checked_add(5)?;
    let disp = i64::try_from(target).ok()? - i64::try_from(next).ok()?;
    let disp = i32::try_from(disp).ok()?;
    let mut out = vec![0xe8];
    out.extend_from_slice(&disp.to_le_bytes());
    Some(out)
}

fn parse_call_rel32(text: &str, address: u64) -> Option<Instruction> {
    let target = parse_absolute_target(text, "call")?;
    let next = address.checked_add(5)?;
    let disp = i64::try_from(target).ok()? - i64::try_from(next).ok()?;
    i32::try_from(disp).ok()?;
    let mut bytes = vec![0xe8];
    bytes.extend_from_slice(&(disp as i32).to_le_bytes());
    Some(Instruction {
        address,
        size: 5,
        bytes,
        mnemonic: "call".to_string(),
        operands: vec![crate::model::Operand::AbsoluteAddress(target)],
        text: format!("call 0x{target:x}"),
        kind: InstructionKind::Call,
        flow: FlowKind::Call,
        branch_target: Some(target),
        status: DecodeStatus::Complete,
    })
}

fn parse_absolute_target(text: &str, mnemonic: &str) -> Option<u64> {
    let text = text.trim();
    let rest = text.strip_prefix(mnemonic)?.trim();
    u64::from_str_radix(rest.strip_prefix("0x")?, 16).ok()
}
```

This is acceptable as a seed primitive because `parse_absolute_target` and relative displacement encoding are reusable form helpers. Do not add a separate `encode_call_rel32` outside the form table.

- [ ] **Step 4: Add AArch64 `b` form entry**

Modify `crates/urcodec/src/arch/aarch64/forms.rs` by adding a second form to `FORMS`:

```rust
InstructionForm::new(
    FormId::new(Architecture::Aarch64, "b_imm26"),
    "b",
    InstructionKind::Branch,
    FlowKind::Branch,
    encode_b_imm26,
    parse_b_imm26,
)
```

Add helper functions:

```rust
fn encode_b_imm26(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.mnemonic != "b" || instruction.flow != FlowKind::Branch {
        return None;
    }
    let target = instruction.branch_target?;
    let delta = i64::try_from(target).ok()? - i64::try_from(instruction.address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm26 = delta / 4;
    if !(-(1 << 25)..(1 << 25)).contains(&imm26) {
        return None;
    }
    let word = 0x1400_0000u32 | ((imm26 as u32) & 0x03ff_ffff);
    Some(word.to_le_bytes().to_vec())
}

fn parse_b_imm26(text: &str, address: u64) -> Option<Instruction> {
    let target = parse_absolute_target(text, "b")?;
    let delta = i64::try_from(target).ok()? - i64::try_from(address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm26 = delta / 4;
    if !(-(1 << 25)..(1 << 25)).contains(&imm26) {
        return None;
    }
    let word = 0x1400_0000u32 | ((imm26 as u32) & 0x03ff_ffff);
    Some(Instruction {
        address,
        size: 4,
        bytes: word.to_le_bytes().to_vec(),
        mnemonic: "b".to_string(),
        operands: vec![crate::model::Operand::AbsoluteAddress(target)],
        text: format!("b 0x{target:x}"),
        kind: InstructionKind::Branch,
        flow: FlowKind::Branch,
        branch_target: Some(target),
        status: DecodeStatus::Complete,
    })
}

fn parse_absolute_target(text: &str, mnemonic: &str) -> Option<u64> {
    let text = text.trim();
    let rest = text.strip_prefix(mnemonic)?.trim();
    u64::from_str_radix(rest.strip_prefix("0x")?, 16).ok()
}
```

- [ ] **Step 5: Run seed form tests**

Run:

```bash
cargo test -p urcodec --test seed_forms
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
cargo fmt --check
git add crates/urcodec
git commit -m "feat: add branch seed forms"
```

Expected: commit succeeds.

---

### Task 10: Update Documentation and Final Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/urcodec/aarch64-coverage.md`
- Modify: `docs/urcodec/x86_64-coverage.md`
- Modify: `docs/urdis2il/coverage.md`
- Modify: `docs/superpowers/specs/2026-06-18-urcodec-declarative-forms-design.md` only if implementation reveals a necessary clarification.

- [ ] **Step 1: Update README support language**

Modify README current support wording to include codec behavior:

```markdown
Instruction coverage is intentionally partial. Unknown instructions are preserved in analysis output and surfaced through diagnostics. `urcodec` owns the shared instruction model, byte decoding, seed byte encoding, canonical text rendering, and seed text parsing.
```

- [ ] **Step 2: Update codec coverage docs**

In `docs/urcodec/x86_64-coverage.md`, add a short section after the opening paragraph:

```markdown
## Codec Seed Forms

The first declarative forms cover `ret` and `call rel32`. These forms drive decode compatibility, encode, canonical text, text parsing, and roundtrip tests from one form table.
```

In `docs/urcodec/aarch64-coverage.md`, add:

```markdown
## Codec Seed Forms

The first declarative forms cover `ret` and `b imm26`. These forms drive decode compatibility, encode, canonical text, text parsing, and roundtrip tests from one form table.
```

- [ ] **Step 3: Update IL coverage dependency wording**

In `docs/urdis2il/coverage.md`, add this sentence after the title:

```markdown
`urdis2il` consumes structured instructions from `urcodec`; it does not own byte decoding, byte encoding, or text parsing.
```

- [ ] **Step 4: Run full verification**

Run:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all three commands exit 0.

- [ ] **Step 5: Confirm no old crate references remain**

Run:

```bash
rg -n 'urdisassembly|urinstruction|urassembly' crates README.md docs Cargo.toml
```

Expected: no `urdisassembly` references. `urinstruction` and `urassembly` may appear only in the design spec as explicitly rejected crate names.

- [ ] **Step 6: Commit final docs**

Run:

```bash
git add README.md docs/urcodec docs/urdis2il/coverage.md docs/superpowers/specs/2026-06-18-urcodec-declarative-forms-design.md
git commit -m "docs: document urcodec seed forms"
```

Expected: commit succeeds if docs changed. If implementation required no doc changes beyond previous tasks, skip this commit and record that final verification passed.

---

## Self-Review

Spec coverage:

- `urdisassembly` absorbed into `urcodec`: Tasks 1 through 4.
- No `urinstruction` or `urassembly` crate: Task 4 workspace cleanup and Task 10 reference check.
- `urdis2il` depends on `urcodec`: Task 2.
- `ura-core` uses `urcodec::Decoder`: Task 3.
- Declarative seed forms: Tasks 5 through 9.
- No long-term independent per-instruction decode/encode pairs: Tasks 7 and 8 establish form table dispatch; Task 9 adds forms through that table.
- Decode, encode, text render, text parse, and roundtrip tests: Tasks 6 through 9.
- Existing behavior preserved: Tasks 1 through 4 run copied tests and workspace tests before form expansion.
- Structured tests before text: Tasks 5 through 9 assert instruction fields or roundtrip bytes before relying on text.
- Final verification commands: Task 10.

Plan scope:

- This plan intentionally implements only seed forms for encode/text parsing. It does not attempt full assembler coverage, full oracle fixture automation, or corpus unknown clustering. Those are follow-up plans after the `urcodec` boundary and form mechanism are proven.
