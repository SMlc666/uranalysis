# Urcodec Form Single Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `urcodec`'s callback-based forms and split decode logic with one schema-driven runtime that owns decode, encode, text formatting, and text parsing for both AArch64 and x86-64.

**Architecture:** First stabilize the data contract by making `Instruction` carry explicit architecture/form identity and replacing `InstructionForm` with a declarative `FormSchema`. Then build one runtime pipeline around `layout -> match -> fields -> operands -> text/alias -> encode`, prove that pipeline with minimal `ret` forms in both architectures, and only then migrate the current supported AArch64 and x86-64 families onto that runtime while deleting the old decoder and format ownership.

**Tech Stack:** Rust 2021 workspace, `cargo test`, `cargo fmt`, `cargo clippy`, existing `urcodec` oracle tests, and existing `urdis2il`/`ura-core` workspace tests.

---

## Scope Notes

This plan implements `docs/superpowers/specs/2026-06-19-urcodec-form-single-source-design.md`.

This is one subsystem. Do not split it into separate specs.

The branch is allowed to stop compiling during execution. Do not add temporary compatibility layers or fallback dispatchers just to keep intermediate commits green.

The final landing must restore:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## File Structure

- Modify `crates/urcodec/src/model.rs`: add explicit architecture and form identity to `Instruction`, plus helpers that stop text code from guessing architecture from byte length.
- Modify `crates/urcodec/src/form.rs`: replace callback-based `InstructionForm` with declarative schema, field, matcher, alias, and encode-rule types.
- Create `crates/urcodec/src/runtime/mod.rs`: runtime facade for decode, parse, format, and encode.
- Create `crates/urcodec/src/runtime/layout.rs`: `LayoutView` parsing for fixed-width AArch64 and byte-stream x86-64.
- Create `crates/urcodec/src/runtime/matcher.rs`: candidate selection and matcher evaluation over layout views.
- Create `crates/urcodec/src/runtime/fields.rs`: named field extraction from a matched schema and layout view.
- Create `crates/urcodec/src/runtime/operands.rs`: field-to-`Instruction` mapping and operand-to-field reverse matching.
- Create `crates/urcodec/src/runtime/text.rs`: canonical text rendering and parse tokenization driven by schemas.
- Create `crates/urcodec/src/runtime/alias.rs`: canonicalization and display-alias selection.
- Create `crates/urcodec/src/runtime/encode.rs`: encode validation and byte emission from schemas.
- Modify `crates/urcodec/src/decoder.rs`: route `Decoder` through runtime only.
- Modify `crates/urcodec/src/encode.rs`: route `Encoder` through runtime only.
- Modify `crates/urcodec/src/text.rs`: route `TextParser` and `format_instruction` through runtime only.
- Modify `crates/urcodec/src/lib.rs`: export the new schema/runtime surface and stop exporting the legacy callback form type.
- Modify `crates/urcodec/src/arch/mod.rs`: wire new adapter modules and drop old decoder/format ownership.
- Modify `crates/urcodec/src/arch/aarch64/forms.rs`: replace callback-based forms with AArch64 schema declarations.
- Create `crates/urcodec/src/arch/aarch64/adapters.rs`: AArch64 field transforms, register-bank mapping, immediate helpers, and alias helpers.
- Modify `crates/urcodec/src/arch/aarch64/mod.rs`: export AArch64 schema registry and adapters.
- Delete `crates/urcodec/src/arch/aarch64/decode.rs`: runtime supersedes the legacy AArch64 decoder.
- Delete `crates/urcodec/src/arch/aarch64/format.rs`: runtime text/alias rules supersede legacy AArch64 formatting.
- Modify `crates/urcodec/src/arch/x86_64/forms.rs`: replace callback-based forms with x86-64 schema declarations.
- Create `crates/urcodec/src/arch/x86_64/adapters.rs`: x86-64 ModRM/SIB, prefix, register, and branch helpers.
- Modify `crates/urcodec/src/arch/x86_64/mod.rs`: export x86-64 schema registry and adapters.
- Delete `crates/urcodec/src/arch/x86_64/decode.rs`: runtime supersedes the legacy x86-64 decoder.
- Delete `crates/urcodec/src/arch/x86_64/format.rs`: runtime text/alias rules supersede legacy x86-64 formatting.
- Modify `crates/urcodec/tests/public_api.rs`: prove `Decoder`/`Encoder`/`TextParser` still work after the rewrite.
- Modify `crates/urcodec/tests/model_text.rs`: prove architecture-aware canonical text and alias behavior.
- Modify `crates/urcodec/tests/seed_forms.rs`: update roundtrip coverage to runtime ownership and add alias-focused checks.
- Modify `crates/urcodec/tests/aarch64_decode.rs`: keep AArch64 decode coverage green under runtime ownership.
- Modify `crates/urcodec/tests/x86_64_decode.rs`: keep x86-64 decode coverage green under runtime ownership.
- Modify `crates/urcodec/tests/aarch64_capstone_oracle.rs`: keep AArch64 oracle coverage aligned with runtime output.
- Modify `crates/urcodec/tests/x86_64_capstone_oracle.rs`: keep x86-64 oracle coverage aligned with runtime output.
- Modify `crates/urdis2il/tests/aarch64_lift.rs`: verify AArch64 control-flow semantics still lift correctly.
- Modify `crates/urdis2il/tests/x86_64_lift.rs`: verify x86-64 control-flow semantics still lift correctly.
- Modify `crates/ura-core/tests/cfg_analysis.rs`: verify CFG edges still match runtime branch/call output.
- Modify `docs/urcodec/aarch64-coverage.md`: reflect AArch64 runtime-owned families.
- Modify `docs/urcodec/x86_64-coverage.md`: reflect x86-64 runtime-owned families.

### Task 1: Add Explicit Instruction Identity For Runtime Ownership

**Files:**
- Modify: `crates/urcodec/src/model.rs`
- Modify: `crates/urcodec/tests/public_api.rs`
- Modify: `crates/urcodec/tests/model_text.rs`

- [ ] **Step 1: Write the failing tests for explicit architecture and form identity**

Append to `crates/urcodec/tests/public_api.rs`:

```rust
#[test]
fn decoded_instruction_carries_architecture_identity() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let decoded = decoder.decode_one(&0xd65f03c0u32.to_le_bytes(), 0x400080).unwrap();

    assert_eq!(decoded.architecture, Architecture::Aarch64);
    assert_eq!(decoded.form.as_deref(), Some("aarch64.ret"));
}
```

Append to `crates/urcodec/tests/model_text.rs`:

```rust
#[test]
fn manual_instruction_text_does_not_need_byte_length_to_find_architecture() {
    let instruction = urcodec::Instruction {
        architecture: urcodec::Architecture::X86_64,
        address: 0x401000,
        size: 6,
        bytes: vec![0x0f, 0x85, 0xfa, 0x00, 0x00, 0x00],
        mnemonic: "jne".to_string(),
        operands: vec![urcodec::Operand::AbsoluteAddress(0x401100)],
        text: String::new(),
        kind: urcodec::InstructionKind::Branch,
        flow: urcodec::FlowKind::ConditionalBranch,
        branch_target: Some(0x401100),
        status: urcodec::DecodeStatus::Complete,
        form: Some("x86_64.jcc_rel32".to_string()),
    };

    assert_eq!(urcodec::format_instruction(&instruction), "jne 0x401100");
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p urcodec --test public_api decoded_instruction_carries_architecture_identity -- --nocapture
cargo test -p urcodec --test model_text manual_instruction_text_does_not_need_byte_length_to_find_architecture -- --nocapture
```

Expected: compile fails because `Instruction` has no `architecture` or `form` fields.

- [ ] **Step 3: Extend `Instruction` with architecture and form identity**

In `crates/urcodec/src/model.rs`, update `Instruction` to:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub architecture: Architecture,
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
    pub form: Option<String>,
}
```

Add this helper below `operand_text()`:

```rust
impl Instruction {
    pub fn with_text(mut self, text: String) -> Self {
        self.text = text;
        self
    }
}
```

Update every existing `Instruction { ... }` literal in `crates/urcodec/src/arch/aarch64/forms.rs`, `crates/urcodec/src/arch/x86_64/forms.rs`, and any tests to populate:

```rust
architecture: Architecture::Aarch64, // or Architecture::X86_64
form: Some("...".to_string()),
```

- [ ] **Step 4: Re-run the focused tests and verify they pass**

Run:

```bash
cargo test -p urcodec --test public_api decoded_instruction_carries_architecture_identity -- --nocapture
cargo test -p urcodec --test model_text manual_instruction_text_does_not_need_byte_length_to_find_architecture -- --nocapture
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/urcodec/src/model.rs crates/urcodec/tests/public_api.rs crates/urcodec/tests/model_text.rs crates/urcodec/src/arch/aarch64/forms.rs crates/urcodec/src/arch/x86_64/forms.rs
git commit -m "refactor: add explicit urcodec instruction identity"
```

### Task 2: Replace `InstructionForm` With Declarative `FormSchema`

**Files:**
- Modify: `crates/urcodec/src/form.rs`
- Modify: `crates/urcodec/src/lib.rs`
- Modify: `crates/urcodec/src/arch/aarch64/forms.rs`
- Modify: `crates/urcodec/src/arch/x86_64/forms.rs`
- Test: `crates/urcodec/tests/public_api.rs`

- [ ] **Step 1: Write the failing test for schema-backed form registries**

Append to `crates/urcodec/tests/public_api.rs`:

```rust
#[test]
fn form_registries_expose_layout_and_matcher_metadata() {
    let x86_ret = urcodec::arch::x86_64::forms::all_forms()
        .iter()
        .find(|form| form.id().local_name() == "ret")
        .expect("x86 ret form should exist");
    assert!(matches!(
        x86_ret.decode_layout(),
        urcodec::form::DecodeLayout::ByteStream(_)
    ));
    assert!(!x86_ret.matchers().is_empty());

    let aarch64_ret = urcodec::arch::aarch64::forms::all_forms()
        .iter()
        .find(|form| form.id().local_name() == "ret")
        .expect("aarch64 ret form should exist");
    assert!(matches!(
        aarch64_ret.decode_layout(),
        urcodec::form::DecodeLayout::FixedWidthBits { width: 32 }
    ));
    assert!(!aarch64_ret.fields().is_empty());
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
cargo test -p urcodec --test public_api form_registries_expose_layout_and_matcher_metadata -- --nocapture
```

Expected: compile fails because `DecodeLayout`, matcher accessors, and schema-backed `all_forms()` do not exist.

- [ ] **Step 3: Replace callback forms with schema types**

Replace `crates/urcodec/src/form.rs` with a declarative schema model that contains:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeLayout {
    FixedWidthBits { width: u8 },
    ByteStream(ByteStreamLayout),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteStreamLayout {
    pub opcode_len: u8,
    pub uses_modrm: bool,
    pub uses_sib: bool,
    pub displacement_bytes: Option<u8>,
    pub immediate_bytes: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matcher {
    MaskEq { mask: u32, value: u32 },
    OpcodeEq(&'static [u8]),
    OpcodeExt { reg: u8 },
    ModrmMode { mode: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSource {
    Bits { start: u8, end: u8 },
    SignedBits { start: u8, end: u8 },
    ModrmReg,
    ModrmRm,
    Immediate8,
    Immediate16,
    Immediate32,
    Immediate64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: &'static str,
    pub source: FieldSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperandSpec {
    Register { field: &'static str, bank: &'static str },
    Immediate { field: &'static str },
    RelativeTarget { field: &'static str, scale: u8, add_instruction_size: bool },
    AbsoluteTarget { field: &'static str },
    Condition { field: &'static str, table: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasRule {
    pub mnemonic: &'static str,
    pub when: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeRule {
    pub require: &'static [&'static str],
    pub canonical_preference: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextRule {
    pub mnemonic: &'static str,
    pub operand_order: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormSchema {
    id: FormId,
    mnemonic: &'static str,
    kind: InstructionKind,
    flow: FlowKind,
    decode_layout: DecodeLayout,
    matchers: &'static [Matcher],
    fields: &'static [FieldSpec],
    operands: &'static [OperandSpec],
    text_rule: TextRule,
    aliases: &'static [AliasRule],
    encode_rule: EncodeRule,
}
```

Add `FormSchema::new(...)` and accessors for `id()`, `mnemonic()`, `kind()`, `flow()`, `decode_layout()`, `matchers()`, `fields()`, `operands()`, `text_rule()`, `aliases()`, and `encode_rule()`.

Update `crates/urcodec/src/lib.rs` to export `FormSchema` and related schema types, and stop exporting `InstructionForm`.

- [ ] **Step 4: Make both architecture registries return `FormSchema`**

In `crates/urcodec/src/arch/aarch64/forms.rs` and `crates/urcodec/src/arch/x86_64/forms.rs`:

- replace `InstructionForm` imports with schema imports
- change `static FORMS: &[InstructionForm]` to `static FORMS: &[FormSchema]`
- change `pub fn all_forms() -> &'static [InstructionForm]` to `pub fn all_forms() -> &'static [FormSchema]`
- for now, only define one schema constant per architecture: `ret`

Use:

```rust
pub fn all_forms() -> &'static [FormSchema] {
    FORMS
}
```

and remove `decode()`, `encode()`, and `parse()` public helpers from these files once no caller needs them.

- [ ] **Step 5: Re-run the focused test and verify it passes**

Run:

```bash
cargo test -p urcodec --test public_api form_registries_expose_layout_and_matcher_metadata -- --nocapture
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/urcodec/src/form.rs crates/urcodec/src/lib.rs crates/urcodec/src/arch/aarch64/forms.rs crates/urcodec/src/arch/x86_64/forms.rs crates/urcodec/tests/public_api.rs
git commit -m "refactor: replace urcodec callback forms with schema declarations"
```

### Task 3: Build The Minimal Runtime Pipeline With `ret` In Both Architectures

**Files:**
- Create: `crates/urcodec/src/runtime/mod.rs`
- Create: `crates/urcodec/src/runtime/layout.rs`
- Create: `crates/urcodec/src/runtime/matcher.rs`
- Create: `crates/urcodec/src/runtime/fields.rs`
- Create: `crates/urcodec/src/runtime/operands.rs`
- Create: `crates/urcodec/src/runtime/text.rs`
- Create: `crates/urcodec/src/runtime/alias.rs`
- Create: `crates/urcodec/src/runtime/encode.rs`
- Modify: `crates/urcodec/src/decoder.rs`
- Modify: `crates/urcodec/src/encode.rs`
- Modify: `crates/urcodec/src/text.rs`
- Modify: `crates/urcodec/src/lib.rs`
- Test: `crates/urcodec/tests/public_api.rs`
- Test: `crates/urcodec/tests/seed_forms.rs`

- [ ] **Step 1: Write the failing end-to-end runtime tests for AArch64 and x86-64 `ret`**

Append to `crates/urcodec/tests/public_api.rs`:

```rust
#[test]
fn decoder_encoder_and_parser_share_runtime_for_aarch64_ret() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xd65f03c0u32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400080).unwrap();
    assert_eq!(decoded.form.as_deref(), Some("aarch64.ret"));
    assert_eq!(urcodec::format_instruction(&decoded), "ret");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("ret", 0x400080).unwrap();
    assert_eq!(parsed.form.as_deref(), Some("aarch64.ret"));
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}

#[test]
fn decoder_encoder_and_parser_share_runtime_for_x86_ret() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xc3];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(decoded.form.as_deref(), Some("x86_64.ret"));
    assert_eq!(urcodec::format_instruction(&decoded), "ret");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("ret", 0x401000).unwrap();
    assert_eq!(parsed.form.as_deref(), Some("x86_64.ret"));
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p urcodec --test public_api decoder_encoder_and_parser_share_runtime_for_aarch64_ret -- --nocapture
cargo test -p urcodec --test public_api decoder_encoder_and_parser_share_runtime_for_x86_ret -- --nocapture
```

Expected: FAIL because the runtime modules and schema-driven entrypoints do not exist yet.

- [ ] **Step 3: Create runtime contracts that are actually sufficient to implement**

Create `crates/urcodec/src/runtime/mod.rs`:

```rust
pub mod alias;
pub mod encode;
pub mod fields;
pub mod layout;
pub mod matcher;
pub mod operands;
pub mod text;

use crate::{
    error::{DecodeError, EncodeError, TextError},
    form::FormSchema,
    model::{Architecture, Instruction},
};

pub fn decode_one(
    architecture: Architecture,
    forms: &'static [FormSchema],
    bytes: &[u8],
    address: u64,
) -> Result<Instruction, DecodeError> {
    let layout = layout::read_layout(architecture, bytes, address)?;
    let form = matcher::select_form(forms, &layout)?;
    let fields = fields::extract_fields(form, &layout)?;
    let mut instruction = operands::build_instruction(form, &layout, &fields)?;
    instruction.text = text::render_instruction(form, &instruction);
    Ok(instruction)
}

pub fn encode_one(
    forms: &'static [FormSchema],
    instruction: &Instruction,
) -> Result<Vec<u8>, EncodeError> {
    let canonical = alias::canonicalize_instruction(forms, instruction)?;
    let form = matcher::select_form_for_instruction(forms, &canonical)?;
    let values = operands::match_instruction(form, &canonical)?;
    encode::emit_instruction(form, &canonical, &values)
}

pub fn parse_one(
    forms: &'static [FormSchema],
    text: &str,
    address: u64,
) -> Result<Instruction, TextError> {
    let (form, values) = text::parse_instruction(forms, text)?;
    let mut instruction = operands::build_instruction_from_values(form, address, &values)?;
    instruction.text = text::render_instruction(form, &instruction);
    Ok(instruction)
}

pub fn format_instruction(forms: &'static [FormSchema], instruction: &Instruction) -> String {
    alias::display_text(forms, instruction)
}
```

Create the other modules with these public functions:

- `layout::read_layout(architecture, bytes, address) -> Result<LayoutView, DecodeError>`
- `matcher::select_form(forms, &layout) -> Result<&'static FormSchema, DecodeError>`
- `matcher::select_form_for_instruction(forms, instruction) -> Result<&'static FormSchema, EncodeError>`
- `fields::extract_fields(form, &layout) -> Result<BTreeMap<&'static str, i64>, DecodeError>`
- `operands::build_instruction(form, &layout, &fields) -> Result<Instruction, DecodeError>`
- `operands::build_instruction_from_values(form, address, &values) -> Result<Instruction, TextError>`
- `operands::match_instruction(form, instruction) -> Result<BTreeMap<&'static str, i64>, EncodeError>`
- `text::render_instruction(form, instruction) -> String`
- `text::parse_instruction(forms, text) -> Result<(&'static FormSchema, BTreeMap<&'static str, i64>), TextError>`
- `alias::canonicalize_instruction(forms, instruction) -> Result<Instruction, EncodeError>`
- `alias::display_text(forms, instruction) -> String`
- `encode::emit_instruction(form, instruction, &values) -> Result<Vec<u8>, EncodeError>`

For this task, implement just enough logic for:

- AArch64 `ret`
- x86-64 `ret`

- [ ] **Step 4: Route public entrypoints through runtime only**

In `crates/urcodec/src/decoder.rs`, replace `decode_one()` with runtime dispatch that calls `crate::runtime::decode_one(...)` using `all_forms()` for the selected architecture.

In `crates/urcodec/src/encode.rs`, replace `encode_one()` with runtime dispatch that calls `crate::runtime::encode_one(...)`.

In `crates/urcodec/src/text.rs`, replace `parse_one()` with runtime dispatch and replace `format_instruction()` with architecture-aware routing based on `instruction.architecture`.

Add:

```rust
pub mod runtime;
```

to `crates/urcodec/src/lib.rs`.

- [ ] **Step 5: Re-run the focused tests and verify they pass**

Run:

```bash
cargo test -p urcodec --test public_api decoder_encoder_and_parser_share_runtime_for_aarch64_ret -- --nocapture
cargo test -p urcodec --test public_api decoder_encoder_and_parser_share_runtime_for_x86_ret -- --nocapture
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/urcodec/src/runtime crates/urcodec/src/decoder.rs crates/urcodec/src/encode.rs crates/urcodec/src/text.rs crates/urcodec/src/lib.rs crates/urcodec/tests/public_api.rs
git commit -m "refactor: add minimal urcodec schema runtime"
```

### Task 4: Migrate AArch64 Families Onto Runtime Ownership

**Files:**
- Modify: `crates/urcodec/src/arch/aarch64/forms.rs`
- Create: `crates/urcodec/src/arch/aarch64/adapters.rs`
- Modify: `crates/urcodec/src/arch/aarch64/mod.rs`
- Modify: `crates/urcodec/src/runtime/fields.rs`
- Modify: `crates/urcodec/src/runtime/operands.rs`
- Modify: `crates/urcodec/src/runtime/text.rs`
- Modify: `crates/urcodec/src/runtime/alias.rs`
- Modify: `crates/urcodec/src/runtime/encode.rs`
- Modify: `crates/urcodec/tests/seed_forms.rs`
- Modify: `crates/urcodec/tests/aarch64_decode.rs`
- Modify: `crates/urcodec/tests/model_text.rs`

- [ ] **Step 1: Add failing AArch64 roundtrip and alias tests**

Append to `crates/urcodec/tests/seed_forms.rs`:

```rust
#[test]
fn aarch64_cmp_alias_roundtrips_through_schema_runtime() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xf100201fu32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(decoded.form.as_deref(), Some("aarch64.cmp_imm"));
    assert_eq!(urcodec::format_instruction(&decoded), "cmp x0, #0x8");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("cmp x0, #0x8", 0x400100).unwrap();
    assert_eq!(parsed.form.as_deref(), Some("aarch64.cmp_imm"));
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
```

Append to `crates/urcodec/tests/model_text.rs`:

```rust
#[test]
fn aarch64_conditional_branch_uses_schema_alias_text() {
    let decoder = urcodec::Decoder::new(
        urcodec::Architecture::Aarch64,
        urcodec::DecodeOptions::default(),
    )
    .unwrap();
    let instruction = decoder
        .decode_one(&0x54000060u32.to_le_bytes(), 0x400100)
        .unwrap();
    assert_eq!(urcodec::format_instruction(&instruction), "b.eq 0x40010c");
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p urcodec --test seed_forms aarch64_cmp_alias_roundtrips_through_schema_runtime -- --nocapture
cargo test -p urcodec --test model_text aarch64_conditional_branch_uses_schema_alias_text -- --nocapture
```

Expected: FAIL because only `ret` is runtime-owned.

- [ ] **Step 3: Add AArch64 adapters and full schema declarations**

Create `crates/urcodec/src/arch/aarch64/adapters.rs` with helper functions for:

- register-bank lookup for `x`, `w`, `x_or_sp`, `w_or_sp`, `x_or_zr`, `w_or_zr`
- signed immediate extraction from bit ranges
- AArch64 branch target calculation
- condition-code string lookup
- move-wide and logical-immediate immediate transforms

Then replace the body of `crates/urcodec/src/arch/aarch64/forms.rs` with `FormSchema` declarations for:

- `nop`
- `ret`
- `br`
- `blr`
- `b_imm26`
- `bl_imm26`
- `b_cond`
- `cbz`
- `cbnz`
- `tbz`
- `tbnz`
- `adr`
- `adrp`
- `add_imm`
- `sub_imm`
- `cmp_imm`
- `cmn_imm`
- `move_wide`
- `logical_imm`
- `bitfield_alias`

Populate each schema with:

- `DecodeLayout::FixedWidthBits { width: 32 }`
- `Matcher::MaskEq { ... }`
- named `FieldSpec` entries
- `OperandSpec` entries
- `TextRule`
- alias rules where needed
- encode requirements

- [ ] **Step 4: Extend runtime modules until AArch64 tests pass**

Implement enough logic across `runtime/fields.rs`, `runtime/operands.rs`, `runtime/text.rs`, `runtime/alias.rs`, and `runtime/encode.rs` to support the AArch64 families above, including:

- fixed-width bit extraction
- scaled relative branch targets
- alias-aware text rendering for `cmp`, `cmn`, and `b.eq`
- parse of canonical and alias AArch64 mnemonics
- encode validation and emission for migrated AArch64 forms

- [ ] **Step 5: Re-run the focused AArch64 tests and verify they pass**

Run:

```bash
cargo test -p urcodec --test seed_forms aarch64_cmp_alias_roundtrips_through_schema_runtime -- --nocapture
cargo test -p urcodec --test model_text aarch64_conditional_branch_uses_schema_alias_text -- --nocapture
cargo test -p urcodec --test aarch64_decode -- --nocapture
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/urcodec/src/arch/aarch64 crates/urcodec/src/runtime crates/urcodec/tests/seed_forms.rs crates/urcodec/tests/aarch64_decode.rs crates/urcodec/tests/model_text.rs
git commit -m "refactor: move aarch64 urcodec support to schema runtime"
```

### Task 5: Migrate x86-64 Families Onto Runtime Ownership

**Files:**
- Modify: `crates/urcodec/src/arch/x86_64/forms.rs`
- Create: `crates/urcodec/src/arch/x86_64/adapters.rs`
- Modify: `crates/urcodec/src/arch/x86_64/mod.rs`
- Modify: `crates/urcodec/src/runtime/layout.rs`
- Modify: `crates/urcodec/src/runtime/fields.rs`
- Modify: `crates/urcodec/src/runtime/operands.rs`
- Modify: `crates/urcodec/src/runtime/text.rs`
- Modify: `crates/urcodec/src/runtime/alias.rs`
- Modify: `crates/urcodec/src/runtime/encode.rs`
- Modify: `crates/urcodec/tests/seed_forms.rs`
- Modify: `crates/urcodec/tests/x86_64_decode.rs`
- Modify: `crates/urcodec/tests/model_text.rs`

- [ ] **Step 1: Add failing x86-64 roundtrip and alias tests**

Append to `crates/urcodec/tests/seed_forms.rs`:

```rust
#[test]
fn x86_call_rm64_roundtrips_through_schema_runtime() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xff, 0xd0];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(decoded.form.as_deref(), Some("x86_64.call_rm64"));
    assert_eq!(urcodec::format_instruction(&decoded), "call rax");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("call rax", 0x401000).unwrap();
    assert_eq!(parsed.form.as_deref(), Some("x86_64.call_rm64"));
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
```

Append to `crates/urcodec/tests/model_text.rs`:

```rust
#[test]
fn x86_conditional_branch_uses_named_schema_alias_text() {
    let decoder = urcodec::Decoder::new(
        urcodec::Architecture::X86_64,
        urcodec::DecodeOptions::default(),
    )
    .unwrap();
    let instruction = decoder
        .decode_one(&[0x0f, 0x85, 0xfa, 0x00, 0x00, 0x00], 0x401000)
        .unwrap();
    assert_eq!(urcodec::format_instruction(&instruction), "jne 0x401100");
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p urcodec --test seed_forms x86_call_rm64_roundtrips_through_schema_runtime -- --nocapture
cargo test -p urcodec --test model_text x86_conditional_branch_uses_named_schema_alias_text -- --nocapture
```

Expected: FAIL because only `ret` and AArch64 families are runtime-owned.

- [ ] **Step 3: Add x86-64 adapters and full schema declarations**

Create `crates/urcodec/src/arch/x86_64/adapters.rs` with helpers for:

- ModRM splitting
- SIB splitting
- general-purpose register mapping
- relative branch target calculation
- condition-code mnemonic lookup
- REX.W-sensitive register and opcode-ext interpretation

Then replace the body of `crates/urcodec/src/arch/x86_64/forms.rs` with `FormSchema` declarations for:

- `ret`
- `ret_imm16`
- `retf`
- `call_rel32`
- `call_rm64`
- `jmp_rel8`
- `jmp_rel32`
- `jmp_rm64`
- `jcc_rel8`
- `jcc_rel32`
- `loopne_rel8`
- `loope_rel8`
- `loop_rel8`
- `jrcxz_rel8`
- `mov_r64_imm64`

Populate each schema with:

- `DecodeLayout::ByteStream(ByteStreamLayout { ... })`
- opcode and ModRM matchers
- named fields
- operand specs
- `TextRule`
- encode requirements

- [ ] **Step 4: Extend runtime modules until x86-64 tests pass**

Implement enough logic across `runtime/layout.rs`, `runtime/fields.rs`, `runtime/operands.rs`, `runtime/text.rs`, `runtime/alias.rs`, and `runtime/encode.rs` to support the x86-64 families above, including:

- opcode and ModRM matching
- immediate and relative displacement extraction
- register operand mapping
- named conditional-branch text aliases
- parse of migrated x86-64 mnemonics
- byte emission for migrated x86-64 forms

- [ ] **Step 5: Re-run the focused x86-64 tests and verify they pass**

Run:

```bash
cargo test -p urcodec --test seed_forms x86_call_rm64_roundtrips_through_schema_runtime -- --nocapture
cargo test -p urcodec --test model_text x86_conditional_branch_uses_named_schema_alias_text -- --nocapture
cargo test -p urcodec --test x86_64_decode -- --nocapture
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/urcodec/src/arch/x86_64 crates/urcodec/src/runtime crates/urcodec/tests/seed_forms.rs crates/urcodec/tests/x86_64_decode.rs crates/urcodec/tests/model_text.rs
git commit -m "refactor: move x86_64 urcodec support to schema runtime"
```

### Task 6: Delete Legacy Decoder And Formatter Ownership

**Files:**
- Modify: `crates/urcodec/src/arch/mod.rs`
- Modify: `crates/urcodec/src/arch/aarch64/mod.rs`
- Modify: `crates/urcodec/src/arch/x86_64/mod.rs`
- Delete: `crates/urcodec/src/arch/aarch64/decode.rs`
- Delete: `crates/urcodec/src/arch/aarch64/format.rs`
- Delete: `crates/urcodec/src/arch/x86_64/decode.rs`
- Delete: `crates/urcodec/src/arch/x86_64/format.rs`
- Test: `crates/urcodec/tests/public_api.rs`

- [ ] **Step 1: Write the failing regression test that proves runtime is the only owner**

Append to `crates/urcodec/tests/public_api.rs`:

```rust
#[test]
fn public_decoder_works_without_arch_specific_decode_modules() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let decoded = decoder.decode_one(&[0xc3], 0x401000).unwrap();
    assert_eq!(decoded.form.as_deref(), Some("x86_64.ret"));
}
```

- [ ] **Step 2: Run the focused test and verify it passes before deletion**

Run:

```bash
cargo test -p urcodec --test public_api public_decoder_works_without_arch_specific_decode_modules -- --nocapture
```

Expected: PASS

- [ ] **Step 3: Delete legacy modules and clean exports**

In `crates/urcodec/src/arch/aarch64/mod.rs`, replace:

```rust
pub mod decode;
pub mod format;
pub mod forms;
pub mod registers;
```

with:

```rust
pub mod adapters;
pub mod forms;
pub mod registers;
```

In `crates/urcodec/src/arch/x86_64/mod.rs`, replace:

```rust
pub mod decode;
pub mod format;
pub mod forms;
pub mod registers;
```

with:

```rust
pub mod adapters;
pub mod forms;
pub mod registers;
```

Delete:

```bash
rm crates/urcodec/src/arch/aarch64/decode.rs
rm crates/urcodec/src/arch/aarch64/format.rs
rm crates/urcodec/src/arch/x86_64/decode.rs
rm crates/urcodec/src/arch/x86_64/format.rs
```

- [ ] **Step 4: Re-run the focused test and verify it still passes**

Run:

```bash
cargo test -p urcodec --test public_api public_decoder_works_without_arch_specific_decode_modules -- --nocapture
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/urcodec/src/arch
git commit -m "refactor: remove legacy urcodec decoder and formatter modules"
```

### Task 7: Restore Oracle Coverage, Consumer Confidence, And Docs

**Files:**
- Modify: `crates/urcodec/tests/aarch64_capstone_oracle.rs`
- Modify: `crates/urcodec/tests/x86_64_capstone_oracle.rs`
- Modify: `crates/urdis2il/tests/aarch64_lift.rs`
- Modify: `crates/urdis2il/tests/x86_64_lift.rs`
- Modify: `crates/ura-core/tests/cfg_analysis.rs`
- Modify: `docs/urcodec/aarch64-coverage.md`
- Modify: `docs/urcodec/x86_64-coverage.md`

- [ ] **Step 1: Add focused consumer and oracle assertions**

Append to `crates/ura-core/tests/cfg_analysis.rs`:

```rust
#[test]
fn x86_call_edges_still_follow_runtime_branch_targets() {
    let summary = analyze_x86_64_bytes(&[0xe8, 0x05, 0x00, 0x00, 0x00, 0xc3], 0x401000);
    assert_eq!(summary.cfg_edges.len(), 2);
    assert!(summary
        .cfg_edges
        .iter()
        .any(|edge| edge.to == 0x40100a && edge.kind == "call"));
}
```

Append to `crates/urdis2il/tests/aarch64_lift.rs`:

```rust
#[test]
fn lifts_runtime_owned_cmp_alias_then_branch() {
    let block = lift_aarch64_words(&[0xf100201f, 0x54000060], 0x400100);
    assert!(block
        .statements
        .iter()
        .any(|stmt| format!("{stmt:?}").contains("Compare")));
}
```

- [ ] **Step 2: Run the focused consumer tests and verify they pass before docs**

Run:

```bash
cargo test -p ura-core --test cfg_analysis x86_call_edges_still_follow_runtime_branch_targets -- --nocapture
cargo test -p urdis2il --test aarch64_lift lifts_runtime_owned_cmp_alias_then_branch -- --nocapture
```

Expected: PASS

- [ ] **Step 3: Update coverage docs**

In `docs/urcodec/aarch64-coverage.md`, replace the old wording with:

```md
## Runtime-Owned Families

- Control flow: `nop`, `ret`, `br`, `blr`, `b`, `bl`, `b.cond`, `cbz`, `cbnz`, `tbz`, `tbnz`
- PC-relative address: `adr`, `adrp`
- Arithmetic immediate: `add`, `sub`, `cmp`, `cmn`
- Alias-bearing scalar forms: `mov`, logical-immediate aliases, bitfield aliases
```

In `docs/urcodec/x86_64-coverage.md`, replace the old wording with:

```md
## Runtime-Owned Families

- Return: `ret`, `ret imm16`, `retf`
- Calls and jumps: `call rel32`, `call r/m64`, `jmp rel8`, `jmp rel32`, `jmp r/m64`
- Conditional control flow: `jcc rel8`, `jcc rel32`, `loop`, `loopne`, `loope`, `jrcxz`
- Data movement: `mov r64, imm64`
```

- [ ] **Step 4: Run full verification**

Run:

```bash
cargo fmt --check
cargo test -p urcodec
cargo test -p urdis2il
cargo test -p ura-core
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected:

- `cargo fmt --check`: exits 0
- all `cargo test` commands: all tests PASS
- `cargo clippy --workspace --all-targets -- -D warnings`: exits 0

- [ ] **Step 5: Commit**

```bash
git add crates/urcodec/tests crates/urdis2il/tests crates/ura-core/tests docs/urcodec/aarch64-coverage.md docs/urcodec/x86_64-coverage.md
git commit -m "test: restore urcodec runtime coverage and consumer confidence"
```

## Self-Review Checklist

- Spec coverage:
  - explicit single-source schema ownership: Tasks 2, 3, 4, 5
  - runtime contract with no guessed architecture: Tasks 1 and 3
  - AArch64 first, x86-64 second: Tasks 4 then 5
  - no legacy fallback or coexistence: Tasks 3 and 6
  - alias/text/encode unification: Tasks 3, 4, and 5
  - oracle and consumer regression: Task 7
- Placeholder scan:
  - no `TBD`, `TODO`, or "implement later" markers remain
  - every code-changing step includes exact code or exact commands
- Type consistency:
  - runtime uses `FormSchema`, not `InstructionForm`
  - `Instruction` carries `architecture` and `form`
  - text routing keys off explicit instruction identity, not byte-length guesses
