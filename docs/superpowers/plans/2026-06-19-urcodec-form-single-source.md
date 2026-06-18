# Urcodec Form Single Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `urcodec`'s callback-based forms and split decode logic with one schema-driven runtime that owns decode, encode, text formatting, and text parsing for both AArch64 and x86-64.

**Architecture:** Rewrite `urcodec` around `FormSchema` plus a generic runtime pipeline (`layout -> match -> fields -> operands -> alias -> encode`), then repopulate AArch64 and x86-64 support as schema data plus small architecture adapters. This is a hard cut: delete the legacy form callback model and old decoder/formatter ownership instead of layering the new runtime beside it.

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

- Modify `crates/urcodec/src/form.rs`: replace callback-based `InstructionForm` with declarative schema types.
- Create `crates/urcodec/src/runtime/mod.rs`: runtime facade and shared helper exports.
- Create `crates/urcodec/src/runtime/layout.rs`: `LayoutView` readers for AArch64 fixed-width and x86-64 byte-stream encodings.
- Create `crates/urcodec/src/runtime/matcher.rs`: candidate bucket selection and matcher evaluation.
- Create `crates/urcodec/src/runtime/fields.rs`: named field extraction from layout views.
- Create `crates/urcodec/src/runtime/operands.rs`: field-to-operand mapping and reverse operand matching.
- Create `crates/urcodec/src/runtime/alias.rs`: canonicalization and display-alias selection.
- Create `crates/urcodec/src/runtime/encode.rs`: runtime byte emission and encode validation.
- Modify `crates/urcodec/src/decoder.rs`: route `Decoder` through runtime only.
- Modify `crates/urcodec/src/encode.rs`: route `Encoder` through runtime only.
- Modify `crates/urcodec/src/text.rs`: route `TextParser` and `format_instruction` through runtime only.
- Modify `crates/urcodec/src/lib.rs`: export the new schema/runtime surface and stop exporting legacy callback form types.
- Modify `crates/urcodec/src/arch/mod.rs`: wire new architecture adapter modules.
- Modify `crates/urcodec/src/arch/aarch64/forms.rs`: replace hand-written form callbacks with AArch64 schema declarations.
- Create `crates/urcodec/src/arch/aarch64/adapters.rs`: AArch64 field transforms, register-bank mapping, and alias helpers.
- Modify `crates/urcodec/src/arch/aarch64/mod.rs`: export AArch64 schema registry and adapters.
- Delete `crates/urcodec/src/arch/aarch64/decode.rs`: schema runtime supersedes the legacy decoder.
- Delete `crates/urcodec/src/arch/aarch64/format.rs`: schema alias rules supersede legacy formatting.
- Modify `crates/urcodec/src/arch/x86_64/forms.rs`: replace hand-written form callbacks with x86-64 schema declarations.
- Create `crates/urcodec/src/arch/x86_64/adapters.rs`: x86-64 prefix, ModRM/SIB, register-bank, and branch helper logic.
- Modify `crates/urcodec/src/arch/x86_64/mod.rs`: export x86-64 schema registry and adapters.
- Delete `crates/urcodec/src/arch/x86_64/decode.rs`: schema runtime supersedes the legacy decoder.
- Delete `crates/urcodec/src/arch/x86_64/format.rs`: schema alias rules supersede legacy formatting.
- Modify `crates/urcodec/tests/public_api.rs`: prove the public `Decoder`/`Encoder`/`TextParser` API still works after the rewrite.
- Modify `crates/urcodec/tests/model_text.rs`: prove schema-driven canonical text and alias formatting.
- Modify `crates/urcodec/tests/seed_forms.rs`: update roundtrip coverage to the new runtime and add alias-focused checks.
- Modify `crates/urcodec/tests/aarch64_decode.rs`: keep fixed-width decode coverage green under runtime ownership.
- Modify `crates/urcodec/tests/x86_64_decode.rs`: keep x86-64 decode coverage green under runtime ownership.
- Modify `crates/urcodec/tests/aarch64_capstone_oracle.rs`: keep AArch64 oracle coverage aligned with the new runtime.
- Modify `crates/urcodec/tests/x86_64_capstone_oracle.rs`: keep x86-64 oracle coverage aligned with the new runtime.
- Modify `crates/urdis2il/tests/aarch64_lift.rs`: verify the consumer still gets the same control-flow semantics.
- Modify `crates/urdis2il/tests/x86_64_lift.rs`: verify the consumer still gets the same control-flow semantics.
- Modify `crates/ura-core/tests/cfg_analysis.rs`: verify CFG and branch-edge behavior still matches runtime output.
- Modify `docs/urcodec/aarch64-coverage.md`: reflect the new AArch64 schema-owned families.
- Modify `docs/urcodec/x86_64-coverage.md`: reflect the new x86-64 schema-owned families.

### Task 1: Replace The Core Form API With Declarative Schema Types

**Files:**
- Modify: `crates/urcodec/src/form.rs`
- Modify: `crates/urcodec/src/lib.rs`
- Test: `crates/urcodec/tests/public_api.rs`

- [ ] **Step 1: Write the failing public test for schema-backed form registries**

Append to `crates/urcodec/tests/public_api.rs`:

```rust
#[test]
fn form_registries_expose_declarative_layout_kinds() {
    let x86_ret = urcodec::arch::x86_64::forms::all_forms()
        .iter()
        .find(|form| form.id().local_name() == "ret")
        .expect("x86 ret form should exist");
    assert!(matches!(
        x86_ret.decode_layout(),
        urcodec::form::DecodeLayout::ByteStream(_)
    ));

    let aarch64_ret = urcodec::arch::aarch64::forms::all_forms()
        .iter()
        .find(|form| form.id().local_name() == "ret")
        .expect("aarch64 ret form should exist");
    assert!(matches!(
        aarch64_ret.decode_layout(),
        urcodec::form::DecodeLayout::FixedWidthBits { width: 32 }
    ));
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
cargo test -p urcodec --test public_api form_registries_expose_declarative_layout_kinds -- --nocapture
```

Expected: compile fails because `DecodeLayout` and `decode_layout()` do not exist.

- [ ] **Step 3: Replace callback forms with schema structs**

Replace the callback-centric body of `crates/urcodec/src/form.rs` with these core declarations:

```rust
use crate::model::{Architecture, FlowKind, InstructionKind};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FormId {
    architecture: Architecture,
    local_name: &'static str,
}

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
    RexW(bool),
    ModrmMode { mode: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSource {
    Bits { start: u8, end: u8 },
    SignedBits { start: u8, end: u8 },
    OpcodeLow3,
    ModrmReg,
    ModrmRm,
    ModrmMode,
    Immediate8,
    Immediate16,
    Immediate32,
    Immediate64,
    Displacement8,
    Displacement32,
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
    Condition { field: &'static str, table: &'static str },
    Memory {
        base: Option<&'static str>,
        index: Option<&'static str>,
        scale: Option<&'static str>,
        displacement: Option<&'static str>,
        width_bits: Option<u16>,
        relative: bool,
    },
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
pub struct FormSchema {
    id: FormId,
    mnemonic: &'static str,
    kind: InstructionKind,
    flow: FlowKind,
    decode_layout: DecodeLayout,
    matchers: &'static [Matcher],
    fields: &'static [FieldSpec],
    operands: &'static [OperandSpec],
    aliases: &'static [AliasRule],
    encode_rule: EncodeRule,
}
```

Also add these accessors near the end of the file:

```rust
impl FormSchema {
    pub const fn decode_layout(&self) -> DecodeLayout {
        self.decode_layout
    }

    pub const fn matchers(&self) -> &'static [Matcher] {
        self.matchers
    }

    pub const fn fields(&self) -> &'static [FieldSpec] {
        self.fields
    }

    pub const fn operands(&self) -> &'static [OperandSpec] {
        self.operands
    }
}
```

Update the form export in `crates/urcodec/src/lib.rs`:

```rust
pub use form::{
    AliasRule, ByteStreamLayout, DecodeLayout, EncodeRule, FieldSource, FieldSpec, FormId,
    FormSchema, Matcher, OperandSpec,
};
```

- [ ] **Step 4: Make the architecture form registries return `FormSchema`**

At the top of both `crates/urcodec/src/arch/aarch64/forms.rs` and `crates/urcodec/src/arch/x86_64/forms.rs`, replace the old import:

```rust
use crate::form::{FormId, InstructionForm};
```

with:

```rust
use crate::form::{
    AliasRule, ByteStreamLayout, DecodeLayout, EncodeRule, FieldSource, FieldSpec, FormId,
    FormSchema, Matcher, OperandSpec,
};
```

Then change:

```rust
static FORMS: &[InstructionForm] = &[
```

to:

```rust
static FORMS: &[FormSchema] = &[
```

and:

```rust
pub fn all_forms() -> &'static [InstructionForm] {
```

to:

```rust
pub fn all_forms() -> &'static [FormSchema] {
```

- [ ] **Step 5: Re-run the focused test and verify it passes**

Run:

```bash
cargo test -p urcodec --test public_api form_registries_expose_declarative_layout_kinds -- --nocapture
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/urcodec/src/form.rs crates/urcodec/src/lib.rs crates/urcodec/src/arch/aarch64/forms.rs crates/urcodec/src/arch/x86_64/forms.rs crates/urcodec/tests/public_api.rs
git commit -m "refactor: replace urcodec callback forms with schema types"
```

### Task 2: Introduce The Shared Runtime Pipeline

**Files:**
- Create: `crates/urcodec/src/runtime/mod.rs`
- Create: `crates/urcodec/src/runtime/layout.rs`
- Create: `crates/urcodec/src/runtime/matcher.rs`
- Create: `crates/urcodec/src/runtime/fields.rs`
- Create: `crates/urcodec/src/runtime/operands.rs`
- Create: `crates/urcodec/src/runtime/alias.rs`
- Create: `crates/urcodec/src/runtime/encode.rs`
- Modify: `crates/urcodec/src/decoder.rs`
- Modify: `crates/urcodec/src/encode.rs`
- Modify: `crates/urcodec/src/text.rs`
- Modify: `crates/urcodec/src/lib.rs`
- Test: `crates/urcodec/tests/public_api.rs`

- [ ] **Step 1: Write the failing runtime ownership test**

Append to `crates/urcodec/tests/public_api.rs`:

```rust
#[test]
fn decoder_encoder_and_parser_share_the_same_runtime_surface() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xd65f03c0u32.to_le_bytes();
    let instruction = decoder.decode_one(&bytes, 0x400080).unwrap();
    assert_eq!(urcodec::format_instruction(&instruction), "ret");
    assert_eq!(encoder.encode_one(&instruction).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("ret", 0x400080).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
cargo test -p urcodec --test public_api decoder_encoder_and_parser_share_the_same_runtime_surface -- --nocapture
```

Expected: compile fails or panics because the old callback paths were removed in Task 1 but no runtime exists yet.

- [ ] **Step 3: Create the runtime skeleton**

Create `crates/urcodec/src/runtime/mod.rs`:

```rust
pub mod alias;
pub mod encode;
pub mod fields;
pub mod layout;
pub mod matcher;
pub mod operands;

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
    operands::build_instruction(form, &layout, &fields)
}

pub fn encode_one(
    architecture: Architecture,
    forms: &'static [FormSchema],
    instruction: &Instruction,
) -> Result<Vec<u8>, EncodeError> {
    let canonical = alias::canonicalize_instruction(architecture, forms, instruction)?;
    encode::emit_instruction(architecture, forms, &canonical)
}

pub fn parse_one(
    architecture: Architecture,
    forms: &'static [FormSchema],
    text: &str,
    address: u64,
) -> Result<Instruction, TextError> {
    alias::parse_instruction(architecture, forms, text, address)
}
```

Create `crates/urcodec/src/runtime/layout.rs`:

```rust
use crate::{
    error::DecodeError,
    form::DecodeLayout,
    model::Architecture,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutView {
    Aarch64Word { word: u32, bytes: [u8; 4], address: u64 },
    X86ByteStream { bytes: Vec<u8>, address: u64 },
}

pub fn read_layout(
    architecture: Architecture,
    bytes: &[u8],
    address: u64,
) -> Result<LayoutView, DecodeError> {
    match architecture {
        Architecture::Aarch64 => {
            let word = bytes.get(..4).ok_or(DecodeError::TruncatedInstruction {
                expected: 4,
                actual: bytes.len(),
            })?;
            Ok(LayoutView::Aarch64Word {
                word: u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
                bytes: [word[0], word[1], word[2], word[3]],
                address,
            })
        }
        Architecture::X86_64 => Ok(LayoutView::X86ByteStream {
            bytes: bytes.to_vec(),
            address,
        }),
    }
}
```

- [ ] **Step 4: Route the public entrypoints through runtime**

In `crates/urcodec/src/decoder.rs`, replace `decode_one()` with:

```rust
pub fn decode_one(&self, bytes: &[u8], address: u64) -> Result<Instruction> {
    match self.architecture {
        Architecture::Aarch64 => crate::runtime::decode_one(
            self.architecture,
            crate::arch::aarch64::forms::all_forms(),
            bytes,
            address,
        ),
        Architecture::X86_64 => crate::runtime::decode_one(
            self.architecture,
            crate::arch::x86_64::forms::all_forms(),
            bytes,
            address,
        ),
    }
}
```

In `crates/urcodec/src/encode.rs`, replace `encode_one()` with:

```rust
pub fn encode_one(&self, instruction: &Instruction) -> Result<Vec<u8>, EncodeError> {
    match self.architecture {
        Architecture::Aarch64 => crate::runtime::encode_one(
            self.architecture,
            crate::arch::aarch64::forms::all_forms(),
            instruction,
        ),
        Architecture::X86_64 => crate::runtime::encode_one(
            self.architecture,
            crate::arch::x86_64::forms::all_forms(),
            instruction,
        ),
    }
}
```

In `crates/urcodec/src/text.rs`, replace `parse_one()` with:

```rust
pub fn parse_one(&self, text: &str, address: u64) -> Result<Instruction, TextError> {
    match self.architecture {
        Architecture::Aarch64 => crate::runtime::parse_one(
            self.architecture,
            crate::arch::aarch64::forms::all_forms(),
            text,
            address,
        ),
        Architecture::X86_64 => crate::runtime::parse_one(
            self.architecture,
            crate::arch::x86_64::forms::all_forms(),
            text,
            address,
        ),
    }
}
```

Also add to `crates/urcodec/src/lib.rs`:

```rust
pub mod runtime;
```

- [ ] **Step 5: Re-run the focused test and verify it passes**

Run:

```bash
cargo test -p urcodec --test public_api decoder_encoder_and_parser_share_the_same_runtime_surface -- --nocapture
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/urcodec/src/runtime crates/urcodec/src/decoder.rs crates/urcodec/src/encode.rs crates/urcodec/src/text.rs crates/urcodec/src/lib.rs crates/urcodec/tests/public_api.rs
git commit -m "refactor: add urcodec schema runtime pipeline"
```

### Task 3: Move AArch64 Support To Schema Data Plus Adapters

**Files:**
- Modify: `crates/urcodec/src/arch/aarch64/forms.rs`
- Create: `crates/urcodec/src/arch/aarch64/adapters.rs`
- Modify: `crates/urcodec/src/arch/aarch64/mod.rs`
- Delete: `crates/urcodec/src/arch/aarch64/decode.rs`
- Delete: `crates/urcodec/src/arch/aarch64/format.rs`
- Modify: `crates/urcodec/tests/seed_forms.rs`
- Modify: `crates/urcodec/tests/aarch64_decode.rs`
- Modify: `crates/urcodec/tests/model_text.rs`

- [ ] **Step 1: Add failing AArch64 alias and roundtrip tests**

Append to `crates/urcodec/tests/seed_forms.rs`:

```rust
#[test]
fn aarch64_cmp_alias_roundtrips_through_schema_runtime() {
    let decoder = Decoder::new(Architecture::Aarch64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::Aarch64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::Aarch64, TextOptions::default()).unwrap();

    let bytes = 0xf100201fu32.to_le_bytes();
    let decoded = decoder.decode_one(&bytes, 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "cmp x0, #0x8");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("cmp x0, #0x8", 0x400100).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
```

Append to `crates/urcodec/tests/model_text.rs`:

```rust
#[test]
fn canonical_text_prefers_aarch64_aliases_from_schema_rules() {
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

- [ ] **Step 2: Run the focused AArch64 tests and verify they fail**

Run:

```bash
cargo test -p urcodec --test seed_forms aarch64_cmp_alias_roundtrips_through_schema_runtime -- --nocapture
cargo test -p urcodec --test model_text canonical_text_prefers_aarch64_aliases_from_schema_rules -- --nocapture
```

Expected: FAIL because AArch64 forms no longer own decode, parse, alias selection, or encode behavior.

- [ ] **Step 3: Add AArch64 adapter helpers**

Create `crates/urcodec/src/arch/aarch64/adapters.rs`:

```rust
use crate::{
    bits::{bits, sign_extend},
    model::{Operand, Register},
};

pub fn x_reg(index: u32) -> Register {
    Register {
        name: format!("x{index}"),
    }
}

pub fn condition_name(cond: i64) -> &'static str {
    match cond {
        0 => "eq",
        1 => "ne",
        2 => "cs",
        3 => "cc",
        4 => "mi",
        5 => "pl",
        6 => "vs",
        7 => "vc",
        8 => "hi",
        9 => "ls",
        10 => "ge",
        11 => "lt",
        12 => "gt",
        13 => "le",
        14 => "al",
        _ => "nv",
    }
}

pub fn branch_target(address: u64, size: u8, imm: i64, scale: u8) -> u64 {
    ((address + u64::from(size)) as i64 + (imm * i64::from(scale))) as u64
}

pub fn signed_field(word: u32, start: u8, end: u8) -> i64 {
    sign_extend(bits(word, start, end), end - start + 1)
}
```

- [ ] **Step 4: Rewrite the AArch64 form table as pure schema data**

At the top of `crates/urcodec/src/arch/aarch64/forms.rs`, replace the old callback-driven entries with schema declarations like:

```rust
static RET_FIELDS: &[FieldSpec] = &[FieldSpec {
    name: "rn",
    source: FieldSource::Bits { start: 5, end: 9 },
}];

static RET_OPERANDS: &[OperandSpec] = &[OperandSpec::Register {
    field: "rn",
    bank: "aarch64.x_or_lr_omittable",
}];

static RET_FORM: FormSchema = FormSchema::new(
    FormId::new(Architecture::Aarch64, "ret"),
    "ret",
    InstructionKind::Return,
    FlowKind::Return,
    DecodeLayout::FixedWidthBits { width: 32 },
    &[Matcher::MaskEq {
        mask: 0xffff_fc1f,
        value: 0xd65f_0000,
    }],
    RET_FIELDS,
    RET_OPERANDS,
    &[],
    EncodeRule {
        require: &["rn == 30 || register(xN)"],
        canonical_preference: "omit lr operand when rn == 30",
    },
);
```

Do the same for:

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

Make `all_forms()` return a slice of these schema constants only.

- [ ] **Step 5: Export adapters and delete legacy AArch64 ownership**

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

Then delete:

```bash
rm crates/urcodec/src/arch/aarch64/decode.rs
rm crates/urcodec/src/arch/aarch64/format.rs
```

- [ ] **Step 6: Re-run the focused AArch64 tests and verify they pass**

Run:

```bash
cargo test -p urcodec --test seed_forms aarch64_cmp_alias_roundtrips_through_schema_runtime -- --nocapture
cargo test -p urcodec --test model_text canonical_text_prefers_aarch64_aliases_from_schema_rules -- --nocapture
cargo test -p urcodec --test aarch64_decode -- --nocapture
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crates/urcodec/src/arch/aarch64 crates/urcodec/tests/seed_forms.rs crates/urcodec/tests/aarch64_decode.rs crates/urcodec/tests/model_text.rs
git commit -m "refactor: move aarch64 urcodec support to schema runtime"
```

### Task 4: Move x86-64 Support To Schema Data Plus Adapters

**Files:**
- Modify: `crates/urcodec/src/arch/x86_64/forms.rs`
- Create: `crates/urcodec/src/arch/x86_64/adapters.rs`
- Modify: `crates/urcodec/src/arch/x86_64/mod.rs`
- Delete: `crates/urcodec/src/arch/x86_64/decode.rs`
- Delete: `crates/urcodec/src/arch/x86_64/format.rs`
- Modify: `crates/urcodec/tests/seed_forms.rs`
- Modify: `crates/urcodec/tests/x86_64_decode.rs`
- Modify: `crates/urcodec/tests/model_text.rs`

- [ ] **Step 1: Add failing x86-64 branch and indirect-call tests**

Append to `crates/urcodec/tests/seed_forms.rs`:

```rust
#[test]
fn x86_call_rm64_roundtrips_through_schema_runtime() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();

    let bytes = [0xff, 0xd0];
    let decoded = decoder.decode_one(&bytes, 0x401000).unwrap();
    assert_eq!(urcodec::format_instruction(&decoded), "call rax");
    assert_eq!(encoder.encode_one(&decoded).unwrap(), bytes.to_vec());

    let parsed = parser.parse_one("call rax", 0x401000).unwrap();
    assert_eq!(encoder.encode_one(&parsed).unwrap(), bytes.to_vec());
}
```

Append to `crates/urcodec/tests/model_text.rs`:

```rust
#[test]
fn canonical_text_prefers_named_x86_condition_aliases_from_schema_rules() {
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

- [ ] **Step 2: Run the focused x86-64 tests and verify they fail**

Run:

```bash
cargo test -p urcodec --test seed_forms x86_call_rm64_roundtrips_through_schema_runtime -- --nocapture
cargo test -p urcodec --test model_text canonical_text_prefers_named_x86_condition_aliases_from_schema_rules -- --nocapture
```

Expected: FAIL because the runtime does not yet understand x86-64 prefix, ModRM, indirect branch, or conditional-branch schema semantics.

- [ ] **Step 3: Add x86-64 adapter helpers**

Create `crates/urcodec/src/arch/x86_64/adapters.rs`:

```rust
use crate::model::Register;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModrmParts {
    pub mode: u8,
    pub reg: u8,
    pub rm: u8,
}

pub fn decode_modrm(byte: u8) -> ModrmParts {
    ModrmParts {
        mode: (byte >> 6) & 0x3,
        reg: (byte >> 3) & 0x7,
        rm: byte & 0x7,
    }
}

pub fn reg64(index: u8) -> Register {
    let name = match index {
        0 => "rax",
        1 => "rcx",
        2 => "rdx",
        3 => "rbx",
        4 => "rsp",
        5 => "rbp",
        6 => "rsi",
        7 => "rdi",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "r13",
        14 => "r14",
        _ => "r15",
    };
    Register {
        name: name.to_string(),
    }
}

pub fn rel_target(address: u64, size: u8, displacement: i64) -> u64 {
    ((address + u64::from(size)) as i64 + displacement) as u64
}
```

- [ ] **Step 4: Rewrite the x86-64 form table as pure schema data**

In `crates/urcodec/src/arch/x86_64/forms.rs`, declare schema constants for:

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

Use the new schema form:

```rust
static CALL_RM64_FORM: FormSchema = FormSchema::new(
    FormId::new(Architecture::X86_64, "call_rm64"),
    "call",
    InstructionKind::Call,
    FlowKind::IndirectCall,
    DecodeLayout::ByteStream(ByteStreamLayout {
        opcode_len: 1,
        uses_modrm: true,
        uses_sib: false,
        displacement_bytes: None,
        immediate_bytes: None,
    }),
    &[
        Matcher::OpcodeEq(&[0xff]),
        Matcher::OpcodeExt { reg: 2 },
        Matcher::ModrmMode { mode: 3 },
    ],
    &[
        FieldSpec {
            name: "rm",
            source: FieldSource::ModrmRm,
        },
    ],
    &[OperandSpec::Register {
        field: "rm",
        bank: "x86_64.gpr64",
    }],
    &[],
    EncodeRule {
        require: &["operand[0] is register64"],
        canonical_preference: "use modrm mode 3 for register operands",
    },
);
```

Make `all_forms()` return a slice of these schema constants only.

- [ ] **Step 5: Export adapters and delete legacy x86-64 ownership**

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

Then delete:

```bash
rm crates/urcodec/src/arch/x86_64/decode.rs
rm crates/urcodec/src/arch/x86_64/format.rs
```

- [ ] **Step 6: Re-run the focused x86-64 tests and verify they pass**

Run:

```bash
cargo test -p urcodec --test seed_forms x86_call_rm64_roundtrips_through_schema_runtime -- --nocapture
cargo test -p urcodec --test model_text canonical_text_prefers_named_x86_condition_aliases_from_schema_rules -- --nocapture
cargo test -p urcodec --test x86_64_decode -- --nocapture
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crates/urcodec/src/arch/x86_64 crates/urcodec/tests/seed_forms.rs crates/urcodec/tests/x86_64_decode.rs crates/urcodec/tests/model_text.rs
git commit -m "refactor: move x86_64 urcodec support to schema runtime"
```

### Task 5: Finish Alias Canonicalization, Public Text Behavior, And Encode Roundtrips

**Files:**
- Modify: `crates/urcodec/src/runtime/alias.rs`
- Modify: `crates/urcodec/src/runtime/encode.rs`
- Modify: `crates/urcodec/src/text.rs`
- Modify: `crates/urcodec/tests/model_text.rs`
- Modify: `crates/urcodec/tests/seed_forms.rs`
- Modify: `crates/urcodec/tests/public_api.rs`

- [ ] **Step 1: Add failing canonicalization tests**

Append to `crates/urcodec/tests/model_text.rs`:

```rust
#[test]
fn parse_and_format_canonicalize_cmp_aliases_before_encode() {
    let parser = urcodec::TextParser::new(
        urcodec::Architecture::Aarch64,
        urcodec::TextOptions::default(),
    )
    .unwrap();
    let encoder = urcodec::Encoder::new(
        urcodec::Architecture::Aarch64,
        urcodec::EncodeOptions::default(),
    )
    .unwrap();

    let parsed = parser.parse_one("cmp x0, #0x8", 0x400100).unwrap();
    assert_eq!(urcodec::format_instruction(&parsed), "cmp x0, #0x8");
    assert_eq!(encoder.encode_one(&parsed).unwrap(), 0xf100201fu32.to_le_bytes());
}
```

Append to `crates/urcodec/tests/public_api.rs`:

```rust
#[test]
fn x86_named_branch_aliases_roundtrip_through_public_api() {
    let parser = TextParser::new(Architecture::X86_64, TextOptions::default()).unwrap();
    let encoder = Encoder::new(Architecture::X86_64, EncodeOptions::default()).unwrap();

    let parsed = parser.parse_one("jne 0x401100", 0x401000).unwrap();
    assert_eq!(
        encoder.encode_one(&parsed).unwrap(),
        vec![0x0f, 0x85, 0xfa, 0x00, 0x00, 0x00]
    );
}
```

- [ ] **Step 2: Run the focused canonicalization tests and verify they fail**

Run:

```bash
cargo test -p urcodec --test model_text parse_and_format_canonicalize_cmp_aliases_before_encode -- --nocapture
cargo test -p urcodec --test public_api x86_named_branch_aliases_roundtrip_through_public_api -- --nocapture
```

Expected: FAIL because alias resolution and canonical pre-encode normalization are incomplete.

- [ ] **Step 3: Implement alias resolution and encode-side canonicalization**

In `crates/urcodec/src/runtime/alias.rs`, add:

```rust
use crate::{
    error::{EncodeError, TextError},
    form::FormSchema,
    model::{Architecture, Instruction},
};

pub fn canonicalize_instruction(
    _architecture: Architecture,
    forms: &'static [FormSchema],
    instruction: &Instruction,
) -> Result<Instruction, EncodeError> {
    let form = forms
        .iter()
        .find(|form| form.matches_instruction(instruction))
        .ok_or_else(|| EncodeError::UnsupportedForm(instruction.mnemonic.clone()))?;

    Ok(form.canonicalize_instruction(instruction))
}

pub fn choose_display_text(forms: &'static [FormSchema], instruction: &Instruction) -> String {
    forms.iter()
        .find(|form| form.matches_instruction(instruction))
        .map(|form| form.render_text(instruction))
        .unwrap_or_else(|| instruction.text.clone())
}

pub fn parse_instruction(
    _architecture: Architecture,
    forms: &'static [FormSchema],
    text: &str,
    address: u64,
) -> Result<Instruction, TextError> {
    forms.iter()
        .find_map(|form| form.parse_text(text, address))
        .ok_or_else(|| TextError::UnknownMnemonic(text.trim().to_string()))
}
```

In `crates/urcodec/src/text.rs`, replace `format_instruction()` with:

```rust
pub fn format_instruction(instruction: &Instruction) -> String {
    let forms = match instruction.mnemonic.as_str() {
        _ if instruction.bytes.len() == 4 => crate::arch::aarch64::forms::all_forms(),
        _ => crate::arch::x86_64::forms::all_forms(),
    };
    crate::runtime::alias::choose_display_text(forms, instruction)
}
```

- [ ] **Step 4: Re-run the focused canonicalization tests and verify they pass**

Run:

```bash
cargo test -p urcodec --test model_text parse_and_format_canonicalize_cmp_aliases_before_encode -- --nocapture
cargo test -p urcodec --test public_api x86_named_branch_aliases_roundtrip_through_public_api -- --nocapture
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/urcodec/src/runtime/alias.rs crates/urcodec/src/runtime/encode.rs crates/urcodec/src/text.rs crates/urcodec/tests/model_text.rs crates/urcodec/tests/seed_forms.rs crates/urcodec/tests/public_api.rs
git commit -m "refactor: finish urcodec alias canonicalization and encode roundtrips"
```

### Task 6: Restore Full Test Coverage, Consumer Confidence, And Docs

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
fn x86_call_edges_still_follow_schema_runtime_targets() {
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
fn lifts_schema_runtime_cmp_alias_as_compare_then_branch() {
    let block = lift_aarch64_words(&[0xf100201f, 0x54000060], 0x400100);
    assert!(block
        .statements
        .iter()
        .any(|stmt| format!("{stmt:?}").contains("Compare")));
}
```

- [ ] **Step 2: Run the focused consumer tests and verify they fail if any runtime regression remains**

Run:

```bash
cargo test -p ura-core --test cfg_analysis x86_call_edges_still_follow_schema_runtime_targets -- --nocapture
cargo test -p urdis2il --test aarch64_lift lifts_schema_runtime_cmp_alias_as_compare_then_branch -- --nocapture
```

Expected: PASS only after the runtime delivers the same semantics as before. If either fails, fix `urcodec` before touching docs.

- [ ] **Step 3: Update coverage docs**

In `docs/urcodec/aarch64-coverage.md`, replace the old seed-only wording with:

```md
## Runtime-Owned Families

- Control flow: `ret`, `br`, `blr`, `b`, `bl`, `b.cond`, `cbz`, `cbnz`, `tbz`, `tbnz`
- PC-relative address: `adr`, `adrp`
- Arithmetic immediate: `add`, `sub`, `cmp`, `cmn`
- Alias-bearing scalar forms: `mov`, logical-immediate aliases, bitfield aliases
```

In `docs/urcodec/x86_64-coverage.md`, replace the old callback-form wording with:

```md
## Runtime-Owned Families

- Return: `ret`, `ret imm16`, `retf`
- Calls and jumps: `call rel32`, `call r/m64`, `jmp rel8`, `jmp rel32`, `jmp r/m64`
- Conditional control flow: `jcc rel8`, `jcc rel32`, `loop`, `loopne`, `loope`, `jrcxz`
- Data movement: `mov r64, imm64`
```

- [ ] **Step 4: Run crate-level and workspace verification**

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
git commit -m "test: restore urcodec oracle and consumer confidence"
```

## Self-Review Checklist

- Spec coverage:
  - single-source schema ownership: Tasks 1, 2, 3, 4, 5
  - no legacy fallback or coexistence: Tasks 3 and 4 delete old decode/format files, Task 2 routes entrypoints only through runtime
  - AArch64 first, x86-64 second: Tasks 3 then 4
  - alias/text/encode unification: Task 5
  - oracle and consumer regression: Task 6
- Placeholder scan:
  - no `TBD`, `TODO`, or "implement later" markers remain
  - every code-changing step includes exact code or exact commands
- Type consistency:
  - runtime uses `FormSchema`, not legacy `InstructionForm`
  - layout ownership stays in `runtime/layout.rs`
  - alias behavior stays in `runtime/alias.rs`

