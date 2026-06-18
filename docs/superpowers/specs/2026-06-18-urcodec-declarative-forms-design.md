# Urcodec Declarative Forms Design

## Goal

Replace the current split between `urdisassembly` as model owner and future
assembly work with a single `urcodec` crate centered on declarative instruction
forms.

`urcodec` is the instruction codec layer. It owns the shared instruction model
and the bidirectional rules that connect bytes, structured instructions, and
canonical text.

The core design constraint is single source of truth: adding one instruction
shape must not require writing independent per-instruction decode and encode
logic. A form defines the instruction once, and decode, encode, text rendering,
text parsing, and roundtrip tests are projections of that form.

## Non-Goals

- Do not build a complete x86-64 or AArch64 assembler in the first pass.
- Do not attempt to preserve every external assembler text dialect.
- Do not merge `urdis2il` into `urcodec`; IL lifting remains a semantic layer.
- Do not change `urloader` responsibilities; file format loading stays separate.
- Do not make `ura-core` store format depend directly on unstable internal form
  definitions.

## Crate Boundary

The workspace should move from:

```text
urloader
urdisassembly
urdis2il
ura-core
ura-cli
ura-daemon
ura-corpus-gate
```

to:

```text
urloader
urcodec
urdis2il
ura-core
ura-cli
ura-daemon
ura-corpus-gate
```

`urdisassembly` is absorbed into `urcodec`. A separate `urinstruction` crate is
not created. A separate `urassembly` crate is not created.

`urcodec` owns:

- `Architecture`, `Endian`, and codec options.
- `Instruction`, `Operand`, `Register`, `MemoryOperand`.
- `InstructionKind`, `FlowKind`, `DecodeStatus`.
- Canonical text rendering.
- Text parsing into structured instructions.
- Byte decoding into structured instructions.
- Byte encoding from structured instructions.
- Unknown, partial, truncation, and unsupported encoding policy.
- Codec-level fixtures and roundtrip test utilities.

`urdis2il` depends on `urcodec`, not on `urdisassembly`.

`ura-core` depends on `urcodec` for decoding, then converts from `urcodec`
instructions into the persisted project instruction model. Directly storing
`urcodec::Instruction` can be reconsidered later after the codec model has
stabilized.

## Internal Modules

```text
crates/urcodec/
  Cargo.toml
  src/
    lib.rs
    model.rs
    error.rs
    form.rs
    fields.rs
    codec.rs
    text.rs
    decode.rs
    encode.rs
    arch/
      aarch64/
        mod.rs
        forms.rs
        fields.rs
        registers.rs
      x86_64/
        mod.rs
        forms.rs
        fields.rs
        modrm.rs
        registers.rs
```

`model.rs` contains stable public data structures.

`form.rs` contains the declarative instruction form model.

`fields.rs` contains reusable field binding types used by decode, encode, and
text parsing.

`decode.rs` and `encode.rs` contain generic engines and public facades. They do
not contain per-instruction business logic.

Architecture `forms.rs` files contain instruction knowledge. Architecture helper
modules may contain reusable primitives such as AArch64 bitfield extraction or
x86-64 ModRM/SIB field handling.

## Instruction Forms

An instruction form describes one canonical instruction shape.

It includes:

- Architecture.
- Stable form id.
- Mnemonic.
- Operand pattern.
- Instruction kind.
- Flow kind.
- Decode status when matched.
- Encoding pattern.
- Text pattern.
- Semantic aliases when applicable.
- Constraints such as register width, immediate width, target range, or
  ModRM/SIB mode.

Conceptual example:

```rust
form! {
    arch: X86_64,
    id: MovR64Imm64,
    mnemonic: "mov",
    operands: [reg64(dst), imm64(src)],
    kind: Move,
    flow: Fallthrough,
    encoding: [rex_w(), opcode_b8_plus(dst), imm64(src)],
    text: "{mnemonic} {dst}, {src}",
}
```

The macro shape is illustrative. The implementation can start with Rust structs
and helper constructors if a macro would hide too much too early. The important
property is that one form provides the data used by all directions.

## Single Source of Truth

The following are hard constraints:

- A supported instruction form is defined once.
- Decode uses form encoding patterns to bind byte fields into operands.
- Encode matches a structured instruction against the same form and emits bytes
  from the same field bindings.
- Text rendering uses the same operands and text pattern.
- Text parsing maps mnemonic and operands back to the same form.
- Tests for a form live next to the form or are generated from form fixtures.

This means long-term code should not accumulate pairs such as
`decode_mov_r64_imm64` and `encode_mov_r64_imm64`. Generic helpers are allowed,
but they must represent encoding primitives, not private per-instruction
implementations.

Allowed helpers:

- `read_imm32`, `write_imm32`.
- `decode_rel_target`, `encode_rel_target`.
- `match_modrm_rm`, `emit_modrm_rm`.
- `extract_bits`, `insert_bits`.
- `register_by_field`, `field_for_register`.

Disallowed long-term shape:

- One hand-written function that decodes only a specific instruction form.
- Another hand-written function that encodes only that same form.
- Text parsing rules that understand an alias differently from the form used by
  byte encoding.

Temporary adapters may exist during migration, but each adapter must be removed
before a form is considered fully migrated.

## Alias Handling

Aliases are form-level behavior, not separate decoder or encoder hacks.

For AArch64, examples include:

- `cmp xN, #imm` represented by the `subs` immediate encoding with `rd == 31`.
- `cmn xN, #imm` represented by the `adds` immediate encoding with `rd == 31`.
- `mov xD, #imm` represented by move-wide encodings when the immediate is
  encodable.

For x86-64, examples include:

- Canonical `nop` text for multi-byte NOP encodings.
- Choosing rel8 or rel32 encodings for branches when both are valid.

The form defines the canonical public instruction. The encoding fields define
how that public instruction maps to bytes. If multiple encodings can represent
the same text, encode chooses the canonical shortest or most explicit encoding
according to a documented per-form policy.

## Public API

Initial public API:

```rust
pub struct Decoder { ... }
pub struct Encoder { ... }
pub struct TextParser { ... }

impl Decoder {
    pub fn new(architecture: Architecture, options: DecodeOptions) -> Result<Self>;
    pub fn decode_one(&self, bytes: &[u8], address: u64) -> Result<Instruction>;
}

impl Encoder {
    pub fn new(architecture: Architecture, options: EncodeOptions) -> Result<Self>;
    pub fn encode_one(&self, instruction: &Instruction) -> Result<Vec<u8>>;
}

impl TextParser {
    pub fn new(architecture: Architecture, options: TextOptions) -> Result<Self>;
    pub fn parse_one(&self, text: &str, address: u64) -> Result<Instruction>;
}

pub fn format_instruction(instruction: &Instruction) -> String;
```

`Instruction::text` should not be the only source of truth. Either remove the
stored `text` field or treat it as cached canonical text derived from
`format_instruction`. Tests should assert structured fields first and text
second.

## Error Policy

Decode errors:

- Truncated instruction remains a hard error.
- Unknown fixed-width AArch64 instruction decodes as one `.word` instruction
  with `DecodeStatus::Unknown`.
- Unknown x86-64 byte decodes as one `.byte` instruction with
  `DecodeStatus::Unknown`.
- Recognized prefixes followed by an unsupported or unknown x86-64 opcode must
  follow a documented consume policy. The first migration should preserve
  current behavior unless tests prove it is wrong.

Encode errors:

- Unsupported form.
- Operand count mismatch.
- Operand kind or width mismatch.
- Immediate out of range.
- Relative target out of range.
- Ambiguous text or instruction when no canonical encoding is selected.

Text parse errors:

- Unknown mnemonic.
- Invalid operand syntax.
- Operand pattern mismatch.
- Ambiguous alias.
- Address-dependent target cannot be resolved.

## Testing Strategy

The decoder tests must be rebuilt around contracts rather than hand-picked text
assertions.

### Model Tests

Validate `Instruction`, operands, registers, memory operands, and canonical text
invariants. These tests do not decode or encode bytes.

### Form Tests

Each migrated form has table-driven fixtures that include:

- Architecture.
- Address.
- Input bytes.
- Expected structured instruction.
- Expected canonical text.
- Expected encode bytes.
- Expected flow and kind.
- Expected status.

The minimum roundtrip requirements are:

```text
bytes -> decode -> instruction -> encode -> bytes
text -> parse -> instruction -> encode -> bytes -> decode -> instruction
instruction -> format -> parse -> instruction
```

Byte equality is required only for canonical encodings. Non-canonical accepted
encodings may decode to the same instruction and re-encode to canonical bytes.

### Oracle Fixtures

Use external tooling as an oracle source, not as the internal model contract.

For x86-64 and AArch64:

- `llvm-mc` or a system assembler can generate bytes from small assembly
  fixtures.
- `llvm-objdump` can provide reference disassembly text.
- The fixture records tool version and command.

Oracle text is used to catch obvious divergence. Internal tests still assert the
structured `urcodec::Instruction` model, because external tools have different
alias and formatting policies.

### Corpus Integration

`ura-corpus-gate` should continue to report unknown rates. After `urcodec` lands,
it should also be able to report top unknown patterns by architecture and sample.
This is separate from the first crate migration and should not block it.

## Migration Plan

1. Create `crates/urcodec` with the current `urdisassembly` public model copied
   into `model.rs`.
2. Move current decoder implementation into `urcodec` with compatibility public
   API.
3. Change workspace dependencies from `urdisassembly` to `urcodec`.
4. Update `urdis2il` to depend on `urcodec`.
5. Update `ura-core` conversion code to consume `urcodec::Instruction`.
6. Replace `urdisassembly` references in tests and docs.
7. Remove `crates/urdisassembly` from the workspace after all consumers move.
8. Introduce declarative form infrastructure for a small seed set.
9. Migrate the seed forms from hand-written decode to form-driven decode.
10. Add form-driven encode for the same seed forms.
11. Add text parse/render roundtrip tests for the seed forms.
12. Expand form coverage only after the seed proves the model.

Seed forms should be deliberately small:

- AArch64: `ret`, `b`, `bl`, `nop`, `add/sub immediate`, `cmp immediate`.
- x86-64: `ret`, `call rel32`, `jmp rel8/rel32`, `jcc rel8/rel32`,
  `mov r64, imm64`.

## Compatibility

This is an internal workspace refactor. Public API names can change because the
workspace is still at `0.1.0`, but the migration should keep behavior stable for
existing CLI, daemon, and core tests.

README and coverage docs must be updated from `urdisassembly` terminology to
`urcodec` terminology once the code migration starts.

## Acceptance Criteria

- Workspace builds with `urcodec` replacing `urdisassembly`.
- `urdis2il` depends on `urcodec`.
- `ura-core` uses `urcodec::Decoder`.
- No separate `urinstruction` or `urassembly` crate exists.
- Seed instruction forms have one declarative definition each.
- Seed forms support decode, encode, canonical text rendering, text parsing, and
  roundtrip tests from the same form definition.
- Existing behavior tests still pass after migration.
- New decoder tests assert structured instruction fields before text.
- `cargo fmt --check`, `cargo test --workspace`, and
  `cargo clippy --workspace --all-targets -- -D warnings` pass.
