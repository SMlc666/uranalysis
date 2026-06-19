# Urcodec Form Single Source Design

Date: 2026-06-19

## Context

`urcodec` already exposes a useful public surface for decoding, canonical text,
seed-form parsing, and a small amount of encoding. The crate also has real
consumer pressure from `urdis2il` and `ura-core`, plus oracle coverage against
Capstone.

The current internal shape is not acceptable as a long-term foundation:

- `InstructionForm` is still a function-pointer registry instead of a real form
  schema.
- `decode`, `encode`, `parse`, and text alias behavior are not all projections
  of one source of truth.
- Architecture form files still contain instruction-specific business logic,
  especially in the decoder path.
- x86-64 and AArch64 are only superficially aligned; they do not yet share a
  true form protocol.

This design replaces that model with a single-source form system. The target is
not "more metadata around the old decoder." The target is a hard architectural
switch where `FormSchema` becomes the only authority for instruction shape,
decode semantics, text semantics, and byte encoding.

## Goals

- Make form definitions the single source of truth for supported instructions.
- Drive decode from form schemas instead of per-form hand-written decode
  routines.
- Build encode as a direct projection of the same schema used by decode.
- Unify decode, encode, canonical text rendering, and text parsing under one
  runtime protocol.
- Support both AArch64 and x86-64 through one form architecture while allowing
  different low-level layout models.
- Produce a final tree with only one runtime path for supported forms and no
  legacy fallback path.

## Non-Goals

- Do not preserve backward compatibility with the current internal `urcodec`
  architecture.
- Do not maintain a migration period with old and new decode paths living
  side-by-side.
- Do not build an external DSL or code generator in this phase.
- Do not turn `urcodec` into a full external-assembler dialect compatibility
  layer.
- Do not redesign `urdis2il` or `ura-core` semantics beyond consuming more
  stable `Instruction` results.

## Hard Constraints

- No old/new decoder coexistence in the final design or migration plan.
- No legacy fallback dispatcher.
- No per-form `decode_*`, `encode_*`, or `parse_*` main logic once the rewrite
  lands.
- No alias behavior hidden in architecture-specific text helpers outside the
  schema system.
- The refactor may leave the branch temporarily uncompilable during execution,
  but the final landing state must restore `fmt`, `test`, and `clippy`.

This is a private-project rewrite. The design optimizes for architectural
clarity, not for incremental compatibility.

## Recommended Approach

Three approaches were considered:

1. Strengthen the current `InstructionForm` registry with more metadata while
   retaining per-form callbacks.
2. Replace the registry with an in-Rust declarative schema and a generic
   runtime.
3. Create an external DSL plus code generation.

Approach 2 is the intended design.

Approach 1 fails the core requirement because it preserves form-local business
logic in callbacks and keeps forms as an index table rather than the actual
instruction truth source.

Approach 3 may be attractive later, but it adds build complexity before the
core runtime contract is proven. The crate is not ready to pay that price yet.

The chosen approach is a hard cut to an embedded declarative schema model,
implemented directly in Rust.

## Target Architecture

The new `urcodec` architecture has three layers:

1. `FormSchema`
2. `FormRuntime`
3. `ArchAdapters`

### FormSchema

`FormSchema` is the only source of truth for a supported instruction form. A
schema defines:

- architecture
- stable form id
- canonical mnemonic
- instruction kind
- flow kind
- decode layout model
- match rules
- named field extraction rules
- semantic operand mapping
- alias and canonicalization rules
- text rendering rules
- text parsing rules
- encode validation and emission rules

Every supported instruction shape must be representable in this schema. If an
instruction cannot fit, the schema model is incomplete and must be extended.
The answer is not to bypass the schema with a private instruction-specific
routine.

### FormRuntime

`FormRuntime` executes schemas through a fixed pipeline:

1. read layout view from bytes
2. select candidate schemas
3. apply matchers
4. extract named fields
5. map fields into semantic operands
6. build canonical `Instruction`
7. choose alias for formatted text when needed
8. canonicalize parsed text before encode
9. validate encode constraints
10. emit bytes from the same field model

The runtime owns the generic flow. It does not own instruction-specific
knowledge beyond what the schema describes.

### ArchAdapters

Architecture adapters remain only for reusable low-level transformations that
should not be duplicated in schemas. Examples include:

- x86-64 ModRM and SIB read/write support
- x86-64 prefix interpretation
- x86-64 register-bank selection from width and extension bits
- AArch64 bitfield immediate expansion and contraction
- AArch64 register-bank selection and condition-code mapping

Adapters are helpers, not truth sources. They may transform one field or one
operand fragment, but they must not contain the primary logic for an entire
instruction form.

## Unified Schema Model

The current `InstructionForm` type should be replaced by a structured schema
model. Exact type names can change, but the design requires equivalents of the
following concepts.

### FormSchema

Each form schema includes at least:

- `id`
- `architecture`
- `mnemonic`
- `kind`
- `flow`
- `decode_layout`
- `matchers`
- `fields`
- `operands`
- `text_rules`
- `encode_rules`
- `aliases`

### Decode Layout

The schema model must support different low-level instruction layouts while
preserving a unified upper-level protocol.

Required layout classes:

- `FixedWidthBits { width: 32 }` for AArch64
- `ByteStreamLayout { ... }` for x86-64

`ByteStreamLayout` must be able to describe at least:

- prefix policy
- opcode map or opcode bytes
- ModRM presence and constraints
- SIB presence and constraints
- displacement shape
- immediate shape
- opcode-embedded register fields when applicable

The goal is not to reduce AArch64 and x86-64 into one unnatural binary format.
The goal is to give both architectures the same semantic form lifecycle while
allowing different raw layout backends.

### Matchers

Matchers define when a layout view belongs to a form.

Examples:

- AArch64 `(word & mask) == value`
- x86-64 opcode byte sequences, mandatory prefixes, ModRM constraints, REX
  constraints, or opcode-extension constraints

Matchers only determine form membership. They do not directly construct
operands.

### Fields

Fields extract named raw values from the matched layout.

Examples:

- AArch64: `imm26`, `imm19`, `rn`, `rd`, `sf`, `cond`
- x86-64: `opcode_reg`, `modrm_mod`, `modrm_reg`, `modrm_rm`, `sib_scale`,
  `sib_index`, `sib_base`, `disp8`, `disp32`, `imm8`, `imm32`

Fields are encoding-facing facts. They are not yet semantic operands.

### Operands

Operand specifications map fields into public `Instruction` operands.

Examples:

- register operands derived from named fields and a register-bank policy
- relative branch targets derived from signed immediates, scaling, and `pc`
  policy
- memory operands derived from base/index/scale/displacement field groups

This layer is the bridge between raw bytes and public instruction semantics. It
is also the bridge encode uses in reverse.

### Text Rules And Aliases

Canonical mnemonic policy, display aliases, and parse aliases must be modeled
in schema data.

This is especially important for:

- AArch64 aliases such as `cmp`, `cmn`, `mov`, `lsr`, `lsl`, `asr`
- x86-64 branch and control-flow textual normalization

Schema rules must answer:

- what the canonical public form is
- when text formatting chooses an alias
- when parsing an alias maps back to the canonical form
- how encode canonicalizes before emission

### Encode Rules

Encode rules define the reverse constraints needed to produce bytes from an
instruction:

- operand count and operand class constraints
- immediate range and alignment requirements
- scaling requirements for branch targets or shifted immediates
- register-width or register-bank requirements
- prefix or extension-bit requirements for x86-64
- canonical encoding choice when multiple encodings can represent the same
  public instruction

Encode is not a secondary add-on. It is one of the required projections of the
same schema.

## Runtime Boundaries

The runtime should be explicit about component boundaries. A concrete module
split can vary, but the design requires equivalents of these stages:

- `LayoutReader`
- `Matcher`
- `FieldExtractor`
- `OperandMapper`
- `AliasResolver`
- `EncoderRuntime`

### LayoutReader

Produces an architecture-specific layout view from bytes and address context.

### Matcher

Selects candidate schemas by architecture-specific buckets, then applies schema
matchers.

This stage replaces the current "walk every form until one callback returns
`Some`" model. Candidate preselection is required. The runtime should not
regress into a global linear scan of business-logic callbacks.

### FieldExtractor

Pulls named raw values from the matched layout using schema field specs.

### OperandMapper

Converts named field values into semantic public operands.

### AliasResolver

Handles canonicalization and alias selection for parse, text, and encode.

### EncoderRuntime

Takes a canonical instruction plus schema and emits bytes through the same
field model, using reverse mappings and encode constraints.

## What Must Be Removed

The rewrite must delete the old operating model, not wrap it.

Required removals:

- function-pointer-based `InstructionForm`
- architecture `FORMS` tables that only dispatch to per-form business-logic
  callbacks
- per-form `decode_*`, `encode_*`, and `parse_*` main implementations
- alias behavior scattered across architecture-specific parsing or formatting
  paths
- old decoder control flow that linearly probes form-local routines until one
  matches

The final tree must not contain a hybrid system where schemas exist but real
decode ownership still lives in legacy instruction-specific routines.

## What May Remain

Only low-level reusable primitives may remain outside schemas:

- ModRM and SIB extraction and emission
- prefix and extension-bit helpers
- register-bank mapping helpers
- signed or scaled immediate transform helpers
- AArch64 bitfield immediate transforms
- condition-code conversion helpers

These helpers must be small in scope. They may transform one field or one
operand fragment. They may not define the meaning of an entire instruction.

If a form appears to require a custom full-form routine, the default conclusion
must be that the schema model is missing an abstraction.

## Rollout Order

This rewrite is intentionally not a compatibility-preserving migration. The
branch may be unstable in the middle. The path is still staged conceptually so
the implementation has a clean order.

### Stage 1: Replace The Core Form Layer

- Rewrite `crates/urcodec/src/form.rs` around structured schemas.
- Introduce runtime modules that implement the fixed schema pipeline.
- Replace decoder, encoder, formatter, and parser entrypoints so they consume
  only the new runtime model.
- Remove function-pointer form APIs as part of this stage.

### Stage 2: Migrate AArch64 Onto The New Runtime

AArch64 goes first because it is fixed width and the fastest way to validate
the full pipeline.

Initial AArch64 families:

- control flow: `ret`, `br`, `blr`, `b`, `bl`, `b.cond`, `cbz`, `cbnz`, `tbz`,
  `tbnz`
- PC-relative address: `adr`, `adrp`
- simple arithmetic and compare immediates: `add`, `sub`, `cmp`, `cmn`
- simple move and logical alias families: `mov`, logical-immediate aliases,
  bitfield aliases such as `lsr`, `lsl`, `asr`

The target is to prove:

- fixed-width layout matching
- field extraction
- alias modeling
- canonical text rendering
- text parsing
- encode constraint validation
- byte emission from schema

### Stage 3: Migrate x86-64 Onto The Same Runtime

x86-64 then validates that the same protocol is strong enough for a variable-
width ISA.

Initial x86-64 families:

- `ret`
- `retf`
- `call rel32`
- `call r/m64`
- `jmp rel8`
- `jmp rel32`
- `jmp r/m64`
- `jcc rel8`
- `jcc rel32`
- `loop`
- `loopne`
- `loope`
- `jrcxz`
- `mov r64, imm64`

These forms force the schema to express:

- rel8 and rel32 targets
- opcode-extension selection through ModRM
- direct and indirect control flow
- opcode-embedded register operands
- basic REX-driven register expansion
- branch alias normalization

### Stage 4: Unify All Public Surfaces

After both architectures are migrated:

- `Decoder` must use only the schema runtime
- `Encoder` must use only the schema runtime
- `TextParser` must use only the schema runtime
- `format_instruction` must derive from schema-driven canonicalization and alias
  rules

At this point no architecture directory may retain instruction-local public
decode, parse, render, or encode ownership.

## Testing And Verification

This rewrite is allowed to destabilize the branch temporarily, but the final
landing must pass a strong validation gate.

### Schema Tests

Each supported form must have schema-level fixtures for decode behavior.

Encodable forms must also have encode fixtures.

Forms with aliases must have explicit canonical-to-alias and alias-to-canonical
tests.

### Roundtrip Tests

The final test suite must cover:

- `bytes -> instruction -> bytes`
- `instruction -> text -> instruction`
- `instruction -> encode -> decode -> instruction`

These tests must focus on:

- branch target math
- register width and bank selection
- immediate scaling and alignment
- alias canonicalization
- x86-64 prefix and extension-bit semantics

### Oracle And Consumer Regression

Existing oracle coverage must remain and be updated to validate the new runtime.
At minimum this includes the Capstone-backed tests for AArch64 and x86-64.

Workspace-level tests in `urdis2il` and `ura-core` must continue to serve as
consumer regression checks. `urcodec` is not allowed to become internally
self-consistent while degrading the analysis stack.

### Final Verification Gate

The final landing state must restore:

```sh
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Risks

The major risks are semantic, not procedural.

### Alias Drift

If canonicalization is under-specified, decode, parse, format, and encode can
silently diverge while still looking superficially correct.

Mitigation:

- alias rules must live in schema data
- alias roundtrip tests are mandatory
- encode always canonicalizes before emission

### Weak x86-64 Schema Power

If the x86-64 layout model is too weak, the implementation may be tempted to
smuggle form semantics back into custom helpers.

Mitigation:

- helpers are restricted to field-level or operand-fragment transforms
- any x86-64 form that does not fit the schema must trigger a schema expansion,
  not a custom full-form decode path

## Acceptance Criteria

The rewrite is complete only when all of the following are true:

- supported forms are defined through one schema system
- decode, encode, parse, and canonical text are projections of that schema
- AArch64 and x86-64 both execute through the same form protocol
- no legacy fallback decode path remains
- no form-local decode or encode main logic remains
- final workspace verification passes

This design intentionally favors a large forward step over incremental safety.
For this project, that is the correct trade.
