# Urdisassembly Crate Design

Date: 2026-06-17

## Purpose

`urdisassembly` is a standalone Rust disassembly crate for Ura. It replaces the current `capstone` dependency with a project-owned decoder that can grow into a publishable crate.

The first implementation targets ELF64 AArch64 little-endian binaries because that is the only architecture currently accepted by `ura-core`. The crate should still expose an API that can later support other architectures without changing Ura's analysis model.

The first version should produce readable AArch64 output for common instructions, not only identify control flow. Unknown instructions must degrade safely to `.word 0x????????` and must never stop project analysis.

## Core Decisions

- Add `crates/urdisassembly` as an independent workspace crate.
- Remove `capstone` and `capstone-sys` from the workspace dependency graph.
- Design `urdisassembly` as a future public crate, with stable data types and tests owned by the crate itself.
- Implement AArch64 decoding with mask/match pattern tables grouped by encoding class.
- Keep decode, formatting, and flow semantics separate.
- Store decode status and decoder metadata in the Ura project schema.
- Migrate the Ura schema from version 1 to version 2.

## Non-Goals

The first version does not include:

- Complete ARM ARM coverage.
- x86, ARM32, RISC-V, MIPS, or other architectures.
- A decompiler.
- A graphical disassembly UI.
- Runtime dependence on external tools such as `llvm-objdump`.
- Perfect formatting parity with Capstone, LLVM, IDA, or Ghidra.

## Public API

The intended primary use is:

```rust
let decoder = urdisassembly::Decoder::new(
    urdisassembly::Architecture::Aarch64,
    urdisassembly::DecodeOptions::default(),
)?;
let insn = decoder.decode_one(bytes, address)?;
```

The public model should include:

```rust
pub enum Architecture {
    Aarch64,
}

pub struct DecodeOptions {
    pub endian: Endian,
}

pub enum Endian {
    Little,
}

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

pub enum Operand {
    Register(Register),
    Immediate(i64),
    AbsoluteAddress(u64),
    Memory(MemoryOperand),
    Condition(ConditionCode),
}

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

pub enum FlowKind {
    Fallthrough,
    Branch,
    ConditionalBranch,
    Call,
    Return,
    IndirectBranch,
    IndirectCall,
}

pub enum DecodeStatus {
    Complete,
    Partial,
    Unknown,
}
```

`Instruction::operand_text()` can be implemented as a helper, but formatted text should be derived from structured operands instead of manually assembled in `ura-core`.

## Crate Structure

Use this layout:

- `crates/urdisassembly/Cargo.toml`: crate manifest.
- `crates/urdisassembly/src/lib.rs`: public exports.
- `crates/urdisassembly/src/error.rs`: decode errors.
- `crates/urdisassembly/src/model.rs`: public instruction model.
- `crates/urdisassembly/src/bits.rs`: bit extraction, sign extension, and immediate helpers.
- `crates/urdisassembly/src/decoder.rs`: architecture-neutral decoder entrypoint.
- `crates/urdisassembly/src/arch/mod.rs`: architecture module root.
- `crates/urdisassembly/src/arch/aarch64/mod.rs`: AArch64 module root.
- `crates/urdisassembly/src/arch/aarch64/decode.rs`: mask/match dispatch and decoders.
- `crates/urdisassembly/src/arch/aarch64/format.rs`: AArch64 formatting and aliases.
- `crates/urdisassembly/src/arch/aarch64/registers.rs`: register naming.
- `crates/urdisassembly/src/arch/aarch64/semantics.rs`: flow and target helpers.
- `crates/urdisassembly/tests/aarch64_decode.rs`: golden decode tests.
- `crates/urdisassembly/tests/aarch64_unknown.rs`: unknown fallback tests.
- `docs/urdisassembly/aarch64-coverage.md`: human-readable coverage matrix.

## AArch64 Decode Strategy

The AArch64 implementation should use a table of mask/match patterns:

```rust
struct Pattern {
    name: &'static str,
    group: &'static str,
    mask: u32,
    value: u32,
    decode: fn(u32, u64) -> DecodedInstruction,
}
```

The dispatcher tests patterns in order. More specific aliases and encodings must appear before broader groups. For example, `nop` should be recognized before generic `hint`, and `ret` before the broader unconditional branch register group.

Decoders should return an internal decoded form. The formatter turns that form into `mnemonic`, `operands`, and `text`. The semantics layer derives `InstructionKind`, `FlowKind`, `branch_target`, and fallthrough behavior from the decoded form.

## Initial AArch64 Coverage

The first implementation should cover these groups:

- Unconditional branch immediate: `b`, `bl`.
- Unconditional branch register: `br`, `blr`, `ret`.
- Conditional branch immediate: `b.cond`.
- Compare and branch: `cbz`, `cbnz`.
- Test and branch: `tbz`, `tbnz`.
- PC-relative addressing: `adr`, `adrp`.
- Load/store unsigned immediate: common `ldr` and `str` forms.
- Load/store pre-index and post-index: common `ldr` and `str` forms.
- Add/sub immediate: `add`, `adds`, `sub`, `subs`.
- Add/sub register: common shifted-register forms.
- Compare aliases: `cmp`, `cmn`.
- Move aliases: common `mov` register and immediate forms where encoding is already covered.
- Move wide: `movz`, `movn`, `movk`.
- Logical immediate: common `and`, `orr`, `eor`, `ands` forms.
- System hints: `nop`.

SIMD/FP and many system encodings may remain `Not implemented` in the first version, but they must be listed in the coverage matrix.

## Unknown Instruction Behavior

An unsupported 32-bit word must decode into a valid instruction:

- `mnemonic = ".word"`
- `operands = "0x????????"`
- `text = ".word 0x????????"`
- `kind = InstructionKind::Unknown`
- `flow = FlowKind::Fallthrough`
- `branch_target = None`
- `status = DecodeStatus::Unknown`

The decoder must not panic or return a hard error for an unsupported but well-sized AArch64 word. Hard errors are reserved for invalid input shape, such as fewer than four bytes for `decode_one`.

## Coverage Matrix

Maintain `docs/urdisassembly/aarch64-coverage.md` as the source of truth for implemented coverage. It should be grouped by AArch64 encoding class, not by ad hoc mnemonic lists.

Each row should track:

- Encoding group.
- Representative mnemonics.
- Decode status: `Implemented`, `Partial`, or `Not implemented`.
- Format status: `Implemented`, `Partial`, or `Not implemented`.
- Flow semantics status.
- Golden test coverage.
- Corpus evidence, if available.
- Notes about missing variants.

This file lets maintainers answer three questions directly:

- What is covered now?
- What is known missing?
- Which missing groups are the next best candidates to implement?

## Corpus Coverage Tool

Add a development-only coverage tool as a Cargo example under `urdisassembly`:

```bash
cargo run -p urdisassembly --example coverage -- path/to/binary-or-directory
```

The tool should:

- Parse ELF64 AArch64 files.
- Disassemble executable ranges with `urdisassembly`.
- Count decoded and unknown instructions.
- Report `unknown_rate`.
- Cluster unknown instructions by coarse encoding bits.
- Print example addresses and words for the highest-frequency unknown clusters.

The output should look like:

```text
decoded: 182391
unknown: 14322
unknown_rate: 7.85%

top_unknown_patterns:
  key=0x1e200000 count=3812 examples=0x401040:0x1e204000,0x401044:0x1e204021
  key=0x4e000000 count=2901 examples=0x402000:0x4e000400
```

The exact clustering key can evolve, but it must be stable enough to guide implementation work. The process is:

1. Run the tool on real AArch64 binaries.
2. Pick the highest-frequency unknown cluster.
3. Map it to an AArch64 encoding group.
4. Add a mask/match pattern and decoder.
5. Add golden tests.
6. Update `docs/urdisassembly/aarch64-coverage.md`.
7. Re-run the tool and confirm unknown rate decreases.

`llvm-objdump` may be used manually as an external oracle during development, but it must not become a runtime dependency.

## Ura Core Integration

`ura-core` should depend on `urdisassembly` instead of `capstone`.

`crates/ura-core/src/analysis/disasm.rs` remains responsible for:

- Iterating executable ranges from `LoadedElf`.
- Reading four-byte AArch64 instructions.
- Calling `urdisassembly::Decoder::decode_one`.
- Mapping `urdisassembly::Instruction` into `ura_core::model::Instruction`.

`ura-core` should stop parsing branch targets from formatted operand strings. It should use structured `branch_target` and `flow` values from `urdisassembly`.

Function discovery and xrefs must use `FlowKind` for branch, call, return, and conditional branch classification. The display mnemonic can still be stored for CLI output, but it must not be the source of control-flow truth.

## Schema Migration

The project schema should move from version 1 to version 2.

The `instructions` table should include:

- `addr INTEGER PRIMARY KEY`
- `size INTEGER NOT NULL`
- `bytes BLOB NOT NULL`
- `mnemonic TEXT NOT NULL`
- `operands TEXT NOT NULL`
- `text TEXT NOT NULL`
- `kind TEXT NOT NULL`
- `flow TEXT NOT NULL`
- `fallthrough INTEGER`
- `branch_target INTEGER`
- `decode_status TEXT NOT NULL`
- `decoder TEXT NOT NULL`
- `decoder_version TEXT NOT NULL`
- `function_addr INTEGER`

`decoder` should identify the backend, for example `urdisassembly/aarch64`. `decoder_version` should use the crate version.

Instruction rows are computed truth. During migration from schema 1 to schema 2, instruction data may be dropped and rebuilt by reanalysis. User truth must be preserved:

- comments
- renames
- manually created functions
- manual function ranges

`new_project` should create schema 2 directly. Opening or reanalyzing an older project should migrate it before writing new analysis results.

## Model Changes In `ura-core`

Extend `ura_core::model::Instruction` with:

- `text: String`
- `kind: String`
- `flow: String`
- `decode_status: String`
- `decoder: String`
- `decoder_version: String`

`ura-core` should store string values in SQLite while keeping typed enums in `urdisassembly`. This keeps the database simple and allows future decoder values without schema churn.

## Testing Strategy

`urdisassembly` tests should include:

- Golden decode cases for each implemented pattern.
- Branch target calculation for positive and negative PC-relative immediates.
- Register formatting for `x`, `w`, `sp`, `xzr`, `wzr`, and `lr`.
- Alias formatting for `ret`, `nop`, `cmp`, and common `mov` forms.
- Unknown fallback tests.
- Coverage matrix consistency tests where practical.

`ura-core` tests should include:

- Existing AArch64 `ret` fixture still disassembles correctly.
- Direct branch and call instructions produce xrefs.
- Conditional branch produces fallthrough and branch target.
- Unknown instruction is inserted and does not abort analysis.
- Old schema project migrates to schema 2 and preserves user edits.

Workspace verification should include:

```bash
cargo test --workspace
cargo tree -p ura-core
```

`cargo tree -p ura-core` must not show `capstone` or `capstone-sys`.

## Acceptance Criteria

The work is complete when:

1. `crates/urdisassembly` exists as a standalone crate with public API documentation in code.
2. `ura-core` no longer depends on `capstone`.
3. `Cargo.lock` no longer contains `capstone` or `capstone-sys`.
4. Existing Ura CLI, daemon, and core smoke tests pass.
5. New disassembly tests cover the initial AArch64 groups listed in this spec.
6. Unknown instructions degrade to `.word` rows and do not abort analysis.
7. Project schema version 2 stores decode status, flow, kind, decoder, and decoder version.
8. Schema migration preserves user truth while rebuilding computed instruction data.
9. `docs/urdisassembly/aarch64-coverage.md` lists implemented, partial, and missing groups.
10. The coverage example reports unknown rate and top unknown clusters for real AArch64 ELF inputs.

## Risks

- AArch64 formatting has many aliases. The first version should prefer stable readable output over trying to match one external tool exactly.
- Immediate decoding bugs can silently affect xrefs. Branch and PC-relative helpers need focused tests.
- The first coverage tool can overfit to one binary corpus. The coverage matrix should distinguish corpus evidence from architectural completeness.
- Schema migration increases scope. The migration should treat instruction rows as rebuildable and keep user truth preservation as the hard invariant.
