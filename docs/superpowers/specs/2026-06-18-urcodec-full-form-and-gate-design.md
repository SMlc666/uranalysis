# Urcodec Full Form Migration And Corpus Gate Design

Date: 2026-06-18

## Context

`uranalysis` already has a working `urcodec` crate, but the current
declarative-form layer is still only a seed. The main decoder paths remain
hand-written, while `Encoder` and `TextParser` only know a tiny subset of
instructions through `forms.rs`.

At the same time, `ura-corpus-gate` already reports sample-level unknown rates
and unknown clusters, but it still gates mostly at the sample level. That is
good enough for detecting broad regressions, but too weak for steering a large
form-migration effort instruction family by instruction family.

The next stage is to make form migration the primary path for the highest-value
instruction families and to tighten the corpus gate so it can fail on family
regressions, not only on global unknown-rate drift.

## Goals

- Make declarative forms a real decoding surface, not only an encode/text seed.
- Migrate the control-flow instruction families that directly affect CFG,
  function discovery, xrefs, and unknown-cluster reduction.
- Keep hand-written legacy decode as a compatibility fallback while migration is
  incomplete.
- Upgrade `ura-corpus-gate` so it can enforce per-family unknown budgets in
  addition to existing sample-level thresholds.
- Preserve current workspace behavior while making the migration observable
  through tests and reports.

## Non-Goals

- Do not finish every existing x86-64 or AArch64 instruction family in one
  change.
- Do not build a general assembler.
- Do not redesign `ura-core` analysis semantics in this phase.
- Do not remove legacy decode paths until the form path has reached full parity.

## Core Decisions

- Full form migration is a multi-phase program. The end state is broad form
  ownership of all currently supported instruction families, but delivery will
  happen in narrow, testable slices.
- Phase 1 focuses on control-flow families because they provide the highest
  product leverage:
  - AArch64: `nop`, `ret`, `br`, `blr`, `b`, `bl`, `b.cond`, `cbz/cbnz`,
    `tbz/tbnz`
  - x86-64: `ret`, `call rel32`, `jmp rel8/rel32`, `jcc rel8/rel32`
- Form decode is attempted first and falls back to the existing decoder when no
  form matches.
- `ura-corpus-gate` remains CI-only for real samples, but its manifest can grow
  per-sample unknown-family budgets.

## Form Model Evolution

The current `InstructionForm` shape only owns encode and parse callbacks. That
is not sufficient for a real migration. The next shape must also allow decode.

The first practical extension is:

- keep `FormId`, mnemonic, kind, and flow
- add a decode callback that can inspect raw bytes plus address
- let decode return:
  - `Some(instruction)` when the form matches
  - `None` when it does not match
  - `DecodeError` when the form clearly matches but bytes are truncated

This keeps the migration incremental:

- `Encoder` and `TextParser` continue to dispatch through forms
- `Decoder` tries forms first
- legacy hand-written decode remains available as fallback

## Decode Ownership Strategy

### AArch64

AArch64 is fixed width and already organized around a pattern table. It is the
easiest place to prove real form-driven decode.

Phase 1 AArch64 forms should own:

- exact fixed encodings: `nop`
- register branch encodings: `ret`, `br`, `blr`
- immediate branch encodings: `b`, `bl`
- conditional branch encodings: `b.cond`
- compare/test branch encodings: `cbz`, `cbnz`, `tbz`, `tbnz`

Their form code must also own canonical text parse and encode for the same
instructions.

### x86-64

x86-64 is variable width, so migration must be more conservative. The first
phase should only move relative control-flow forms that have clear byte layouts
and strong CFG impact.

Phase 1 x86-64 forms should own:

- `ret`
- `call rel32`
- `jmp rel8`
- `jmp rel32`
- `jcc rel8`
- `jcc rel32`

Legacy decode continues to own loop-family, indirect branches, and the rest of
the instruction space until later phases.

## Corpus Gate Upgrade

The corpus gate already emits:

- sample summaries
- unknown rates
- unknown clusters
- candidate-family heuristics

The next change is to make family-level regressions enforceable.

Each sample manifest entry may optionally declare per-family maximum counts, for
example:

- `x86_64_two_byte_opcode <= N`
- `x86_64_unknown_opcode_or_prefix <= N`
- `aarch64_encoding_group_0x2a <= N`

This keeps the gate aligned with the migration strategy:

- form migration reduces unknowns in specific families
- the manifest can ratchet down only those families that were improved
- unrelated families do not block progress

The report and markdown summary should include a per-sample family-count
section, so gate failures point directly to the drifting family.

## Phasing

### Phase 1

- extend `InstructionForm` with decode support
- route `Decoder` through forms before legacy fallback
- migrate AArch64 control-flow forms
- migrate x86-64 relative control-flow forms
- add roundtrip tests for representative instructions from those families
- add corpus-gate family budgets and summary output

### Phase 2

- migrate AArch64 address and arithmetic immediate seed families
- migrate x86-64 `loop`, `jrcxz`, `mov r64, imm64`, and other small CFG-adjacent
  families
- tighten manifest family budgets from CI evidence

### Phase 3

- migrate the remaining currently supported families in descending corpus
  frequency order
- remove dead legacy decode branches only after parity is demonstrated

## Acceptance Criteria

- `Decoder` can decode a real subset through forms before falling back to legacy
  decode.
- Phase 1 form families support decode, encode, parse, and canonical text
  roundtrip.
- Existing workspace tests stay green.
- New tests prove representative AArch64 and x86-64 control-flow forms
  roundtrip through decode, encode, and text parsing.
- `ura-corpus-gate` can fail on declared unknown-family budgets.
- The corpus summary surfaces family-level evidence suitable for ratcheting.
