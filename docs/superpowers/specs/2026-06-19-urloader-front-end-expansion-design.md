# Urloader Front-End Expansion Design

Date: 2026-06-19

## Context

`urloader` is no longer a disposable replacement for `goblin`. It already sits
on the product path for `ura-core`, `ura-cli`, and `ura-daemon`, and it already
defines the repository's format boundary for ELF and PE inputs.

That boundary is still too thin. Today `urloader` can identify targets, map
basic ranges, parse sections, and extract limited symbol data, but higher
layers still own too much format-sensitive normalization and too many policy
decisions about what counts as executable bytes, which metadata is trustworthy,
and what capability level a loaded image actually provides.

The next stage is not a cosmetic refactor. `urloader` should become the binary
front-end infrastructure layer for `uranalysis`: the place where raw container
formats are parsed, normalized into analysis-facing views, enriched with
high-value metadata such as imports, exports, relocations, DWARF, and unwind
information, and graded through explicit capability and diagnostic contracts.

This layer must remain strictly pre-analysis. It may own binary structure,
mapping, naming, linkage, debug, and unwind facts, but it must not own
instruction semantics, disassembly, IL, CFG, function discovery, xrefs, or any
other analysis interpretation over decoded instructions.

## Goals

- Turn `urloader` into the shared binary front-end layer for the workspace.
- Split raw format parsing from analysis-facing normalized views.
- Move format-sensitive executable-view construction out of `ura-core`.
- Expand loader infrastructure to cover imports, exports, relocations, debug
  metadata, and unwind metadata.
- Provide normalized, directly consumable views for DWARF, `eh_frame`, and PE
  unwind data instead of only exposing raw parser fragments.
- Introduce capability and diagnostic contracts so callers can tell whether an
  image is fully analyzable, partially analyzable, or only partially described.
- Reduce unnecessary byte copying and move the default product path toward
  borrowed or low-copy binary views.
- Strengthen validation through stable unit tests, local integration fixtures,
  and CI-only real-sample gates.
- Keep the real-sample corpus gate out of local default workflows.

## Non-Goals

- No instruction decoding inside `urloader`.
- No IL, CFG, basic-block, function, xref, or dataflow logic inside
  `urloader`.
- No decompiler-oriented semantic reconstruction in this phase.
- No requirement to expose complete raw DIE trees or complete raw exception
  frame bytecode as the primary public API.
- No local-default real-sample gate execution.
- No forced crate split such as introducing a separate `urimage` crate in this
  phase.

## Core Decisions

- `urloader` becomes a two-layer crate: raw parse layer plus analysis-facing
  front layer.
- Raw format facts remain available, but higher layers should consume the
  normalized front layer by default.
- The normalized front layer becomes the single source of truth for target
  identity, executable mappings, address translation, metadata capabilities,
  and loader diagnostics.
- `ura-core` stops reconstructing analysis input policy from raw loader output.
- Debug and unwind support are first-class front-end capabilities, not deferred
  parser experiments.
- Imports, exports, relocations, and symbol/name provenance become normalized
  infrastructure, not format-specific side channels.
- The default fast path should borrow source bytes instead of storing an owned
  `Vec<u8>` inside every front-end object.

## Layering

### Raw Parse Layer

The raw parse layer owns format identification and format-specific parsing for
ELF and PE.

It is responsible for:

- container header validation
- segment and section parsing
- format-native symbol parsing
- import and export table parsing
- relocation parsing
- discovery of debug and unwind sections/directories
- extraction of format details needed for diagnostics or advanced callers

Its primary output is a format-fact object such as `RawImage`. That object can
still expose format-native detail summaries, but it is not the main analysis
contract.

### Analysis-Facing Front Layer

The front layer consumes `RawImage` plus borrowed source bytes and produces a
normalized `BinaryView`.

It is responsible for:

- canonical target identity
- canonical executable mapping ranges
- VA, RVA, and file-offset translation
- section and segment normalization policy
- normalized symbols, names, imports, exports, and relocations
- normalized debug and unwind views
- capability declaration
- diagnostic grading

This layer answers the question, "what can the rest of the system reliably do
with this binary right now?"

## Public API Shape

The public API should separate raw parsing from front-end view construction.

Recommended shape:

```rust
pub fn load(bytes: &[u8]) -> Result<RawImage>;

impl RawImage {
    pub fn analysis_view<'a>(&'a self, bytes: &'a [u8]) -> Result<BinaryView<'a>>;
}
```

This is preferred over a single `load()` that immediately returns a combined
object because:

- it keeps the raw-versus-normalized boundary explicit
- it allows raw-only success with view-construction failure when capabilities
  are insufficient
- it gives future callers a place to request specialized view-building policy
  without polluting the raw parser contract

The crate may still provide a convenience helper such as:

```rust
pub fn load_view(bytes: &[u8]) -> Result<(RawImage, BinaryView<'_>)>;
```

but the primary conceptual contract should remain two-step.

## `BinaryView`

The main analysis-facing contract is `BinaryView`.

```rust
pub struct BinaryView<'a> {
    pub target: BinaryTarget,
    pub entry: Option<u64>,
    pub image_base: Option<u64>,
    pub bytes: &'a [u8],
    pub ranges: Vec<MappedRange>,
    pub sections: Vec<ViewSection>,
    pub symbols: Vec<NormalizedSymbol>,
    pub imports: Vec<NormalizedImport>,
    pub exports: Vec<NormalizedExport>,
    pub relocations: Vec<NormalizedRelocation>,
    pub debug: Option<DebugView>,
    pub unwind: Option<UnwindView>,
    pub capabilities: CapabilitySet,
    pub diagnostics: Vec<LoaderDiagnostic>,
}
```

### Target Identity

`BinaryTarget` owns:

- `format`
- `architecture`
- `class`
- `endian`

This becomes the backend-selection contract for `ura-core`. Higher layers must
not infer target identity indirectly from raw ELF or PE details.

### Mapping Model

`MappedRange` should represent the normalized memory/file relationship used by
analysis:

- virtual start and end
- file offset and file-backed size
- memory size
- permissions
- provenance such as originating segment or section

This replaces ad hoc reconstruction of executable ranges inside `ura-core`.

### Section Model

`ViewSection` keeps human-facing and tool-facing container information:

- normalized name
- virtual range
- file offset
- permissions
- provenance
- section kind or role when known

Sections remain useful for inspection and diagnostics, but they are not the
only truth for executable-policy decisions.

## Metadata Views

`urloader` should no longer expose metadata only as raw format fragments. It
should normalize high-value infrastructure into stable, directly consumable
views.

### Name View

Name-oriented metadata should normalize:

- static symbols
- dynamic symbols
- import names
- export names
- optional demangled candidates
- binding or visibility where available
- provenance of each name

Each normalized name-bearing object should record:

- its address or range when applicable
- its source
- its confidence or completeness

### Linkage View

Linkage-oriented metadata should normalize:

- imports
- exports
- relocations
- PLT entries
- GOT slots
- IAT slots
- relocation targets and relocation kinds

This front-end contract exists so later analysis passes can recover external
linkage and relocation-aware naming without reopening ELF or PE details.

### Debug View

`DebugView` should provide high-value debug results rather than only raw DIE
trees or raw section buffers.

At minimum it should expose:

- `line_entries`: address to file/line/column mappings
- `function_ranges`: address ranges from DWARF debug info
- `inline_ranges`: optional inline attribution ranges when available
- `compilation_units`: normalized CU index
- `source_files`: normalized source file table

This is intended to make source attribution and debug-derived range recovery
usable immediately by higher layers.

### Unwind View

`UnwindView` should normalize function-range and unwind-fact coverage from:

- ELF `eh_frame`
- PE `pdata` and `xdata`

It should expose:

- frame or unwind records
- address-range to unwind-record mapping
- optional personality or LSDA references
- augmentation or platform-specific flags where useful

This layer does not own exception semantics. It owns range-indexed unwind
facts.

## Normalized Record Style

High-value metadata records should carry source and completeness information,
not just naked payloads.

Example:

```rust
pub struct FunctionRange {
    pub start: u64,
    pub end: u64,
    pub name: Option<String>,
    pub source: FunctionRangeSource,
    pub confidence: MetadataConfidence,
}
```

The same principle should apply to imported symbols, exports, relocations,
debug line entries, and unwind-derived range facts.

This is required because real binaries routinely contain partial, conflicting,
or degraded metadata. Without explicit source and confidence markers, higher
layers will rebuild their own hidden trust model and the front-end boundary
will rot.

## Capability Contract

`BinaryView` must declare its actual front-end capability level through a
direct product-facing contract.

Recommended initial fields:

```rust
pub struct CapabilitySet {
    pub can_map_executable_bytes: bool,
    pub can_translate_va: bool,
    pub can_translate_rva: bool,
    pub has_named_sections: bool,
    pub has_symbols: bool,
    pub has_imports: bool,
    pub has_exports: bool,
    pub has_relocations: bool,
    pub has_debug_lines: bool,
    pub has_debug_function_ranges: bool,
    pub has_unwind_ranges: bool,
    pub supports_analysis_entry: bool,
}
```

These are intentionally concrete. `ura-core`, CLI surfaces, and corpus gates
should be able to make decisions directly from capability flags instead of
inspecting diagnostics text.

Capability truth rules:

- missing optional metadata should not become a fatal error by itself
- required analysis-input capabilities must be enforced before analysis starts
- partial availability should remain observable even when analysis can proceed

## Diagnostic Contract

`LoaderDiagnostic` should be graded at least as:

- `error`
- `warning`
- `info`

Rules:

- `error` means the view is not trustworthy enough for the requested front-end
  use and `analysis_view()` must fail if the missing capability is required
- `warning` means the view is usable but degraded
- `info` records compatibility facts or non-actionable observations

Diagnostics should be structured, not message-only. They should carry a code,
severity, subject, and optional address or section context.

## Ownership And Memory Model

The default product path should move toward borrowed or low-copy views.

Rules:

- `BinaryView` borrows `&[u8]` by default
- raw parse objects store offsets, ranges, and compact metadata rather than an
  owned whole-file copy
- strings and normalized names may allocate selectively
- an owned variant such as `OwnedBinaryView` can exist later for persistence or
  session-caching use cases

This reduces duplication and keeps front-end expansion compatible with larger
real-world binaries and corpus gates.

## `ura-core` Boundary Changes

`ura-core` should stop reconstructing analysis input policy from raw loader
state.

### New Consumption Model

`ura-core` should accept `urloader::BinaryView` as its analysis-front-end
contract.

`ura-core` remains responsible for:

- verifying the target is supported by the selected backend
- choosing decoder and backend implementations
- disassembly
- CFG
- function discovery
- xrefs
- derived analysis state

`ura-core` must stop owning:

- executable-range policy
- ELF versus PE mapping quirks
- address-translation reconstruction from raw segments
- metadata capability guessing
- loader diagnostic interpretation from raw format details

### Session And CLI Integration

`ura-cli`, `ura-daemon`, and `ura-core::analysis::session` should retain raw
source bytes at the orchestration boundary and build `BinaryView` once per
session load or source refresh.

They should not store format-specific reconstruction logic outside `urloader`.

## Supported Metadata Expansion

This phase explicitly includes meaningful infrastructure expansion, not only
model cleanup.

### ELF Expansion

`urloader` should expand ELF coverage for:

- static and dynamic symbols with richer binding and kind normalization
- imports/exports as representable linkage facts where derivable
- relocations
- `eh_frame`
- key DWARF sections needed for lines and function-range recovery

### PE Expansion

`urloader` should expand PE coverage for:

- imports
- exports
- base relocations
- unwind metadata from `pdata` and `xdata`
- normalized section and mapping policy consistent with the ELF front-end view

### DWARF And Unwind Depth

DWARF and unwind support in this design is intentionally "high-value usable,"
not just parser exposure.

The front-end should aim to provide:

- line info suitable for address-to-source lookups
- function ranges suitable for later naming or range alignment
- unwind ranges suitable for later function-boundary or recovery helpers

This remains pre-analysis infrastructure. It does not authorize instruction
semantic analysis inside `urloader`.

## Testing Strategy

Testing is split into three layers and those layers must remain distinct.

### 1. Stable Unit Tests

Location:

- `crates/urloader/tests/`
- focused module tests where appropriate

Characteristics:

- fully local
- deterministic
- hand-built fixtures
- no network
- no external release assets

Coverage includes:

- ELF and PE header parsing
- segments, sections, symbols, imports, exports, relocations
- debug and unwind happy paths
- debug and unwind error paths
- address translation
- executable-range normalization
- capability derivation
- diagnostic grading
- low-copy and borrowed-view invariants

### 2. Local Fixture Integration Tests

Characteristics:

- still local-default and deterministic
- can use generated miniature sample binaries
- validate cooperation between raw parse, front-end normalization, and
  `ura-core` target dispatch

Coverage includes:

- `RawImage -> BinaryView`
- `BinaryView -> ura-core` target dispatch
- metadata merging from multiple front-end sources
- conflict and degradation behavior

These tests are stronger than unit tests but do not depend on CI-only corpus
assets.

### 3. CI-Only Real-Sample Corpus Gate

Characteristics:

- runs only in GitHub Actions
- never runs from `cargo test`
- never becomes a local-default command

Purpose:

- catch compatibility regression against real-world binaries
- catch front-end capability regressions even when downstream analysis still
  produces output

Gate expectations should expand beyond decode metrics and include front-end
metrics such as:

- target detection correctness
- executable mapping success
- import and export availability
- relocation availability
- debug-line availability where expected
- unwind-range availability where expected
- fatal and warning diagnostic counts

## CI Contract

### Local-Equivalent CI

`ci.yml` remains the normal developer-quality gate:

- `cargo fmt --check`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`

This path should include unit tests and local fixture integration tests.

### Real-Sample Gate

`corpus-gate.yml` remains the only real-sample gate.

It should:

- install and restore required corpus toolchains
- build or fetch corpus binaries
- run the corpus gate binary
- emit a front-end summary alongside existing analysis summaries

That summary should report, per sample:

- detected target
- front-end capabilities
- missing or partial metadata classes
- fatal and warning diagnostic totals
- relevant regressions from prior capability expectations

## Local Gate Policy

The policy remains unchanged and explicit:

- the real-sample corpus gate is GitHub Actions only
- local developers run normal Rust quality checks and local fixture tests
- `tests/corpus/scripts/run-corpus-gate.sh` must continue to reject local
  execution unless `GITHUB_ACTIONS=true`
- the corpus gate must not be wired into `cargo test`, `cargo xtask`, or any
  other local-default command path

## Error Handling

The front-end must distinguish:

- parse failure
- normalized-view construction failure
- degraded-but-usable metadata

Recommended handling model:

- `load()` returns typed parse errors for malformed or unsupported containers
- `analysis_view()` returns typed front-end errors when required capabilities
  for view construction are unavailable
- optional metadata gaps become capability downgrades plus structured warnings

This keeps fatal format rejection separate from partial metadata degradation.

## Rollout

The safest rollout path is staged:

1. Introduce raw-versus-view layering and migrate `ura-core` to `BinaryView`.
2. Replace ad hoc executable mapping and target normalization in higher layers.
3. Add normalized linkage, name, debug, and unwind infrastructure.
4. Expand unit and integration coverage for each metadata class.
5. Extend the CI-only corpus gate with front-end capability assertions and
   reporting.

At every stage, the hard boundary remains:

- `urloader` owns pre-analysis binary infrastructure
- `ura-core` owns decoded-instruction analysis

## Success Criteria

This design is successful when:

- `ura-core` no longer reconstructs executable policy from raw loader output
- `urloader` can express real front-end capability differences explicitly
- imports, exports, relocations, debug, and unwind metadata are normalized into
  usable views
- the default product path avoids whole-file duplication where unnecessary
- local verification remains fast and deterministic
- the CI-only corpus gate catches real-sample front-end regressions without
  becoming a local workflow dependency
