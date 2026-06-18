# Ura Core Kernelization Design

Date: 2026-06-18

## Context

`uranalysis` already has a working binary-analysis chain: image loading,
instruction decoding, IL lifting, CFG construction, function discovery, xrefs,
project persistence, CLI commands, and a simple daemon protocol. The current
system is no longer an empty MVP, but its core boundary is still MVP-shaped:
`ura-core` owns both analysis behavior and project storage, and `reanalyze`
does not represent a real analysis lifecycle.

The next stage is to turn `ura-core` into a pure analysis kernel that can scale
to broader decoder coverage, richer IL, more passes, and reliable reanalysis
without continuing to accumulate storage and command-layer debt inside the core.

## Goals

- Make `ura-core` a pure analysis kernel with no file-format or disk-IO
  responsibilities.
- Introduce a real analysis lifecycle centered on sessions, passes, scheduling,
  and invalidation.
- Split project storage into a dedicated `urastore` crate.
- Treat user edits as first-class analysis inputs rather than display-only
  patches.
- Store derived analysis as cache with explicit validity rules rather than as
  undifferentiated project truth.
- Keep the first kernelized design compatible with the current analysis chain
  so migration can be incremental.

## Non-Goals

- No GUI or frontend work.
- No broad new decoder-family expansion in this phase.
- No SSA, decompiler, or advanced type-recovery implementation in this phase.
- No speculative multithreaded scheduler in this phase.
- No big-bang rewrite that replaces all current code at once.

## Core Decisions

- `ura-core` becomes a pure analysis kernel.
- Project storage moves into a new `urastore` crate.
- `urastore` persists both project truth and analysis cache, but only truth is
  authoritative.
- `rename`, `comment`, `make-func`, and `set-func-range` are first-class user
  facts that can affect analysis results.
- Analysis execution moves to a declarative pass graph with explicit dependency
  and invalidation rules.
- The first implementation reuses the existing analysis pipeline logic behind
  the new scheduling model instead of redesigning all passes at once.

## System Boundaries

### `urloader`

`urloader` remains responsible for parsing input binaries into a normalized
loaded-image representation and target metadata. It does not own project files,
analysis scheduling, or user edits.

### `ura-core`

`ura-core` becomes the pure analysis kernel. It owns:

- analysis domain types
- session lifecycle
- user fact interpretation
- pass definitions
- pass scheduling
- invalidation
- derived analysis queries

`ura-core` must not own:

- project file format
- schema migration
- disk persistence
- temporary files
- CLI command semantics
- daemon protocol semantics

### `urastore`

`urastore` becomes the project persistence layer. It owns:

- project truth persistence
- analysis-cache persistence
- schema versioning
- engine/cache compatibility metadata
- cache loading and saving
- upgrade logic

`urastore` must not own:

- analysis algorithms
- pass ordering rules
- invalidation policy
- semantic interpretation of user edits beyond storing them

### `ura-cli` and `ura-daemon`

The CLI and daemon become orchestration layers over `urastore` and `ura-core`.
They open projects, construct sessions, submit user edits, request analysis,
and present results. They must not directly manipulate on-disk project internals
or reimplement scheduler logic.

## Truth Model

The new architecture separates persistent project data into truth and cache.

### Project Truth

Project truth is authoritative and must survive cache loss.

It includes:

- source bytes
- source hash
- target metadata
- project identity metadata
- user renames
- user comments
- manual function roots
- manual function ranges

### Analysis Cache

Analysis cache is derived, rebuildable, and never more authoritative than
project truth.

It includes:

- instructions
- strings
- basic blocks
- CFG edges
- discovered functions
- xrefs
- diagnostics
- future derived products such as IL, call graphs, and dataflow summaries

If cache is missing, stale, corrupted, or version-incompatible, the project
must still open successfully and `ura-core` must be able to rebuild the needed
products from truth.

## `ura-core` Analysis Model

The center of the kernel becomes `AnalysisSession`.

### `AnalysisInputs`

`AnalysisInputs` represents immutable analysis inputs:

- source bytes
- target metadata
- user facts

### `UserFacts`

`UserFacts` is an explicit analysis input set. It includes:

- renames
- comments
- manual function roots
- manual function ranges

The kernel treats these as semantic constraints, not as display-only overlays.
For example, a manual function range can force CFG/function rebuild behavior and
must participate in invalidation.

### `AnalysisState`

`AnalysisState` holds currently available derived products and pass metadata:

- instructions
- strings
- basic blocks
- CFG edges
- functions
- xrefs
- diagnostics
- pass-run metadata

The state is in-memory kernel state, not a persistence contract.

### `AnalysisSession`

`AnalysisSession` owns one working analysis context:

- current `AnalysisInputs`
- current `AnalysisState`
- pass registry
- dependency graph
- invalidation state

It provides APIs to:

- inspect derived products
- apply user-fact updates
- mark invalidation
- request refresh/reanalysis
- query pass status

## Declarative Pass Graph

Analysis execution moves to declarative passes rather than a command-driven
fixed pipeline.

Each pass declares:

- required inputs and prerequisite products
- produced outputs
- invalidation triggers
- execution entrypoint

The initial kernelized graph keeps the current analysis stages but wraps them in
declarative pass definitions.

### Initial Pass Set

- `decode_pass`
  - inputs: source bytes, target metadata
  - outputs: instructions

- `string_pass`
  - inputs: source bytes, target metadata
  - outputs: strings

- `cfg_pass`
  - inputs: instructions, manual function roots, manual function ranges
  - outputs: basic blocks, CFG edges

- `function_pass`
  - inputs: instructions, CFG, manual function roots, manual function ranges,
    renames
  - outputs: functions

- `xref_pass`
  - inputs: instructions, strings, CFG
  - outputs: xrefs

- `diagnostics_pass`
  - inputs: instructions, CFG, functions, user facts
  - outputs: diagnostics

This graph intentionally matches the current system closely so the first
migration preserves working behavior while changing the execution model.

## Scheduler And Invalidation

### `PassScheduler`

`PassScheduler` decides which passes must run for a given session refresh. It
uses:

- pass dependencies
- input changes
- cache validity
- previous pass status

The scheduler produces a concrete execution plan for the current session rather
than exposing scheduling decisions to CLI or daemon layers.

### `InvalidationSet`

`InvalidationSet` records which facts changed and which products are dirty.

The first version should use explicit, conservative rules:

- source-bytes change: invalidate all passes
- target-metadata change: invalidate all passes
- manual function root/range change: invalidate CFG, functions, xrefs, and
  diagnostics
- rename/comment change: invalidate only passes that depend on those facts,
  especially functions naming surfaces and diagnostics

The first kernelized implementation should prefer correctness and clarity over
fine-grained refresh windows. More precise range-bounded invalidation can be
added later on top of the same scheduler contract.

## Reanalysis Semantics

`reanalyze` must stop meaning "open then save" and start meaning "refresh the
session according to truth, cache validity, and invalidation rules."

The new reanalysis lifecycle is:

1. Load truth and any available cache from `urastore`.
2. Construct `AnalysisSession`.
3. Validate cached products against source hash, truth revision, engine version,
   pass-graph version, and per-pass fingerprints.
4. Mark dirty products.
5. Run the scheduler.
6. Update `AnalysisState`.
7. Return refreshed results to the caller.
8. Let the caller persist updated cache through `urastore`.

## `urastore` Data Model

`urastore` replaces the current monolithic project snapshot with explicit truth
and cache layers.

### `ProjectSource`

`ProjectSource` stores foundational binary truth:

- source bytes
- source hash
- target metadata
- project metadata

### `UserTruth`

`UserTruth` stores persistent human assertions:

- renames
- comments
- manual function roots
- manual function ranges

This layer is designed to grow later to include manual types, symbols, regions,
or other user-defined constraints without changing `ura-core`'s storage role.

### `AnalysisCache`

`AnalysisCache` stores rebuildable products:

- instructions
- strings
- basic blocks
- CFG edges
- functions
- xrefs
- diagnostics

Future caches can add IL, call graph, or dataflow summaries without changing
the truth contract.

## Cache Metadata

`urastore` must store explicit compatibility and validity metadata for cache.

Required metadata:

- project schema version
- engine version
- pass-graph version
- source hash at cache time
- user-truth revision
- per-pass fingerprints

Per-pass fingerprints are preferred over a single global cache flag because the
design explicitly commits to a declarative pass graph. New passes should be able
to enter the project model without forcing unrelated cached products to be
reinterpreted as truth.

## `urastore` API Shape

`urastore` should expose storage-oriented APIs, not mutable access to a giant
project struct.

The API should support:

- load project source
- load user truth
- load specific cached products or cache metadata
- persist updated user truth
- persist updated cached products
- upgrade schema or cache layout

`ura-core` should never need to know how a project is encoded on disk. Whether
the backing store is a single container file, a directory layout, SQLite, or
chunked binary blobs must remain an internal `urastore` concern.

## Migration Plan

Migration should be staged and continuously testable.

### Phase 1: Introduce The Kernel Execution Model

Add `AnalysisInputs`, `UserFacts`, `AnalysisState`, `AnalysisSession`, pass
definitions, scheduler, and invalidation types inside `ura-core`.

In this phase, the internal pass implementations may still call the current
analysis routines.

### Phase 2: Split Truth And Cache Semantics

Refactor the current project model so source truth, user truth, and derived
analysis are distinct in code even if they are still stored in the current
container temporarily.

This phase removes the assumption that one persisted struct is the analysis
contract.

### Phase 3: Introduce `urastore`

Move storage, schema management, cache metadata, and upgrade logic into the new
crate. `ura-core` stops importing persistence-layer types.

The first kernelization landing does not need to support automatic upgrade from
pre-`urastore` project snapshots. Legacy projects may fail with a clear
compatibility error. Upgrade machinery is required for `urastore`-native schema
evolution after the new boundary is in place.

### Phase 4: Rewire External Entry Points

Update `ura-cli` and `ura-daemon` to:

- open truth and cache through `urastore`
- construct `AnalysisSession`
- submit user-fact mutations
- request scheduler-driven refresh
- persist updated truth and cache

This phase also replaces the current fake `reanalyze` behavior with the real
session refresh flow.

## Testing Strategy

The migration needs dedicated coverage at three layers.

### `ura-core` Tests

- pass dependency planning
- invalidation behavior
- user-fact influence on analysis
- reanalysis lifecycle
- dirty-cache rebuild behavior

### `urastore` Tests

- truth roundtrip
- cache roundtrip
- stale-cache handling
- missing-cache handling
- schema upgrade behavior

### Integration Tests

- CLI opens existing projects and rebuilds stale cache
- daemon opens projects and returns refreshed products
- user edits trigger the expected invalidation scope
- pre-`urastore` project data fails with a clear compatibility error
- `urastore`-native stale cache rebuilds without losing truth

## Risks

- If pass interfaces are too tightly coupled to current concrete structs, the
  pass graph may become declarative in name only.
- If cache validity rules are underspecified, stale results will look like
  truth and recreate the current architectural problem.
- If `urastore` leaks storage details into `ura-core`, the split will not
  produce the intended kernel boundary.

## Recommendation

Choose the full kernelization route rather than a partial repair.

Do not keep storage in `ura-core`.
Do not keep reanalysis as an ad hoc command path.
Do not treat user edits as display-only overlays.

The recommended path is:

1. turn `ura-core` into a session-based analysis kernel
2. split storage into `urastore`
3. represent derived analysis as versioned cache
4. make scheduler-driven refresh the only reanalysis model

This is the smallest design that actually removes the current MVP boundary
instead of patching around it.
