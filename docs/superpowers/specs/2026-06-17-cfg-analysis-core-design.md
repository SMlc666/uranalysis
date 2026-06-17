# CFG Analysis Core Design

## Context

`uranalysis` currently has a working loader, linear disassembly, project
storage, CLI, daemon, and early IL support. The next step is to make the core
analysis trustworthy by adding basic blocks, CFG edges, function ownership, and
bounded refresh behavior.

This design chooses the CFG/function model route first. Decoder work is done
only when CFG construction proves a missing instruction is blocking a correct
graph.

## Goals

- Persist basic blocks and CFG edges in project files.
- Build functions from CFG reachability rather than a simple first-terminal
  range guess.
- Treat full analysis as an import-time operation, not as a repeated user
  command.
- Make later reanalysis event-driven and range-bounded.
- Fail CFG construction on missing graph-critical decode coverage instead of
  producing a misleading graph.
- Keep pass boundaries clean so future parallelism can be added after CFG,
  block, or function boundaries exist.

## Non-Goals

- No GUI work.
- No decompiler or high-level type recovery.
- No broad instruction-table completion.
- No full IL dataflow engine in this phase.
- No jump-table recovery in the first CFG version.
- No speculative multithreaded scheduler in this phase.

## Project Data Model

Project data is split into source truth and derived analysis.

Source truth:

- `source_bytes`
- `source_hash`
- comments
- renames
- manual functions
- manual function ranges

Derived analysis:

- instructions
- basic blocks
- CFG edges
- auto-discovered functions
- xrefs
- diagnostics

`ProjectFile` gains:

- `source_bytes: Vec<u8>`
- `basic_blocks: Vec<BasicBlock>`
- `cfg_edges: Vec<CfgEdge>`

`PROJECT_SCHEMA_VERSION` moves from `3` to `4`. This early project does not need
old-schema migration in this phase; old project files should fail with a clear
unsupported schema/container error.

### BasicBlock

`BasicBlock` becomes a first-class persisted record:

- `id: i64`
- `function_addr: Option<u64>`
- `start: u64`
- `end: u64`
- `terminal_addr: Option<u64>`
- `instruction_count: usize`
- `source: BasicBlockSource`

`BasicBlockSource`:

- `Entry`
- `BranchTarget`
- `Fallthrough`
- `User`

### CfgEdge

Add a CFG edge record:

- `from_block: i64`
- `to_block: Option<i64>`
- `from_addr: u64`
- `to_addr: Option<u64>`
- `kind: CfgEdgeKind`

`CfgEdgeKind`:

- `Fallthrough`
- `Branch`
- `ConditionalTrue`
- `ConditionalFalse`
- `Call`
- `Return`
- `Indirect`

`to_block` and `to_addr` are optional for terminal or unresolved indirect
edges.

### Function

The existing `Function` record keeps:

- `addr`
- `name`
- `start`
- `end`
- `source`

The function range is derived from reachable blocks. User functions override
auto functions at the same address. If a user function root or range no longer
maps cleanly to current instructions, the project keeps the user truth and emits
a diagnostic.

## Import Analysis Flow

Full import is used only when creating a project from source bytes or replacing
the source binary.

Pipeline:

1. Load image.
2. Linear disassemble executable ranges.
3. Discover basic block starts.
4. Build CFG edges.
5. Discover functions from CFG roots and reachability.
6. Extract strings.
7. Build xrefs.
8. Collect diagnostics.
9. Persist source truth plus derived analysis.

Linear disassembly remains serial in this phase. AArch64 could be range-split,
but x86-64 variable-width decoding requires trusted boundaries. CFG creation is
the work that will eventually provide safe boundaries for future parallel work.

## Block Discovery

Block starts include:

- image entry
- direct branch targets
- direct call targets
- conditional-branch fallthrough targets
- user function starts
- user range starts

Potential starts after unconditional branches, returns, and indirect branches
are not trusted by themselves. They become blocks only if referenced by a known
entry, target, fallthrough, or user range.

Each block ends at:

- a branch
- a conditional branch
- a call plus fallthrough
- a return
- an indirect control-flow instruction
- the instruction immediately before the next block start
- the end of the analyzed range

## CFG Strict Decode Policy

Raw disassembly may preserve unknown bytes or words so users can see where
coverage is missing.

CFG construction is stricter:

- `DecodeStatus::Unknown` in a CFG window is an error.
- Graph-critical `DecodeStatus::Partial` is an error when the missing semantics
  affect control flow, fallthrough, call target, return behavior, or block
  termination.
- The CFG pass must not treat unknown instructions as normal fallthrough.

CFG errors include:

- architecture
- address
- raw bytes
- analysis window
- decode status
- reason

The expected workflow is:

1. CFG fails at a concrete address.
2. Add a focused decoder test for that instruction.
3. Implement decode and flow semantics.
4. Re-run CFG tests.

This keeps decoder work tied to real graph blockers instead of broad table
completion.

## Function Discovery

Function roots:

- image entry
- direct call targets
- user function starts

Function bodies are built by walking reachable CFG blocks from a root.

Conservative rules:

- A direct call creates a call edge and a fallthrough edge, but the callee body
  is not merged into the caller.
- A direct branch inside the current reachable graph remains a normal edge.
- A branch to a known function root is treated conservatively as a possible tail
  call boundary.
- Indirect branches stop local reachability and emit diagnostics until jump-table
  support exists.

Function `end` is the maximum end address of owned reachable blocks.

## Event-Driven Refresh

Reanalysis is not a user-facing mental model and does not run just because a
project is opened. Refresh is caused by events that invalidate derived analysis.

Refresh plans:

- `None`
- `GraphWindow(AnalysisWindow)`
- `DecodeWindow(AnalysisWindow)`
- `FullImport`

`FullImport` occurs only for:

- new project import
- source binary replacement

`GraphWindow` occurs for:

- manual function added
- manual function range changed
- future operations that change block/function ownership without changing bytes

`DecodeWindow` is reserved for future byte patching or source-range edits. It
requires a trusted decode anchor, such as a function start, block start, symbol
start, or another proven synchronization point. It is not implemented in the
first phase unless a byte-patching feature is added.

`None` occurs for:

- rename
- comment
- info queries
- disassembly queries
- xref queries
- string queries

### AnalysisWindow

`AnalysisWindow` identifies the bounded area affected by an event:

- `start: u64`
- `end: u64`
- `reason: RefreshReason`

Graph refresh must operate inside the window and any directly affected adjacent
edges. It must not silently rerun full import as a fallback.

## User Truth Merge

Refresh rebuilds derived data and then reapplies user truth:

- renames override automatic function names
- comments are preserved by address
- user functions override automatic functions at the same root
- invalid or unmapped user roots are retained and diagnosed

The project must never drop user edits as a side effect of derived-analysis
refresh.

## Xrefs

Code xrefs should be derived from CFG/branch semantics rather than separate
instruction scanning once CFG exists.

String xrefs can keep the current operand-token approach in this phase. It is
not the blocker for the CFG core.

## Corpus And Quality Gates

The corpus gate should evolve away from only global unknown-rate thresholds.

Add structural metrics:

- basic block count
- CFG edge count
- function count
- CFG construction failures
- unknown terminal instruction count
- graph diagnostics count
- decoded direct branch/call count

A CFG failure on a corpus sample should be treated as a decoder or CFG work item
with address and byte evidence.

## Tests

Model and persistence tests:

- schema v4 persists `source_bytes`, `basic_blocks`, and `cfg_edges`
- old project schemas fail clearly
- user comments, renames, manual functions, and manual ranges survive refresh

CFG tests:

- AArch64 direct branch creates a branch edge
- AArch64 conditional branch creates true and false edges
- AArch64 call creates call and fallthrough edges
- AArch64 return terminates a block
- x86-64 direct branch creates a branch edge
- x86-64 conditional branch creates true and false edges
- x86-64 call creates call and fallthrough edges
- x86-64 return terminates a block
- unknown instruction in a CFG window fails with address and bytes

Refresh tests:

- `new_project` uses full import
- `make_function` plans a graph window
- `set_function_range` plans a graph window
- `rename` plans no refresh
- `comment` plans no refresh
- queries plan no refresh
- graph-window refresh does not rerun full import

Decoder tests:

- Any instruction added to unblock CFG must first have a focused golden decode
  test covering mnemonic, operands, flow kind, branch target or fallthrough
  behavior, and decode status.

## Implementation Order

1. Add schema v4 data structures and persistence tests.
2. Add refresh event and refresh-plan types without changing behavior.
3. Add block discovery and CFG builder with strict unknown failure.
4. Wire full import to produce instructions, blocks, CFG edges, functions,
   xrefs, strings, and diagnostics.
5. Replace function discovery with CFG reachability.
6. Add graph-window planning for manual function events.
7. Implement bounded graph-window refresh.
8. Add corpus structural metrics.
9. Add focused decoder coverage only for CFG failures encountered by tests or
   corpus evidence.
