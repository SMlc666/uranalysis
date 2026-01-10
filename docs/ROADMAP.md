# Roadmap

## Phase 0: Project skeleton
- xmake project layout
- Core engine library target
- CLI client target

## Phase 1: Minimal pipeline (ARM64 + ELF)
- ELF loader (basic segments and entry point)
- Capstone-based ARM64 decoding
- LLIR lift for a minimal instruction subset
- CFG construction
- Simple textual output for functions/basic blocks

## Phase 2: Analysis + readability
- SSA form and basic data-flow
- Calling convention modeling (ARM64 AAPCS)
- Basic variable recovery
- Early pseudocode emitter

## Phase 3: Decompiler quality improvements
- Structured control-flow recovery
- Type inference and propagation
- Expression simplification and cleanup passes
- Expanded instruction coverage

## Phase 4: Hard cases and stability
- Jump tables, tail calls, inlining patterns
- Opaque predicates and compiler quirks
- Regression suite and quality metrics
