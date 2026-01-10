# Architecture

## Layering (engine)
- Loader: ELF parsing, mapping, and symbol discovery (when present).
- Disasm/Decoder: ARM64 instruction decoding (Capstone initially).
- LLIR: instruction semantics (architecture-specific lift).
- MLIL: SSA + CFG, architecture-agnostic expressions for analysis and lifting.
- HLIR: structured, typed IR (not pseudocode) for decompiler output.
- Decompiler: structuring, variable recovery, simplification, and pseudocode emitter.

## MLIL vs HLIR boundary
- MLIL keeps CFG form and low-level memory operations but normalizes expressions and SSA.
- HLIR is structured control flow with variables/types; pseudocode is a rendering of HLIR.

## Client/Engine relationship
- The engine is a standalone library with a clean C++ API.
- Clients link against the engine library directly.
- CLI is the default client; GUI can be added later without engine changes.

## Extensibility
- Architecture-specific code lives under src/engine/arch/<arch>.
- New architectures implement the decoder + lifter interfaces and register with the engine.
- Core analysis and IR remain architecture-agnostic.
