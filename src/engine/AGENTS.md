# Engine Core Knowledge Base

## Overview

Core reverse engineering library: binary loading, disassembly, 3-tier IR lifting, decompilation.

## Structure

```
engine/
├── arch/{arm64,x86_64}/  # Architecture-specific lifters
├── ir/{llir,mlil,hlil}/  # IR representations + passes
├── decompiler/           # Pseudocode generation pipeline
├── loader/{elf,pe}/      # Binary format parsers
├── analysis/             # Function discovery, boundaries
├── dwarf/, ehframe/      # Debug info parsers
├── xrefs/                # Cross-reference analysis
├── symbols/, strings/    # Symbol/string catalogs
└── include/engine/       # Public headers
```

## Where to Look

| Task | Location |
|------|----------|
| Add ARM64 instruction | `arch/arm64/llil_lifter.cpp` (switch on opcode) |
| Add x86-64 instruction | `arch/x86_64/llil_lifter.cpp` |
| Add LLIR optimization | `ir/llir/opt.cpp` or `ir/llir/passes.cpp` |
| Add MLIR optimization | `ir/mlil/opt.cpp` |
| Add HLIR pass | `ir/hlil/passes/` (inherit `HlilPass`) |
| Add decompiler pass | `decompiler/passes/` |
| Add type inference | `decompiler/types/type_solver.cpp` |
| Add binary format | `loader/` (follow ELF/PE pattern) |
| Add xref type | `xrefs/xrefs.cpp` |

## Key Patterns

**Session Model**: `Session` in `core/session.cpp` owns all analysis state - binary image, symbol catalog, xref catalog, analysis DB.

**Lifter Pattern**: Each architecture implements `lift_instruction()` returning `LlirInstr`. Switch on Capstone opcode, extract operands, emit LLIR nodes.

**IR Flow**: `LLIR` → `MLIR` (mlil_lift.cpp) → `HLIR` (hlil_lift.cpp). Each level has SSA construction (`ssa.cpp`) and optimization passes (`opt.cpp`).

**Pass Pattern**: Decompiler passes inherit common interface. Run order matters - see `decompiler/passes/` for dependencies.

## Complexity Hotspots

| File | Lines | Why |
|------|-------|-----|
| `arch/arm64/llil_lifter.cpp` | 2022 | Handles 1000+ ARM64 instruction variants |
| `xrefs/xrefs.cpp` | 1224 | Symbolic evaluation, reloc processing, jump tables |
| `ehframe/eh_frame.cpp` | 1144 | Complex DWARF CFI encoding |
| `decompiler/transforms/var_transforms.cpp` | 1222 | SSA manipulation, expression materialization |

## Anti-Patterns

- **Do NOT** force types to register width - breaks on 32-bit values in 64-bit regs
- **Do NOT** assume float regs from Phi nodes are valid - often garbage
- **Do NOT** skip SSA construction for new IR passes - required for correctness

## Notes

- Headers in `include/engine/` mirror source layout
- Use `spdlog` macros for logging (`SPDLOG_DEBUG`, etc.)
- All public types use `std::` containers
