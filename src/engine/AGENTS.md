# Engine Core Knowledge Base

## Overview

Core reverse engineering library: binary loading, disassembly, 3-tier IR lifting, decompilation.

## Structure

```
engine/
├── arch/{arm64,x86_64}/  # Architecture-specific lifters
├── ir/{llir,mlil,hlil}/  # IR representations + passes (see ir/AGENTS.md)
├── decompiler/           # Pseudocode pipeline (see decompiler/AGENTS.md)
├── loader/{elf,pe}/      # Binary format parsers
├── analysis/             # Function discovery, boundaries
├── dwarf/, ehframe/      # Debug info parsers
├── xrefs/                # Cross-reference analysis
├── symbols/, strings/    # Symbol/string catalogs
├── pass/                 # LLVM-style pass manager infrastructure
└── include/engine/       # Public headers
```

## Where to Look

| Task | Location |
|------|----------|
| Add ARM64 instruction | `arch/arm64/llil_lifter.cpp` (switch on opcode) |
| Add x86-64 instruction | `arch/x86_64/llil_lifter.cpp` |
| Add LLIR optimization | `ir/llir/opt.cpp` or `ir/llir/passes/` |
| Add MLIR optimization | `ir/mlil/opt.cpp` |
| Add HLIR pass | `ir/hlil/passes/` (inherit `HlilPass`) |
| Add decompiler pass | `decompiler/passes/` |
| Add type inference rule | `decompiler/types/type_solver.cpp` |
| Add binary format | `loader/` (follow ELF/PE pattern) |
| Add xref type | `xrefs/xrefs.cpp` |

## Key Patterns

**Session Model**: `Session` in `core/session.cpp` owns all analysis state.

**Lifter Pattern**: Switch on Capstone opcode → extract operands → emit LLIR nodes.

**IR Flow**: `LLIR` → `MLIR` (mlil_lift.cpp) → `HLIR` (hlil_lift.cpp).

**Pass Architectures**:
| Level | Base Class | Return Type | Analysis |
|-------|------------|-------------|----------|
| LLIR | `pass::PassInfoMixin<T>` | `pass::PassResult` | `AnalysisManager` |
| HLIR | `HlilPass` | `bool` | Manual |
| Decompiler | Procedural | `bool`/`void` | Heuristic |

## Complexity Hotspots

| File | Lines | Why |
|------|-------|-----|
| `arch/arm64/llil_lifter.cpp` | 2022 | 1000+ ARM64 instruction variants |
| `xrefs/xrefs.cpp` | 1224 | Symbolic evaluation, relocs, jump tables |
| `ehframe/eh_frame.cpp` | 1144 | Complex DWARF CFI encoding |

## Anti-Patterns

- **Do NOT** force types to register width - breaks on 32-bit in 64-bit regs
- **Do NOT** trust float regs from Phi nodes - often garbage
- **Do NOT** skip SSA construction for new IR passes

## IR Debugging

**Pass Instrumentation** (`pass/include/engine/pass/pass_instrumentation.h`):
```cpp
PassInstrumentationOptions opts;
opts.diff_only = true;      // Show before/after diff for each pass
opts.dump_before = true;    // Dump IR before pass
opts.dump_after = true;     // Dump IR after pass
opts.log_stats = true;      // Log statement count changes
opts.time_passes = true;    // Log execution time
opts.filter_pass = "DCE";   // Only instrument specific pass
```

**IR Dump Utilities** (`debug/include/engine/debug/ir_dump.h`):
```cpp
// Dump any IR level to string
std::string s = debug::dump(llir_func);  // LLIR
std::string s = debug::dump(mlir_func);  // MLIR
std::string s = debug::dump(hlir_func);  // HLIR

// Customize output
debug::DumpOptions opts;
opts.include_ssa_versions = true;
opts.include_asm = true;
```

## Notes

- Headers in `include/engine/` mirror source layout
- Use `spdlog` macros (`SPDLOG_DEBUG`, etc.)
- All public types use `std::` containers
