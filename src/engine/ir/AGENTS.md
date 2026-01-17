# IR Pipeline Knowledge Base

## Overview

Three-tier intermediate representation: LLIR (low) → MLIR (medium) → HLIR (high).

## Structure

```
ir/
├── llir/          # Assembly-like IR (registers, memory, flags)
│   ├── llir.cpp   # Core LLIR construction from Capstone
│   ├── ssa.cpp    # SSA form construction
│   ├── opt.cpp    # LLIR optimizations
│   └── passes.cpp # Stack var lifting, jump table resolution
├── mlil/          # SSA variables, expression trees
│   ├── mlil_lift.cpp  # LLIR → MLIR lifting
│   ├── ssa.cpp    # MLIR SSA construction
│   └── opt.cpp    # Copy prop, constant fold, DCE
└── hlil/          # Structured control flow
    ├── hlil_lift.cpp  # MLIR → HLIR structuring
    ├── analysis/  # CFG analysis for structuring
    └── passes/    # Expression prop, DCE, loop reconstruction
```

## Where to Look

| Task | Location |
|------|----------|
| Add LLIR node type | `llir/llir.cpp` + headers |
| Add LLIR optimization | `llir/opt.cpp` |
| Add MLIR expression | `mlil/mlil_lift.cpp` |
| Add MLIR optimization | `mlil/opt.cpp` |
| Add HLIR pass | `hlil/passes/` (inherit `HlilPass`) |
| Fix control flow structuring | `hlir/hlil_lift.cpp`, `hlil/analysis/control_flow_graph.cpp` |

## Data Flow

```
Binary → LLIR: Capstone disasm → basic blocks → CFG
LLIR → MLIR:   Register → variable mapping, expression trees
MLIR → HLIR:   IPDOM analysis → structured if/while/for
```

**SSA at each level**: `ssa.cpp` files implement phi-node insertion and variable renaming.

**Optimization passes**: Run at each IR level. LLIR: stack lifting, const eval. MLIR: copy prop, fold, DCE. HLIR: expr prop, loop reconstruction.

## Key Files

| File | Role |
|------|------|
| `llir/llir.cpp` | ARM64 LLIR construction, CFG building |
| `llir/llir_x86_64.cpp` | x86-64 LLIR specifics |
| `mlil/mlil_lift.cpp` | LLIR→MLIR conversion |
| `hlir/hlil_lift.cpp` | MLIR→HLIR structuring |
| `hlir/passes/hlil_pass.h` | Base class for HLIR passes |

## Conventions

- IR nodes use smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- Passes implement visitor pattern for node traversal
- All optimizations preserve SSA invariants
