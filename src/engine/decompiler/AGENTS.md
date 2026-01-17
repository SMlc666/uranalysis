# Decompiler Knowledge Base

## Overview

Transforms HLIR into C-like pseudocode via multi-pass pipeline.

## Structure

```
decompiler/
├── passes/        # Analysis and transformation passes
│   ├── abi_params.cpp     # ABI parameter recovery (748 lines)
│   ├── de_ssa.cpp         # SSA destruction + critical edge splitting
│   ├── rename_vars.cpp    # Variable naming
│   ├── stack_vars.cpp     # Stack variable recovery
│   ├── special_regs.cpp   # Special register handling
│   ├── ssa_groups.cpp     # SSA group management
│   ├── range_analysis.cpp # Value range analysis
│   ├── constant_propagation.cpp
│   └── dce.cpp            # Dead code elimination
├── transforms/    # Expression/control flow transforms
│   ├── var_transforms.cpp     # SSA transforms (1222 lines)
│   ├── expr_transforms.cpp    # Expression simplification (1376 lines)
│   ├── control_flow.cpp       # Control flow normalization
│   ├── loop_transforms.cpp    # Loop detection/optimization
│   └── condition_flattening.cpp
├── types/         # Type inference system
│   ├── type_solver.cpp        # Constraint-based inference
│   ├── type_constraints.cpp   # Constraint solving
│   ├── type_system.cpp        # Core type definitions
│   └── signature_db.cpp       # Function signature database
├── pseudoc.cpp    # Pseudocode AST generation
└── printer.cpp    # C-like code formatting (1092 lines)
```

## Where to Look

| Task | Location |
|------|----------|
| Add decompiler pass | `passes/` (procedural style) |
| Fix variable naming | `passes/rename_vars.cpp` |
| Add type inference rule | `types/type_solver.cpp` |
| Fix expression simplification | `transforms/expr_transforms.cpp` |
| Fix loop detection | `transforms/loop_transforms.cpp` |
| Change output formatting | `printer.cpp` |

## Pipeline Order

1. **ABI params** → Recover parameters from calling convention
2. **Stack vars** → Identify stack-allocated variables
3. **SSA groups** → Group related SSA variables
4. **Transforms** → Simplify expressions, normalize control flow
5. **De-SSA** → Convert out of SSA form (critical edge splitting)
6. **Rename vars** → Generate readable variable names
7. **Type inference** → Constraint-based type propagation
8. **Pseudoc** → Generate pseudocode AST
9. **Printer** → Format as C-like code

## Anti-Patterns

- **Do NOT** force types to register width (`type_constraints.cpp`)
- **Do NOT** trust float regs (v0-v31) from Phi nodes - usually clobbers
- **Do NOT** run de-SSA before all SSA-dependent passes complete
- **Do NOT** skip critical edge splitting in de-SSA

## Key Gotchas

**Liveness Rules** (in DCE):
- Variables in loops → always live (loop-carried deps)
- `Call`, `Store`, `Return` statements → always live

**SSA Versioning**: Incoming version always differs from phi version.

**ABI Heuristics**: `abi_params.cpp` uses register usage patterns to guess arg count.

## Notes

- Large files reflect complex pattern matching
- Type system is constraint-based with solver
- `printer.cpp` handles all statement types + indentation
