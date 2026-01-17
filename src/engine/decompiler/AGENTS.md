# Decompiler Knowledge Base

## Overview

Transforms HLIR into C-like pseudocode via multi-pass pipeline.

## Structure

```
decompiler/
├── passes/        # Analysis and transformation passes
│   ├── abi_params.cpp     # ABI parameter recovery (748 lines)
│   ├── de_ssa.cpp         # SSA destruction (517 lines)
│   ├── rename_vars.cpp    # Variable naming
│   ├── stack_vars.cpp     # Stack variable recovery
│   ├── special_regs.cpp   # Special register handling
│   └── ssa_groups.cpp     # SSA group management
├── transforms/    # Expression/control flow transforms
│   ├── var_transforms.cpp     # Variable SSA transforms (1222 lines)
│   ├── expr_transforms.cpp    # Expression simplification (1017 lines)
│   ├── control_flow.cpp       # Control flow normalization (879 lines)
│   └── loop_transforms.cpp    # Loop detection/optimization (990 lines)
├── types/         # Type inference system
│   ├── type_solver.cpp        # Type inference engine
│   ├── type_constraints.cpp   # Constraint solving
│   ├── type_system.cpp        # Core type definitions
│   └── signature_db.cpp       # Function signature database
├── pseudoc.cpp    # Pseudocode AST generation
└── printer.cpp    # C-like code formatting (1092 lines)
```

## Where to Look

| Task | Location |
|------|----------|
| Add decompiler pass | `passes/` (follow existing pattern) |
| Fix variable naming | `passes/rename_vars.cpp` |
| Add type inference rule | `types/type_solver.cpp` |
| Fix expression simplification | `transforms/expr_transforms.cpp` |
| Fix loop detection | `transforms/loop_transforms.cpp` |
| Change output formatting | `printer.cpp` |

## Pipeline Order

1. **ABI params** → Recover function parameters from calling convention
2. **Stack vars** → Identify stack-allocated variables
3. **SSA groups** → Group related SSA variables
4. **Transforms** → Simplify expressions, normalize control flow
5. **De-SSA** → Convert out of SSA form
6. **Rename vars** → Generate readable variable names
7. **Type inference** → Infer/propagate types
8. **Pseudoc** → Generate pseudocode AST
9. **Printer** → Format as C-like code

## Anti-Patterns

- **Do NOT** force types to register width (see `type_constraints.cpp`)
- **Do NOT** assume float regs from Phi nodes are valid - often garbage/clobbers
- **Do NOT** run de-SSA before all SSA-dependent passes complete

## Notes

- Large files reflect complex pattern matching for readable output
- `printer.cpp` handles all statement types, indentation, naming
- Type system uses constraint-based inference with solver
