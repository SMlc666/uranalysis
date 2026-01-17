# IR Pipeline Knowledge Base

## Overview

Three-tier intermediate representation: LLIR (low) → MLIR (medium) → HLIR (high).

## Structure

```
ir/
├── llir/          # Assembly-like IR (registers, memory, flags)
│   ├── llir.cpp       # Core LLIR construction from Capstone
│   ├── ssa.cpp        # SSA form construction
│   ├── opt.cpp        # LLIR optimizations
│   └── passes/        # Mixin-based passes (PassInfoMixin<T>)
├── mlil/          # SSA variables, expression trees
│   ├── mlil_lift.cpp  # LLIR → MLIR lifting
│   ├── ssa.cpp        # MLIR SSA construction
│   └── opt.cpp        # Copy prop, constant fold, DCE
└── hlil/          # Structured control flow
    ├── hlil_lift.cpp  # MLIR → HLIR structuring
    ├── analysis/      # CFG analysis for structuring
    ├── passes/        # OO passes (inherit HlilPass)
    └── pm_passes/     # Pass manager integrated passes
```

## Where to Look

| Task | Location |
|------|----------|
| Add LLIR node type | `llir/llir.cpp` + headers |
| Add LLIR optimization | `llir/opt.cpp` or `llir/passes/` |
| Add MLIR expression | `mlil/mlil_lift.cpp` |
| Add MLIR optimization | `mlil/opt.cpp` |
| Add HLIR pass | `hlil/passes/` (inherit `HlilPass`) |
| Fix control flow structuring | `hlil/hlil_lift.cpp` |

## Data Flow

```
Binary → LLIR: Capstone disasm → basic blocks → CFG
LLIR → MLIR:   Register → variable, expression trees
MLIR → HLIR:   IPDOM analysis → structured if/while/for
```

## Pass Patterns

**LLIR Passes** (Modern C++ Mixin):
```cpp
struct MyPass : public pass::PassInfoMixin<MyPass> {
    pass::PassResult run(Function& fn, AnalysisManager<Function>& am);
};
// Uses AnalysisManager for dependency tracking
```

**HLIL Passes** (Classic OO):
```cpp
class MyPass : public HlilPass {
    bool run(Function& fn) override;  // true if modified
    const char* name() const override;
};
```

## Key Files

| File | Role |
|------|------|
| `llir/llir.cpp` | ARM64 LLIR construction, CFG |
| `llir/llir_x86_64.cpp` | x86-64 LLIR specifics |
| `mlil/mlil_lift.cpp` | LLIR→MLIR conversion |
| `hlil/hlil_lift.cpp` | MLIR→HLIR structuring |
| `hlil/passes/hlil_pass.h` | Base class for HLIR passes |

## Debugging IR Passes

**Diff Mode** - 查看每个 pass 前后的 IR 变化：
```cpp
PassInstrumentationOptions opts;
opts.diff_only = true;   // 只显示变化的行 (- removed, + added)
opts.log_stats = true;   // 显示语句数量变化
// PassManager 会自动输出每个 pass 的 diff
```

**Dump IR** - 打印任意 IR 层级：
```cpp
#include "engine/debug/ir_dump.h"
std::string s = debug::dump(function);  // LLIR/MLIR/HLIR 都支持
```

## Conventions

- IR nodes use smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- Passes implement visitor pattern for traversal
- All optimizations preserve SSA invariants
- LLIR passes check `detail::has_ssa(function)` before SSA ops
