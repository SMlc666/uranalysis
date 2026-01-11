# Pseudo-C Quality Improvement Plan

Based on the analysis of `binaryO0Opt.elf` decompilation, here are the prioritized improvements:

## Priority 1: Simplify Verbose Comparison Expressions

**Problem**: Loop conditions show verbose bit manipulation:
```c
// Current output:
(((v28_2 - 0x27) >> 0x1f) != ((v28_2 >> 0x1f) & (((v28_2 - 0x27) >> 0x1f) != (v28_2 >> 0x1f))))

// Should be:
(v28_2 <= 0x27)
```

**Solution**: Add pattern matching in `expr_transforms.cpp` to recognize:
- `(x >> 31)` as sign extraction for signed comparisons
- Complex signed overflow detection patterns from compiler output

**Files to modify**:
- `src/engine/decompiler/transforms/expr_transforms.cpp`

## Priority 2: Reduce Excessive Function Arguments

**Problem**: Function calls show many spurious register arguments:
```c
// Current output:
sink_u64(v56, x1_4, x2_13, x3_2);

// Should be:
sink_u64(v56);
```

**Solution**: Enhance `prune_call_args` in `abi_params.cpp`:
1. Be more aggressive about removing high-index register args (x4-x7)
2. Use DWARF info when available for precise parameter counts
3. Trust symbol demangled names for C++ methods (e.g., methods like `sink_u64` clearly take 1 arg)

**Files to modify**:
- `src/engine/decompiler/passes/abi_params.cpp`

## Priority 3: Better Variable Naming and Folding

**Problem**: Too many temporary variables with SSA-like names:
```c
uint64_t x0_4;
uint64_t x0_5;
uint64_t v0_6;
```

**Solution**:
1. Enhance copy propagation to fold more cases
2. Remove unused variable declarations
3. Rename temporaries to simpler names

**Files to modify**:
- `src/engine/decompiler/transforms/var_transforms.cpp`
- `src/engine/decompiler/passes/naming.cpp`

## Priority 4: Stack Variable Reconstruction

**Problem**: Stack access shown as raw pointer arithmetic:
```c
*((sp - 0x18)) = x30;
```

**Solution**: 
1. Group stack offsets into local variable declarations
2. Detect frame pointer usage and reconstruct struct-like access

**Files to modify**:
- `src/engine/decompiler/passes/naming.cpp` (new pass needed)

## Priority 5: Loop Condition Recognition (for-loop recovery)

**Problem**: `for` loops decompiled as `while(0x1)`:
```c
while (0x1) {
    ...
    ++v16_3;
}

// Should be:
for (v16_3 = 0; v16_3 < limit; ++v16_3) {
    ...
}
```

**Solution**: Already have `merge_while_to_for` but it may need enhancement for:
1. Better loop bound detection
2. Detection of init/increment patterns

**Files to modify**:
- `src/engine/decompiler/transforms/loop_transforms.cpp`

## Implementation Status

| Priority | Issue | Status | Notes |
|----------|-------|--------|-------|
| 1 | Verbose comparison simplification | TODO | Complex signed comparison patterns |
| 2 | Excessive function arguments | TODO | Tighter ABI heuristics |
| 3 | Variable naming/folding | TODO | More aggressive copy prop |
| 4 | Stack variable reconstruction | TODO | New pass needed |
| 5 | for-loop recovery | TODO | Enhance existing pass |

## Quick Wins (Can implement now)

1. **Simplify `(x - c) >> 31` patterns** in expr_transforms.cpp
2. **Limit call args to 4** by default when no signature info available
3. **DCE pass** to remove unused variable declarations