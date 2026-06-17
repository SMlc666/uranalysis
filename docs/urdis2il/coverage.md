# Urdis2il Coverage Matrix

| Architecture | Instruction family | IL status | Representation | Tests | Notes |
| --- | --- | --- | --- | --- | --- |
| AArch64 | `mov`, `movz`, `movn`, `movk` | Partial | `Assign` | Yes | Immediate and register forms only. |
| AArch64 | `adr`, `adrp` | Implemented | `Assign(Const)` | Yes | Uses decoded absolute target. |
| AArch64 | `add`, `sub`, `and`, `orr`, `eor` | Partial | `Assign(BinOp)` | Yes | Covered decoded operand forms only. |
| AArch64 | `cmp`, `cmn` | Partial | Flag intrinsic | Yes | Emits `aarch64_sub_flags` or `aarch64_add_flags`. |
| AArch64 | `ldr`, `str` | Partial | `Load`, `Store` | Yes | Common integer forms only. |
| AArch64 | `b`, `bl`, `ret`, `b.cond` | Partial | Terminators | Yes | Common direct control-flow forms only. |
| X86-64 | `mov`, `lea` | Partial | `Assign`, `Load`, `Store` | Yes | 64-bit GPR and common memory forms only. |
| X86-64 | `add`, `sub`, `and`, `or`, `xor` | Partial | `Assign` plus flag intrinsic | Yes | Common 64-bit GPR and imm8 forms only. |
| X86-64 | `cmp`, `test` | Partial | Flag intrinsic | Yes | Emits `x86_sub_flags` or `x86_logic_flags`. |
| X86-64 | `push`, `pop` | Partial | Stack pointer update plus memory access | Yes | 64-bit GPR forms only. |
| X86-64 | `jmp`, `jcc`, `call`, `ret` | Partial | Terminators | Yes | Direct relative control-flow forms only. |
| Both | Unknown or partial decode | Implemented | `Unsupported` | Yes | Keeps address alignment and reports reason. |
