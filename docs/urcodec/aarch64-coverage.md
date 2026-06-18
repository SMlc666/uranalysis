# AArch64 Coverage Matrix

The CI corpus gate records sample-level codec totals and unknown rates. Per-encoding corpus attribution is still not measured in this matrix.

| Encoding group | Representative mnemonics | Decode | Format | Flow semantics | Golden tests | Corpus evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Unconditional branch immediate | `b`, `bl` | Implemented | Implemented | Implemented | Yes | Not measured | Direct targets use absolute addresses. |
| Unconditional branch register | `br`, `blr`, `ret` | Implemented | Implemented | Implemented | Yes | Not measured | `ret` omits `lr`. |
| Conditional branch immediate | `b.cond` | Implemented | Implemented | Implemented | Yes | Not measured | All condition suffixes are named. |
| Compare and branch | `cbz`, `cbnz` | Implemented | Implemented | Implemented | Yes | Not measured | 32-bit and 64-bit register forms supported. |
| Test and branch | `tbz`, `tbnz` | Implemented | Implemented | Implemented | Yes | Not measured | 32-bit and 64-bit register forms supported. |
| PC-relative addressing | `adr`, `adrp` | Implemented | Implemented | Implemented | Yes | Not measured | Targets are absolute. |
| Load/store unsigned immediate | `ldr`, `str` | Partial | Partial | Implemented | Yes | Not measured | Common integer register forms only. |
| Load/store pre/post index | `ldr`, `str` | Partial | Partial | Implemented | Yes | Not measured | Common integer register forms only. |
| Add/sub immediate | `add`, `adds`, `sub`, `subs`, `cmp`, `cmn` | Implemented | Implemented | Implemented | Yes | Not measured | Immediate shift supported. |
| Logical shifted register | `and`, `orr`, `eor`, `ands`, `mov` | Partial | Partial | Implemented | Yes | Not measured | Shift display is not emitted in first pass. |
| Move wide | `movz`, `movn`, `movk`, `mov` | Partial | Implemented | Implemented | Yes | Not measured | `movz` is displayed as `mov`. |
| Logical immediate | `and`, `orr`, `eor`, `ands` | Not implemented | Not implemented | Not implemented | No | Not measured | Add after corpus evidence shows priority. |
| Data processing register | `add`, `sub`, `mul`, `lsl`, `lsr` | Partial | Partial | Implemented | Limited | Not measured | Only logical shifted register subset is covered. |
| System hints | `nop` | Partial | Implemented | Implemented | Yes | Not measured | Other hints remain unknown. |
| SIMD/FP | `fmov`, `fadd`, `ldr q0` | Not implemented | Not implemented | Not implemented | No | Not measured | Track via corpus unknown clusters. |
| System registers | `mrs`, `msr`, `sys` | Not implemented | Not implemented | Not implemented | No | Not measured | Track via corpus unknown clusters. |
