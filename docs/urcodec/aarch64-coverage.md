# AArch64 Coverage Matrix

The CI corpus gate records sample-level codec totals, unknown rates, and unknown-instruction clusters by architecture, bytes, decoder, sample, and first address. Per-encoding-family attribution is still heuristic in this matrix.

## Codec Seed Forms

The first declarative forms cover `ret` and `b imm26`. These forms drive decode compatibility, encode, canonical text, text parsing, and roundtrip tests from one form table.

| Encoding group | Representative mnemonics | Decode | Format | Flow semantics | Golden tests | Corpus evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Unconditional branch immediate | `b`, `bl` | Implemented | Implemented | Implemented | Yes | Not measured | Direct targets use absolute addresses. |
| Unconditional branch register | `br`, `blr`, `ret` | Implemented | Implemented | Implemented | Yes | Not measured | `ret` omits `lr`. |
| Conditional branch immediate | `b.cond` | Implemented | Implemented | Implemented | Yes | Not measured | All condition suffixes are named. |
| Compare and branch | `cbz`, `cbnz` | Implemented | Implemented | Implemented | Yes | Not measured | 32-bit and 64-bit register forms supported. |
| Test and branch | `tbz`, `tbnz` | Implemented | Implemented | Implemented | Yes | Not measured | 32-bit and 64-bit register forms supported. |
| PC-relative addressing | `adr`, `adrp` | Implemented | Implemented | Implemented | Yes | Not measured | Targets are absolute. |
| Load/store unsigned immediate | `ldr`, `str` | Partial | Partial | Implemented | Yes | Not measured | Common integer register forms only. |
| Load/store unscaled and pre/post index | `ldur`, `stur`, `ldr`, `str` | Partial | Partial | Implemented | Yes | Corpus-driven | Common integer register forms only. |
| Load/store register offset | `ldr`, `str` | Partial | Partial | Implemented | Yes | Corpus-driven | `uxtw` register-index forms are covered. |
| Load/store pair | `ldp`, `stp` | Partial | Partial | Implemented | Yes | Corpus-driven | 32-bit/64-bit GPR and `q` vector signed-offset forms, plus GPR pre/post-index forms. |
| Add/sub immediate | `add`, `adds`, `sub`, `subs`, `cmp`, `cmn` | Implemented | Implemented | Implemented | Yes | Not measured | Immediate shift supported. |
| Add/sub shifted register | `add`, `adds`, `sub`, `subs`, `cmp`, `cmn` | Partial | Partial | Implemented | Yes | Corpus-driven | Register forms and explicit shifted-register operands are covered. |
| Logical shifted register | `and`, `orr`, `eor`, `ands`, `mov` | Partial | Partial | Implemented | Yes | Not measured | Shift display is not emitted in first pass. |
| Move wide | `movz`, `movn`, `movk`, `mov` | Partial | Implemented | Implemented | Yes | Not measured | `movz` is displayed as `mov`. |
| Conditional select | `csel`, `cset` | Partial | Implemented | Implemented | Yes | Corpus-driven | Common select and zero-register set aliases are covered. |
| Logical immediate | `and`, `orr`, `eor`, `ands`, `mov` | Partial | Partial | Implemented | Yes | Corpus-driven | Includes bitmask immediate decode and `orr zr, #imm` as `mov`. |
| Bitfield aliases | `lsl`, `lsr`, `asr` | Partial | Partial | Implemented | Yes | Corpus-driven | Common `ubfm`/`sbfm` shift aliases are covered. |
| Data processing register | `add`, `sub`, `mul`, `lsl`, `lsr` | Partial | Partial | Implemented | Limited | Corpus-driven | Logical shifted register subset and `lsr` register alias are covered. |
| System hints and exceptions | `nop`, `brk` | Partial | Implemented | Implemented | Yes | Corpus-driven | Other hints and system instructions remain unknown. |
| SIMD/FP | `fmov`, `fadd`, `ldr q0`, `ldp q0`, `movi` | Partial | Partial | Implemented | Limited | Corpus-driven | Only `q` load/store pair and zero `movi v*.2d` forms are covered. |
| System registers | `mrs`, `msr`, `sys` | Not implemented | Not implemented | Not implemented | No | Not measured | Track via corpus unknown clusters. |
