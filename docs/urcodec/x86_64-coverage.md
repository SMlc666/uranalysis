# X86-64 Coverage Matrix

The CI corpus gate records sample-level codec totals, unknown rates, and unknown-instruction clusters by architecture, bytes, decoder, sample, and first address. Per-encoding-family attribution is still heuristic in this matrix.

## Codec Seed Forms

The first declarative forms cover `ret` and `call rel32`. These forms drive decode compatibility, encode, canonical text, text parsing, and roundtrip tests from one form table.

| Encoding group | Representative mnemonics | Decode | Format | Flow semantics | Golden tests | Corpus evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Return | `ret` | Implemented | Implemented | Implemented | Yes | Not measured | Near return only. |
| Relative call | `call rel32` | Implemented | Implemented | Implemented | Yes | Not measured | Direct relative call only. |
| Relative jump | `jmp rel8`, `jmp rel32` | Implemented | Implemented | Implemented | Yes | Not measured | Direct relative jump only. |
| Conditional jump | `jcc rel8`, `jcc rel32` | Implemented | Implemented | Implemented | Yes | Not measured | Common condition mnemonics covered. |
| Register move | `mov r64, imm64`, `mov r/m64, r64`, `mov r64, r/m64`, `mov r/m64, imm32`, `mov m16, imm16` | Partial | Implemented | Implemented | Yes | Not measured | 64-bit GPR forms plus operand-size-prefixed memory immediate stores only. |
| Address calculation | `lea r64, m` | Partial | Implemented | Implemented | Yes | Not measured | Common ModRM/SIB memory only. |
| Arithmetic | `add`, `adc`, `sbb`, `sub`, `inc`, `dec`, `neg`, `mul`, `imul`, `div`, `idiv` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit GPR, imm8/imm32 group, `f7`, and `ff /0`-`/1` forms only. |
| Compare and test | `cmp`, `test` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit GPR, imm8/imm32 group, and `f7 /0` forms only. |
| Logical | `and`, `or`, `xor`, `not` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit GPR, imm8/imm32 group, and `f7 /2` forms only. |
| Indirect control flow | `call r/m64`, `jmp r/m64` | Partial | Implemented | Implemented | Yes | Not measured | Near indirect `ff /2` and `ff /4` forms only. |
| Stack | `push`, `pop` | Partial | Implemented | Implemented | Yes | Not measured | 64-bit GPR forms and `ff /6` only. |
| SSE/AVX | `movups`, `movaps`, `xorps`, `vaddps` | Partial | Implemented | Implemented | Yes | Not measured | Basic legacy XMM `movups`, `movaps`, and `xorps` forms only; AVX remains out of scope. |
| System and privileged | `nop`, `int3`, `syscall`, `rdmsr`, `wrmsr` | Partial | Implemented | Implemented | Yes | Not measured | Plain and selected prefixed multi-byte NOPs plus `int3`; privileged/system instructions remain out of first scope. |
| Segment/TLS | `fs:`, `gs:` | Not implemented | Not implemented | Not implemented | No | Not measured | Out of first scope. |
