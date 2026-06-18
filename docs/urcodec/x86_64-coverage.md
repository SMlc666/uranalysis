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
| Conditional move | `cmovcc r32/r64, r/m32/r/m64` | Partial | Implemented | Implemented | Yes | Not measured | Common integer conditional moves with default operand width and REX.W only. |
| Register move | `mov r64, imm64`, `mov r8, imm8`, `movsxd`, `xchg`, `mov r/m64, r64`, `mov r64, r/m64`, `mov r/m64, imm32`, `mov m16, imm16`, `mov r/m8, r8`, `mov r8, r/m8`, `mov r/m8, imm8` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit and byte GPR forms, sign-extending moves, exchange forms, and operand-size-prefixed memory immediate stores only. |
| Address calculation | `lea r64, m` | Partial | Implemented | Implemented | Yes | Not measured | Common ModRM/SIB memory only. |
| Arithmetic | `add`, `adc`, `sbb`, `sub`, `xadd`, `inc`, `dec`, `neg`, `mul`, `imul`, `div`, `idiv` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit and byte GPR forms, accumulator imm32 forms, AL imm8 forms, byte/imm8/imm32 group, selected lock-prefixed atomics, `f6`/`f7`, and `ff /0`-`/1` forms only. |
| Compare and test | `cmp`, `cmpxchg`, `test`, `bt`, `setcc` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit and byte GPR forms, `cmp al, imm8`, `test al, imm8`, byte `test`, byte/imm8/imm32 group, `f6`/`f7 /0`, selected lock-prefixed atomics, `bt r/m, r`, and `setcc r/m8` forms only. |
| Logical | `and`, `or`, `xor`, `not`, `rol`, `ror`, `rcl`, `rcr`, `shl`, `shr`, `sar` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit and byte GPR forms, AL imm8 forms, byte/imm8/imm32 group, shift imm8 groups, implicit-count-one shift groups, and `f6`/`f7 /2` forms only. |
| Indirect control flow | `call r/m64`, `jmp r/m64` | Partial | Implemented | Implemented | Yes | Not measured | Near indirect `ff /2` and `ff /4` forms only. |
| Stack | `push`, `pop` | Partial | Implemented | Implemented | Yes | Not measured | 64-bit GPR forms and `ff /6` only. |
| SSE/AVX | `movups`, `movaps`, `xorps`, `mulps`, `mulsd`, `cmpps`, `movd`, `movq`, `pcmpeqb`, `vmovdqa`, `vmovdqu`, `vmovntdq`, `vpmovmskb`, `vmulps`, `vmulsd`, `vzeroupper` | Partial | Implemented | Implemented | Yes | Not measured | Basic legacy XMM forms plus corpus-driven 2-byte and 3-byte VEX.128/VEX.256 decode for selected AVX move, multiply, mask, and cleanup forms only. |
| MMX | `movd`, `movq`, `pcmpeqb`, `pavgb`, `pmaddwd`, `psllw`, `paddw`, `pmovmskb` | Partial | Implemented | Implemented | Yes | Not measured | Corpus-driven legacy MMX register/memory forms only; 3DNow remains out of scope. |
| System and privileged | `nop`, `int3`, `int imm8`, `ud2`, `xgetbv`, `sfence`, `syscall`, `rdmsr`, `wrmsr` | Partial | Implemented | Implemented | Yes | Not measured | Plain NOP, selected prefixed multi-byte NOPs, `int3`, `int imm8`, `xgetbv`, `sfence`, and `ud2`; privileged/system instructions remain partial. |
| Segment/TLS | `fs:`, `gs:` | Not implemented | Not implemented | Not implemented | No | Not measured | Out of first scope. |
