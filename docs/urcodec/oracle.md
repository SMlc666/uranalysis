# Urcodec Oracle Tests

`urcodec` uses Capstone as a test-only decode oracle for selected fixture bytes.
The oracle verifies that high-risk complete decodes agree with an external
decoder on instruction length, mnemonic family, and coarse operand shape.

Capstone is not part of the runtime decode path. It is declared only under
`crates/urcodec` dev-dependencies, and `ura-core` continues to depend on
`urcodec` rather than Capstone.

The oracle tests intentionally do not compare Capstone operand text as the
project contract. `urcodec` owns its canonical text format, structured operands,
instruction kind, flow semantics, and unknown-instruction policy. Capstone is
used to catch obvious decode drift such as wrong instruction length, wrong
mnemonic family, wrong Reg/Mem/Imm operand shape, or completing bytes that
should be reviewed against an external decoder before landing.

Current fixture scope:

- AArch64 core control flow, address, arithmetic, move, load, and store forms.
- X86-64 control flow, selected `0f` scalar forms, MMX/SSE shifts, SSE
  arithmetic/logical forms, packed integer, packed shuffle, MXCSR memory forms,
  selected VEX logical/scalar arithmetic forms, and AVX cleanup forms.

When adding corpus-driven decoder coverage, add a Capstone oracle fixture for
the representative bytes if Capstone can decode the instruction and the opcode
family is security- or alignment-sensitive.
