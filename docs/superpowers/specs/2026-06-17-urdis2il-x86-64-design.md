# Urdis2il And X86-64 Decoder Design

Date: 2026-06-17

## Purpose

Ura will add a new `urdis2il` crate that lifts decoded instructions into a
small architecture-neutral intermediate language. The first version must be
constrained by both AArch64 and x86-64 so the IL does not accidentally encode
AArch64-only assumptions such as fixed-width instructions, ARM register naming,
or ARM condition-code behavior.

This work also expands `urdisassembly` with a self-owned minimal x86-64 decoder.
The x86-64 decoder is intentionally narrow, but it must be real enough to
exercise the IL model across variable-length instructions, complex memory
operands, stack operations, flags, and conditional branches.

## Goals

- Add `crates/urdis2il` as a workspace crate.
- Keep `urdis2il` dependent only on `urdisassembly`, not on `ura-core`.
- Extend `urdisassembly` with `Architecture::X86_64`.
- Implement a self-owned minimal x86-64 decoder instead of binding to an
  external decoder library.
- Define a low-level normalized IL suitable for later data-flow, constant
  propagation, CFG, and xref improvements.
- Lift a focused subset of AArch64 and x86-64 instructions into the same IL
  shape.
- Preserve safe degradation: unsupported or partially understood instructions
  must produce explicit unsupported IL instead of invented semantics.

## Non-Goals

- No decompiler or pseudocode generation.
- No complete x86-64 decoder.
- No SSE, AVX, floating-point, system, segment, ring, or privileged x86
  instruction support in the first version.
- No full x86 partial-register alias semantics in the first version.
- No complete AArch64 SIMD, floating-point, system-register, or privileged
  instruction lifting.
- No `ura-core` project-file schema change in this first design.
- No `ura-cli` or daemon user-facing IL commands in this first design.

## Architecture

The new architecture has two layers:

- `urdisassembly`: owns decoding and structured instruction operands.
- `urdis2il`: owns semantic lifting from decoded instructions to IL.

`ura-core` will not be part of the first implementation. Current `ura-core`
instructions flatten operands into strings, which is the wrong input for a
semantic lifter. The first implementation must prove the direct
`urdisassembly -> urdis2il` boundary before project persistence or CLI exposure
is added.

## Urdisassembly X86-64 Extension

`urdisassembly::Architecture` gains:

```rust
pub enum Architecture {
    Aarch64,
    X86_64,
}
```

The existing `Decoder::decode_one(bytes, address) -> Result<Instruction>` API can
remain, but `Instruction::size` becomes the authoritative consumed length for
variable-width architectures. AArch64 keeps its fixed four-byte requirement.
X86-64 reads between one and fifteen bytes and returns a hard decode error only
for truncated encodings or malformed input shape. Unsupported but well-formed
encodings decode to an unknown instruction instead of stopping analysis.

The x86-64 implementation lives under:

- `crates/urdisassembly/src/arch/x86_64/mod.rs`
- `crates/urdisassembly/src/arch/x86_64/decode.rs`
- `crates/urdisassembly/src/arch/x86_64/format.rs`
- `crates/urdisassembly/src/arch/x86_64/registers.rs`

The first decoder supports:

- REX prefixes needed for 64-bit GPR and `r8..r15`.
- ModRM and common SIB memory operands.
- Displacements and immediates needed by the covered instructions.
- RIP-relative addressing.
- 64-bit GPR operands for `rax..r15` and `rsp`.
- Relative branch and call target calculation.

The first instruction coverage is:

- `ret`
- `call rel32`
- `jmp rel8` and `jmp rel32`
- common `jcc rel8` and `jcc rel32`
- `mov reg, imm`
- `mov reg, reg`
- `mov reg, [mem]`
- `mov [mem], reg`
- `lea reg, [mem]`
- `add`, `sub`, `cmp`, `test`, `and`, `or`, `xor` for common register,
  immediate, and memory forms
- `push reg`
- `pop reg`

## Urdis2il Crate Boundary

`urdis2il` exposes a lifter selected by architecture:

```rust
let lifter = urdis2il::Lifter::new(urdisassembly::Architecture::X86_64);
let lifted = lifter.lift_instruction(&instruction)?;
```

The crate provides both per-instruction lifting and simple linear-block helpers.
It does not discover functions, own project state, parse ELF, or build a full
program database.

## IL Model

The IL is low-level and normalized. It represents explicit register reads and
writes, memory reads and writes, flag updates, and control-flow effects.

### Containers

```rust
pub struct IlInstruction {
    pub address: u64,
    pub size: u8,
    pub statements: Vec<IlStmt>,
    pub terminator: Option<IlTerminator>,
}

pub struct IlBlock {
    pub start: u64,
    pub instructions: Vec<IlInstruction>,
}

pub struct IlFunction {
    pub address: u64,
    pub blocks: Vec<IlBlock>,
}
```

`IlBlock` and `IlFunction` are model types for later consumers. The first lifter
does not need to perform function discovery or CFG recovery.

### Statements

```rust
pub enum IlStmt {
    Assign { dst: IlLocation, src: IlExpr },
    Load { dst: IlLocation, address: IlExpr, size: u16 },
    Store { address: IlExpr, value: IlExpr, size: u16 },
    SetFlag { flag: IlFlag, value: IlExpr },
    Intrinsic { name: String, inputs: Vec<IlExpr>, outputs: Vec<IlLocation> },
    Unsupported { address: u64, mnemonic: String, reason: String },
}
```

### Expressions

```rust
pub enum IlExpr {
    Reg(IlReg),
    Flag(IlFlag),
    Temp(u32),
    Const { value: u64, width_bits: u16 },
    Add(Box<IlExpr>, Box<IlExpr>),
    Sub(Box<IlExpr>, Box<IlExpr>),
    And(Box<IlExpr>, Box<IlExpr>),
    Or(Box<IlExpr>, Box<IlExpr>),
    Xor(Box<IlExpr>, Box<IlExpr>),
    Shl(Box<IlExpr>, Box<IlExpr>),
    Shr(Box<IlExpr>, Box<IlExpr>),
    Eq(Box<IlExpr>, Box<IlExpr>),
    Ne(Box<IlExpr>, Box<IlExpr>),
    Lt(Box<IlExpr>, Box<IlExpr>),
    Le(Box<IlExpr>, Box<IlExpr>),
    Gt(Box<IlExpr>, Box<IlExpr>),
    Ge(Box<IlExpr>, Box<IlExpr>),
    Not(Box<IlExpr>),
    SignExtend { value: Box<IlExpr>, to_bits: u16 },
    ZeroExtend { value: Box<IlExpr>, to_bits: u16 },
    Truncate { value: Box<IlExpr>, to_bits: u16 },
}
```

### Locations, Registers, And Flags

```rust
pub enum IlLocation {
    Reg(IlReg),
    Flag(IlFlag),
    Temp(u32),
}

pub struct IlReg {
    pub arch: urdisassembly::Architecture,
    pub name: String,
    pub width_bits: u16,
}

pub struct IlFlag {
    pub arch: urdisassembly::Architecture,
    pub name: String,
}
```

Register and flag names are not bare semantic keys. They are scoped by
architecture and width. X86 flags such as `zf`, `cf`, `of`, `sf`, and `pf` are
represented explicitly. AArch64 `nzcv` is split into `n`, `z`, `c`, and `v` so
conditional branches can share the same IL condition model as x86-64 jumps.

### Terminators

```rust
pub enum IlTerminator {
    Jump { target: IlExpr },
    Branch { condition: IlExpr, true_target: IlExpr, false_target: IlExpr },
    Call { target: IlExpr, return_address: Option<u64> },
    Return,
    Fallthrough { target: u64 },
    Unknown,
}
```

Calls are terminators because they affect control flow, but later analyses may
choose to model calls as both a statement and a fallthrough edge.

## Initial Lifting Scope

### AArch64

The first AArch64 lifter covers:

- `mov`, `movz`, `movn`, and `movk` as register assignment or update.
- `adr` and `adrp` as address constants.
- `add`, `sub`, `and`, `orr`, and `eor` as binary operations.
- `cmp` and `cmn` as flag updates.
- Common `ldr` and `str` forms as `Load` and `Store`.
- `b`, `bl`, `br`, `blr`, `ret`, `b.cond`, `cbz`, `cbnz`, `tbz`, and `tbnz` as
  terminators.
- `nop` as an empty lifted instruction.

### X86-64

The first x86-64 lifter covers:

- `mov` as assignment, load, or store depending on operands.
- `lea` as address-expression assignment.
- `add`, `sub`, `and`, `or`, and `xor` as assignment plus flag update.
- `cmp` and `test` as flag update.
- `push` as stack-pointer subtraction plus store.
- `pop` as load plus stack-pointer addition.
- `jmp`, `jcc`, `call`, and `ret` as terminators.
- Common memory operands of the form `[base + index * scale + displacement]`.
- RIP-relative memory operands as `Const(next_ip + displacement)`.

### Flag Semantics

The first version does not need complete handwritten flag formulas for every
operation. It may use named intrinsics such as:

- `x86_add_flags`
- `x86_sub_flags`
- `x86_logic_flags`
- `aarch64_add_flags`
- `aarch64_sub_flags`

Conditional branches must consume explicit flag expressions where the condition
is known. For example, x86 `je` and AArch64 `b.eq` both become a branch condition
equivalent to `Eq(Flag(z), Const(1, 1))`.

## Unsupported Semantics

The lifter must never pretend to understand unsupported instructions. If a
decoded instruction has `DecodeStatus::Unknown`, incomplete structured operands,
or a mnemonic outside the first lifting scope, the lifter returns:

```rust
IlStmt::Unsupported {
    address,
    mnemonic,
    reason,
}
```

The lifted instruction remains present in output so callers can keep addresses
aligned with the original disassembly and report coverage gaps.

## Success Criteria

The design is successful when the following examples produce equivalent IL
shapes across architectures:

- AArch64 `ldr x0, [x1, #8]` and x86-64 `mov rax, [rbx+8]` both lift to
  `Load` from an address expression.
- AArch64 `cmp x0, #0; b.eq target` and x86-64 `cmp rax, 0; je target` both lift
  to flag updates followed by a conditional branch using the zero flag.
- AArch64 `bl target` and x86-64 `call target` both lift to `Call` terminators
  with return-address metadata.
- Unsupported instructions produce explicit unsupported IL without failing the
  entire lift.

## Documentation

Add these coverage files as part of implementation:

- `docs/urdisassembly/x86_64-coverage.md`
- `docs/urdis2il/coverage.md`

The x86-64 coverage file tracks decode, formatting, flow semantics, golden
tests, and missing variants by instruction family. The IL coverage file tracks
which decoded instructions are lifted, lowered to intrinsics, or unsupported for
each architecture.

## Testing

Tests must be structural, not just formatted-text checks.

`urdisassembly` tests:

- AArch64 existing tests continue passing.
- X86-64 golden tests cover instruction size, mnemonic, structured operands,
  formatted text, flow kind, and branch target.
- X86-64 malformed or truncated encodings produce hard errors.
- X86-64 unsupported but well-shaped encodings produce unknown instructions.

`urdis2il` tests:

- AArch64 and x86-64 load/store instructions produce equivalent `Load` and
  `Store` shapes.
- AArch64 and x86-64 compare-plus-conditional-branch patterns use explicit zero
  flag conditions.
- Calls and returns produce terminators.
- Stack operations on x86-64 modify `rsp` and access memory with the expected
  width.
- Unknown and partial decode results produce `Unsupported` IL.

Workspace verification:

- `cargo fmt -- --check`
- `cargo test -p urdisassembly`
- `cargo test -p urdis2il`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`

## Rollout

Implement this as a focused foundation before connecting IL to `ura-core`.

1. Extend `urdisassembly` with x86-64 architecture selection and minimal decode
   support.
2. Add `urdis2il` with the IL model and lifter API.
3. Add AArch64 lifting for currently covered decoded instructions.
4. Add x86-64 lifting for the new minimal decoder coverage.
5. Add coverage documents.
6. Keep `ura-core` unchanged until the decoder and lifter crates have their own
   passing structural tests.

Future `ura-core` integration should preserve user truth and project-file
compatibility rules separately from this design.
