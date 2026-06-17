# Urdis2il X86-64 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a minimal self-owned x86-64 decoder to `urdisassembly` and a new `urdis2il` crate that lifts AArch64 and x86-64 decoded instructions into a shared low-level IL.

**Architecture:** `urdisassembly` continues to own instruction decoding, formatting, structured operands, flow kind, and decode status. `urdis2il` depends only on `urdisassembly` and lifts structured decoded instructions into architecture-neutral IL; `ura-core`, CLI, daemon, and project persistence remain unchanged in this plan.

**Tech Stack:** Rust 2021, Cargo workspace, existing `serde` and `thiserror`, current `urdisassembly` AArch64 decoder, new self-contained x86-64 prefix/opcode/ModRM/SIB parser, structural Rust tests.

---

## Scope Notes

This plan implements `docs/superpowers/specs/2026-06-17-urdis2il-x86-64-design.md`.

The spec covers two tightly coupled foundations: x86-64 decoding and cross-architecture IL lifting. They stay in one plan because the IL shape must be validated against both AArch64 and x86-64 before it is useful. `ura-core` integration is deliberately out of scope.

Keep commits frequent. Each task below ends with a commit command. If a command fails in a way not described by the expected output, stop and inspect before continuing.

## File Structure

- Modify `Cargo.toml`: add `crates/urdis2il` as a workspace member and shared path dependency.
- Modify `crates/urdisassembly/src/model.rs`: add `Architecture::X86_64` and expand `MemoryOperand` so it can represent x86 base/index/scale/displacement and RIP-relative memory.
- Modify `crates/urdisassembly/src/decoder.rs`: dispatch AArch64 fixed-width decode and x86-64 variable-width decode.
- Modify `crates/urdisassembly/src/arch/mod.rs`: export the new x86-64 architecture module.
- Modify `crates/urdisassembly/src/arch/aarch64/decode.rs`: construct the expanded `MemoryOperand`.
- Modify `crates/urdisassembly/src/arch/aarch64/format.rs`: render the expanded `MemoryOperand` without changing AArch64 output.
- Create `crates/urdisassembly/src/arch/x86_64/mod.rs`: x86-64 module root.
- Create `crates/urdisassembly/src/arch/x86_64/registers.rs`: x86-64 register naming and flag names.
- Create `crates/urdisassembly/src/arch/x86_64/format.rs`: x86-64 operand and instruction rendering.
- Create `crates/urdisassembly/src/arch/x86_64/decode.rs`: self-owned x86-64 prefix/opcode/ModRM/SIB decoder.
- Create `crates/urdisassembly/tests/x86_64_decode.rs`: x86-64 decode golden tests.
- Create `docs/urdisassembly/x86_64-coverage.md`: x86-64 decode coverage matrix.
- Create `crates/urdis2il/Cargo.toml`: new lifter crate manifest.
- Create `crates/urdis2il/src/lib.rs`: public exports.
- Create `crates/urdis2il/src/error.rs`: lifter errors.
- Create `crates/urdis2il/src/model.rs`: IL containers, statements, expressions, locations, registers, flags, and terminators.
- Create `crates/urdis2il/src/lifter.rs`: architecture-neutral `Lifter` entrypoint.
- Create `crates/urdis2il/src/aarch64.rs`: AArch64 lifting rules.
- Create `crates/urdis2il/src/x86_64.rs`: x86-64 lifting rules.
- Create `crates/urdis2il/src/operand.rs`: shared operand-to-IL helpers.
- Create `crates/urdis2il/tests/model.rs`: IL model and unsupported fallback tests.
- Create `crates/urdis2il/tests/aarch64_lift.rs`: AArch64 structural lift tests.
- Create `crates/urdis2il/tests/x86_64_lift.rs`: x86-64 structural lift tests.
- Create `docs/urdis2il/coverage.md`: IL lifting coverage matrix.

---

### Task 1: Add X86-64 Architecture Plumbing

**Files:**
- Modify: `crates/urdisassembly/src/model.rs`
- Modify: `crates/urdisassembly/src/decoder.rs`
- Modify: `crates/urdisassembly/src/arch/mod.rs`
- Modify: `crates/urdisassembly/src/arch/aarch64/decode.rs`
- Modify: `crates/urdisassembly/src/arch/aarch64/format.rs`
- Create: `crates/urdisassembly/src/arch/x86_64/mod.rs`
- Create: `crates/urdisassembly/src/arch/x86_64/decode.rs`
- Create: `crates/urdisassembly/src/arch/x86_64/format.rs`
- Create: `crates/urdisassembly/src/arch/x86_64/registers.rs`
- Create: `crates/urdisassembly/tests/x86_64_decode.rs`

- [ ] **Step 1: Write the failing x86-64 API tests**

Create `crates/urdisassembly/tests/x86_64_decode.rs`:

```rust
use urdisassembly::{
    Architecture, DecodeError, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind,
};

fn decode(bytes: &[u8], address: u64) -> urdisassembly::Instruction {
    Decoder::new(Architecture::X86_64, DecodeOptions::default())
        .unwrap()
        .decode_one(bytes, address)
        .unwrap()
}

#[test]
fn constructs_x86_64_decoder_and_decodes_unknown_byte() {
    let insn = decode(&[0xcc], 0x401000);

    assert_eq!(insn.address, 0x401000);
    assert_eq!(insn.size, 1);
    assert_eq!(insn.bytes, vec![0xcc]);
    assert_eq!(insn.mnemonic, ".byte");
    assert_eq!(insn.text, ".byte 0xcc");
    assert_eq!(insn.kind, InstructionKind::Unknown);
    assert_eq!(insn.flow, FlowKind::Fallthrough);
    assert_eq!(insn.branch_target, None);
    assert_eq!(insn.status, DecodeStatus::Unknown);
}

#[test]
fn empty_x86_64_input_is_truncated() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();

    let err = decoder.decode_one(&[], 0x401000).unwrap_err();

    assert_eq!(
        err,
        DecodeError::TruncatedInstruction {
            expected: 1,
            actual: 0,
        }
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
cargo test -p urdisassembly --test x86_64_decode
```

Expected: compilation fails because `Architecture::X86_64` does not exist.

- [ ] **Step 3: Expand the public architecture and memory model**

In `crates/urdisassembly/src/model.rs`, change `Architecture` and `MemoryOperand` to:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
    X86_64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryOperand {
    pub base: Option<Register>,
    pub index: Option<Register>,
    pub scale: u8,
    pub offset: i64,
    pub width_bits: Option<u16>,
    pub writeback: bool,
    pub post_index: bool,
    pub relative: bool,
}

impl MemoryOperand {
    pub fn base_offset(base: Register, offset: i64, width_bits: Option<u16>) -> Self {
        Self {
            base: Some(base),
            index: None,
            scale: 1,
            offset,
            width_bits,
            writeback: false,
            post_index: false,
            relative: false,
        }
    }

    pub fn indexed(
        base: Option<Register>,
        index: Option<Register>,
        scale: u8,
        offset: i64,
        width_bits: Option<u16>,
    ) -> Self {
        Self {
            base,
            index,
            scale,
            offset,
            width_bits,
            writeback: false,
            post_index: false,
            relative: false,
        }
    }

    pub fn rip_relative(offset: i64, width_bits: Option<u16>) -> Self {
        Self {
            base: Some(Register {
                name: "rip".to_string(),
            }),
            index: None,
            scale: 1,
            offset,
            width_bits,
            writeback: false,
            post_index: false,
            relative: true,
        }
    }

    pub fn with_writeback(mut self) -> Self {
        self.writeback = true;
        self
    }

    pub fn with_post_index(mut self) -> Self {
        self.post_index = true;
        self
    }
}
```

Update every AArch64 `MemoryOperand { ... }` construction in `crates/urdisassembly/src/arch/aarch64/decode.rs` so base-only memory uses:

```rust
Operand::Memory(MemoryOperand::base_offset(base_register, offset, Some(width_bits)))
```

For AArch64 pre-index forms, append `.with_writeback()`. For post-index forms, append `.with_post_index()`.

- [ ] **Step 4: Keep AArch64 memory formatting stable**

In `crates/urdisassembly/src/arch/aarch64/format.rs`, replace `render_memory` with:

```rust
fn render_memory(mem: &MemoryOperand) -> String {
    let base = mem
        .base
        .as_ref()
        .map(|reg| reg.name.as_str())
        .unwrap_or("unknown");
    if mem.offset == 0 && !mem.writeback && !mem.post_index {
        format!("[{base}]")
    } else if mem.post_index {
        format!("[{base}], #{}", format_signed_hex(mem.offset))
    } else if mem.writeback {
        format!("[{base}, #{}]!", format_signed_hex(mem.offset))
    } else {
        format!("[{base}, #{}]", format_signed_hex(mem.offset))
    }
}
```

- [ ] **Step 5: Add x86-64 module stubs with unknown fallback**

Edit `crates/urdisassembly/src/arch/mod.rs`:

```rust
pub mod aarch64;
pub mod x86_64;
```

Create `crates/urdisassembly/src/arch/x86_64/mod.rs`:

```rust
pub mod decode;
pub mod format;
pub mod registers;
```

Create `crates/urdisassembly/src/arch/x86_64/registers.rs`:

```rust
use crate::model::Register;

pub fn reg64(index: u8) -> Register {
    let name = match index & 0x0f {
        0 => "rax",
        1 => "rcx",
        2 => "rdx",
        3 => "rbx",
        4 => "rsp",
        5 => "rbp",
        6 => "rsi",
        7 => "rdi",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "r13",
        14 => "r14",
        _ => "r15",
    };
    Register {
        name: name.to_string(),
    }
}
```

Create `crates/urdisassembly/src/arch/x86_64/format.rs`:

```rust
use crate::model::{MemoryOperand, Operand};

pub fn render_instruction(mnemonic: &str, operands: &[Operand]) -> String {
    let operand_text = render_operands(operands);
    if operand_text.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{mnemonic} {operand_text}")
    }
}

pub fn render_operands(operands: &[Operand]) -> String {
    operands
        .iter()
        .map(render_operand)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn render_operand(operand: &Operand) -> String {
    match operand {
        Operand::Register(reg) => reg.name.clone(),
        Operand::Immediate(value) => format!("0x{:x}", *value as u64),
        Operand::AbsoluteAddress(addr) => format!("0x{addr:x}"),
        Operand::Memory(mem) => render_memory(mem),
        Operand::Condition(cond) => cond.clone(),
    }
}

fn render_memory(mem: &MemoryOperand) -> String {
    let mut parts = Vec::new();
    if let Some(base) = &mem.base {
        parts.push(base.name.clone());
    }
    if let Some(index) = &mem.index {
        if mem.scale > 1 {
            parts.push(format!("{}*{}", index.name, mem.scale));
        } else {
            parts.push(index.name.clone());
        }
    }
    if mem.offset > 0 {
        parts.push(format!("0x{:x}", mem.offset));
    } else if mem.offset < 0 {
        parts.push(format!("-0x{:x}", mem.offset.unsigned_abs()));
    }
    if parts.is_empty() {
        "[0x0]".to_string()
    } else {
        format!("[{}]", parts.join("+"))
    }
}
```

Create `crates/urdisassembly/src/arch/x86_64/decode.rs`:

```rust
use crate::{
    arch::x86_64::format::render_instruction,
    error::{DecodeError, Result},
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

pub fn decode_instruction(bytes: &[u8], address: u64) -> Result<Instruction> {
    let first = *bytes.first().ok_or(DecodeError::TruncatedInstruction {
        expected: 1,
        actual: 0,
    })?;
    Ok(unknown(first, address))
}

fn base(
    bytes: Vec<u8>,
    address: u64,
    mnemonic: &str,
    operands: Vec<Operand>,
    kind: InstructionKind,
    flow: FlowKind,
    branch_target: Option<u64>,
    status: DecodeStatus,
) -> Instruction {
    Instruction {
        address,
        size: bytes.len() as u8,
        bytes,
        mnemonic: mnemonic.to_string(),
        text: render_instruction(mnemonic, &operands),
        operands,
        kind,
        flow,
        branch_target,
        status,
    }
}

fn unknown(byte: u8, address: u64) -> Instruction {
    base(
        vec![byte],
        address,
        ".byte",
        vec![Operand::Immediate(i64::from(byte))],
        InstructionKind::Unknown,
        FlowKind::Fallthrough,
        None,
        DecodeStatus::Unknown,
    )
}
```

- [ ] **Step 6: Dispatch x86-64 from `Decoder`**

In `crates/urdisassembly/src/decoder.rs`, import `x86_64` and update `new` and `decode_one`:

```rust
use crate::{
    arch::{aarch64, x86_64},
    error::{DecodeError, Result},
    model::{Architecture, DecodeOptions, Endian, Instruction},
};

impl Decoder {
    pub fn new(architecture: Architecture, options: DecodeOptions) -> Result<Self> {
        match (architecture, options.endian) {
            (Architecture::Aarch64 | Architecture::X86_64, Endian::Little) => Ok(Self {
                architecture,
                options,
            }),
        }
    }

    pub fn decode_one(&self, bytes: &[u8], address: u64) -> Result<Instruction> {
        match self.architecture {
            Architecture::Aarch64 => {
                let word = Self::require_word(bytes)?;
                Ok(aarch64::decode::decode_word(word, address))
            }
            Architecture::X86_64 => x86_64::decode::decode_instruction(bytes, address),
        }
    }
}
```

Keep the existing `architecture`, `options`, and `require_word` methods unchanged.

- [ ] **Step 7: Run focused tests**

Run:

```bash
cargo test -p urdisassembly --test x86_64_decode
cargo test -p urdisassembly --test aarch64_decode
```

Expected: both commands pass. AArch64 text output remains unchanged.

- [ ] **Step 8: Commit architecture plumbing**

Run:

```bash
git add crates/urdisassembly/src crates/urdisassembly/tests/x86_64_decode.rs
git commit -m "feat: add x86-64 decoder plumbing"
```

---

### Task 2: Decode X86-64 Branches And Calls

**Files:**
- Modify: `crates/urdisassembly/src/arch/x86_64/decode.rs`
- Modify: `crates/urdisassembly/tests/x86_64_decode.rs`

- [ ] **Step 1: Add failing branch and call golden tests**

Append to `crates/urdisassembly/tests/x86_64_decode.rs`:

```rust
#[test]
fn decodes_x86_64_returns_calls_and_jumps() {
    let ret = decode(&[0xc3], 0x401000);
    assert_eq!(ret.text, "ret");
    assert_eq!(ret.size, 1);
    assert_eq!(ret.kind, InstructionKind::Return);
    assert_eq!(ret.flow, FlowKind::Return);

    let call = decode(&[0xe8, 0x05, 0x00, 0x00, 0x00], 0x401000);
    assert_eq!(call.text, "call 0x40100a");
    assert_eq!(call.size, 5);
    assert_eq!(call.branch_target, Some(0x40100a));
    assert_eq!(call.flow, FlowKind::Call);

    let jmp_rel8 = decode(&[0xeb, 0x06], 0x401000);
    assert_eq!(jmp_rel8.text, "jmp 0x401008");
    assert_eq!(jmp_rel8.size, 2);
    assert_eq!(jmp_rel8.branch_target, Some(0x401008));
    assert_eq!(jmp_rel8.flow, FlowKind::Branch);

    let jmp_rel32 = decode(&[0xe9, 0xfb, 0xff, 0xff, 0xff], 0x401010);
    assert_eq!(jmp_rel32.text, "jmp 0x401010");
    assert_eq!(jmp_rel32.branch_target, Some(0x401010));
}

#[test]
fn decodes_x86_64_conditional_jumps() {
    let je = decode(&[0x74, 0x05], 0x401000);
    assert_eq!(je.text, "je 0x401007");
    assert_eq!(je.flow, FlowKind::ConditionalBranch);
    assert_eq!(je.branch_target, Some(0x401007));

    let jne = decode(&[0x0f, 0x85, 0x05, 0x00, 0x00, 0x00], 0x401000);
    assert_eq!(jne.text, "jne 0x40100b");
    assert_eq!(jne.size, 6);
    assert_eq!(jne.flow, FlowKind::ConditionalBranch);
    assert_eq!(jne.branch_target, Some(0x40100b));
}

#[test]
fn truncated_x86_64_relative_control_flow_is_an_error() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let err = decoder.decode_one(&[0xe8, 0x00], 0x401000).unwrap_err();
    assert_eq!(
        err,
        DecodeError::TruncatedInstruction {
            expected: 5,
            actual: 2,
        }
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cargo test -p urdisassembly --test x86_64_decode
```

Expected: branch and call assertions fail because the decoder still returns `.byte` unknown instructions.

- [ ] **Step 3: Add immediate readers and branch helpers**

In `crates/urdisassembly/src/arch/x86_64/decode.rs`, add:

```rust
fn require_len(bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() < expected {
        return Err(DecodeError::TruncatedInstruction {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn read_i8(bytes: &[u8], offset: usize) -> Result<i8> {
    require_len(bytes, offset + 1)?;
    Ok(bytes[offset] as i8)
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32> {
    require_len(bytes, offset + 4)?;
    Ok(i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn rel_target(address: u64, size: usize, displacement: i64) -> u64 {
    address.wrapping_add(size as u64).wrapping_add_signed(displacement)
}

fn absolute_target(target: u64) -> Vec<Operand> {
    vec![Operand::AbsoluteAddress(target)]
}

fn mnemonic_for_jcc(opcode: u8) -> &'static str {
    match opcode & 0x0f {
        0x0 => "jo",
        0x1 => "jno",
        0x2 => "jb",
        0x3 => "jae",
        0x4 => "je",
        0x5 => "jne",
        0x6 => "jbe",
        0x7 => "ja",
        0x8 => "js",
        0x9 => "jns",
        0xa => "jp",
        0xb => "jnp",
        0xc => "jl",
        0xd => "jge",
        0xe => "jle",
        _ => "jg",
    }
}
```

- [ ] **Step 4: Replace the x86-64 opcode dispatch for branches**

Update `decode_instruction` so it handles the branch opcodes before falling back to `unknown`:

```rust
pub fn decode_instruction(bytes: &[u8], address: u64) -> Result<Instruction> {
    let first = *bytes.first().ok_or(DecodeError::TruncatedInstruction {
        expected: 1,
        actual: 0,
    })?;
    match first {
        0xc3 => Ok(base(
            vec![0xc3],
            address,
            "ret",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
            DecodeStatus::Complete,
        )),
        0xe8 => {
            let disp = i64::from(read_i32(bytes, 1)?);
            let target = rel_target(address, 5, disp);
            Ok(base(
                bytes[..5].to_vec(),
                address,
                "call",
                absolute_target(target),
                InstructionKind::Call,
                FlowKind::Call,
                Some(target),
                DecodeStatus::Complete,
            ))
        }
        0xe9 => {
            let disp = i64::from(read_i32(bytes, 1)?);
            let target = rel_target(address, 5, disp);
            Ok(base(
                bytes[..5].to_vec(),
                address,
                "jmp",
                absolute_target(target),
                InstructionKind::Branch,
                FlowKind::Branch,
                Some(target),
                DecodeStatus::Complete,
            ))
        }
        0xeb => {
            let disp = i64::from(read_i8(bytes, 1)?);
            let target = rel_target(address, 2, disp);
            Ok(base(
                bytes[..2].to_vec(),
                address,
                "jmp",
                absolute_target(target),
                InstructionKind::Branch,
                FlowKind::Branch,
                Some(target),
                DecodeStatus::Complete,
            ))
        }
        0x70..=0x7f => {
            let disp = i64::from(read_i8(bytes, 1)?);
            let target = rel_target(address, 2, disp);
            Ok(base(
                bytes[..2].to_vec(),
                address,
                mnemonic_for_jcc(first),
                absolute_target(target),
                InstructionKind::Branch,
                FlowKind::ConditionalBranch,
                Some(target),
                DecodeStatus::Complete,
            ))
        }
        0x0f => {
            require_len(bytes, 2)?;
            let second = bytes[1];
            if (0x80..=0x8f).contains(&second) {
                let disp = i64::from(read_i32(bytes, 2)?);
                let target = rel_target(address, 6, disp);
                Ok(base(
                    bytes[..6].to_vec(),
                    address,
                    mnemonic_for_jcc(second),
                    absolute_target(target),
                    InstructionKind::Branch,
                    FlowKind::ConditionalBranch,
                    Some(target),
                    DecodeStatus::Complete,
                ))
            } else {
                Ok(unknown(first, address))
            }
        }
        _ => Ok(unknown(first, address)),
    }
}
```

- [ ] **Step 5: Run the focused tests**

Run:

```bash
cargo test -p urdisassembly --test x86_64_decode
```

Expected: all x86-64 tests pass.

- [ ] **Step 6: Commit branch decode**

Run:

```bash
git add crates/urdisassembly/src/arch/x86_64/decode.rs crates/urdisassembly/tests/x86_64_decode.rs
git commit -m "feat: decode x86-64 branches and calls"
```

---

### Task 3: Decode X86-64 Registers, ModRM, SIB, Moves, And LEA

**Files:**
- Modify: `crates/urdisassembly/src/arch/x86_64/decode.rs`
- Modify: `crates/urdisassembly/src/arch/x86_64/registers.rs`
- Modify: `crates/urdisassembly/src/arch/x86_64/format.rs`
- Modify: `crates/urdisassembly/tests/x86_64_decode.rs`

- [ ] **Step 1: Add failing x86-64 data movement tests**

Append to `crates/urdisassembly/tests/x86_64_decode.rs`:

```rust
use urdisassembly::{MemoryOperand, Operand};

fn register_name(operand: &Operand) -> &str {
    match operand {
        Operand::Register(reg) => &reg.name,
        other => panic!("expected register operand, got {other:?}"),
    }
}

fn memory_operand(operand: &Operand) -> &MemoryOperand {
    match operand {
        Operand::Memory(mem) => mem,
        other => panic!("expected memory operand, got {other:?}"),
    }
}

#[test]
fn decodes_x86_64_mov_register_forms() {
    let mov_imm = decode(
        &[0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        0x401000,
    );
    assert_eq!(mov_imm.text, "mov rax, 0x1122334455667788");
    assert_eq!(mov_imm.size, 10);
    assert_eq!(mov_imm.kind, InstructionKind::Move);
    assert_eq!(register_name(&mov_imm.operands[0]), "rax");

    let mov_reg = decode(&[0x48, 0x89, 0xd8], 0x401000);
    assert_eq!(mov_reg.text, "mov rax, rbx");
    assert_eq!(mov_reg.size, 3);
    assert_eq!(register_name(&mov_reg.operands[0]), "rax");
    assert_eq!(register_name(&mov_reg.operands[1]), "rbx");

    let mov_r8 = decode(&[0x4d, 0x89, 0xc8], 0x401000);
    assert_eq!(mov_r8.text, "mov r8, r9");
    assert_eq!(register_name(&mov_r8.operands[0]), "r8");
    assert_eq!(register_name(&mov_r8.operands[1]), "r9");
}

#[test]
fn decodes_x86_64_memory_moves_and_lea() {
    let load = decode(&[0x48, 0x8b, 0x43, 0x08], 0x401000);
    assert_eq!(load.text, "mov rax, [rbx+0x8]");
    assert_eq!(load.kind, InstructionKind::Load);
    let mem = memory_operand(&load.operands[1]);
    assert_eq!(mem.base.as_ref().unwrap().name, "rbx");
    assert_eq!(mem.offset, 8);
    assert_eq!(mem.width_bits, Some(64));

    let store = decode(&[0x48, 0x89, 0x43, 0x08], 0x401000);
    assert_eq!(store.text, "mov [rbx+0x8], rax");
    assert_eq!(store.kind, InstructionKind::Store);

    let lea = decode(&[0x48, 0x8d, 0x44, 0x8b, 0x10], 0x401000);
    assert_eq!(lea.text, "lea rax, [rbx+rcx*4+0x10]");
    let mem = memory_operand(&lea.operands[1]);
    assert_eq!(mem.base.as_ref().unwrap().name, "rbx");
    assert_eq!(mem.index.as_ref().unwrap().name, "rcx");
    assert_eq!(mem.scale, 4);
    assert_eq!(mem.offset, 0x10);

    let rip = decode(&[0x48, 0x8b, 0x05, 0x34, 0x12, 0x00, 0x00], 0x401000);
    assert_eq!(rip.text, "mov rax, [rip+0x1234]");
    let mem = memory_operand(&rip.operands[1]);
    assert!(mem.relative);
    assert_eq!(mem.offset, 0x1234);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cargo test -p urdisassembly --test x86_64_decode
```

Expected: new data movement assertions fail because register and ModRM/SIB decoding is not implemented.

- [ ] **Step 3: Add REX and ModRM data structures**

In `crates/urdisassembly/src/arch/x86_64/decode.rs`, add:

```rust
#[derive(Debug, Clone, Copy, Default)]
struct Rex {
    w: bool,
    r: bool,
    x: bool,
    b: bool,
}

#[derive(Debug, Clone, Copy)]
struct Prefixes {
    rex: Rex,
    opcode_offset: usize,
}

#[derive(Debug, Clone, Copy)]
struct ModRm {
    mode: u8,
    reg: u8,
    rm: u8,
}

fn parse_prefixes(bytes: &[u8]) -> Result<Prefixes> {
    require_len(bytes, 1)?;
    let mut offset = 0;
    let mut rex = Rex::default();
    while offset < bytes.len() {
        let byte = bytes[offset];
        if (0x40..=0x4f).contains(&byte) {
            rex = Rex {
                w: byte & 0x08 != 0,
                r: byte & 0x04 != 0,
                x: byte & 0x02 != 0,
                b: byte & 0x01 != 0,
            };
            offset += 1;
        } else {
            break;
        }
    }
    if offset >= bytes.len() {
        return Err(DecodeError::TruncatedInstruction {
            expected: offset + 1,
            actual: bytes.len(),
        });
    }
    Ok(Prefixes {
        rex,
        opcode_offset: offset,
    })
}

fn parse_modrm(byte: u8) -> ModRm {
    ModRm {
        mode: byte >> 6,
        reg: (byte >> 3) & 0x07,
        rm: byte & 0x07,
    }
}

fn extend_reg(index: u8, extension: bool) -> u8 {
    index | if extension { 8 } else { 0 }
}
```

- [ ] **Step 4: Add x86 memory operand parsing**

In `crates/urdisassembly/src/arch/x86_64/decode.rs`, add:

```rust
use crate::arch::x86_64::registers::reg64;
use crate::model::MemoryOperand;

fn read_i32_as_i64(bytes: &[u8], offset: usize) -> Result<i64> {
    Ok(i64::from(read_i32(bytes, offset)?))
}

fn parse_rm_operand(
    bytes: &[u8],
    modrm_offset: usize,
    rex: Rex,
    width_bits: u16,
) -> Result<(Operand, usize)> {
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let mut consumed = modrm_offset + 1;
    if modrm.mode == 0b11 {
        let reg = reg64(extend_reg(modrm.rm, rex.b));
        return Ok((Operand::Register(reg), consumed));
    }

    let mut base = None;
    let mut index = None;
    let mut scale = 1u8;
    let mut offset = 0i64;
    let mut relative = false;

    if modrm.rm == 0b100 {
        require_len(bytes, consumed + 1)?;
        let sib = bytes[consumed];
        consumed += 1;
        scale = 1u8 << (sib >> 6);
        let sib_index = (sib >> 3) & 0x07;
        let sib_base = sib & 0x07;
        if sib_index != 0b100 {
            index = Some(reg64(extend_reg(sib_index, rex.x)));
        }
        if modrm.mode == 0 && sib_base == 0b101 {
            offset = read_i32_as_i64(bytes, consumed)?;
            consumed += 4;
        } else {
            base = Some(reg64(extend_reg(sib_base, rex.b)));
        }
    } else if modrm.mode == 0 && modrm.rm == 0b101 {
        relative = true;
        base = Some(reg64(16));
        offset = read_i32_as_i64(bytes, consumed)?;
        consumed += 4;
    } else {
        base = Some(reg64(extend_reg(modrm.rm, rex.b)));
    }

    match modrm.mode {
        0 => {}
        1 => {
            offset = i64::from(read_i8(bytes, consumed)?);
            consumed += 1;
        }
        2 => {
            offset = read_i32_as_i64(bytes, consumed)?;
            consumed += 4;
        }
        _ => {}
    }

    let mut mem = if relative {
        MemoryOperand::rip_relative(offset, Some(width_bits))
    } else {
        MemoryOperand::indexed(base, index, scale, offset, Some(width_bits))
    };
    mem.relative = relative;
    Ok((Operand::Memory(mem), consumed))
}
```

Update `reg64` in `crates/urdisassembly/src/arch/x86_64/registers.rs` so index `16` returns `rip`:

```rust
16 => "rip",
```

- [ ] **Step 5: Add move and LEA opcode handling**

In `decode_instruction`, parse prefixes first and dispatch on the opcode at `prefixes.opcode_offset`. Preserve the branch opcodes from Task 2 by moving their match arms into the prefixed dispatch. Add these cases:

```rust
let prefixes = parse_prefixes(bytes)?;
let opcode_offset = prefixes.opcode_offset;
let opcode = bytes[opcode_offset];
match opcode {
    0xb8..=0xbf if prefixes.rex.w => {
        require_len(bytes, opcode_offset + 9)?;
        let dst = reg64(extend_reg(opcode - 0xb8, prefixes.rex.b));
        let imm = u64::from_le_bytes([
            bytes[opcode_offset + 1],
            bytes[opcode_offset + 2],
            bytes[opcode_offset + 3],
            bytes[opcode_offset + 4],
            bytes[opcode_offset + 5],
            bytes[opcode_offset + 6],
            bytes[opcode_offset + 7],
            bytes[opcode_offset + 8],
        ]);
        Ok(base(
            bytes[..opcode_offset + 9].to_vec(),
            address,
            "mov",
            vec![Operand::Register(dst), Operand::Immediate(imm as i64)],
            InstructionKind::Move,
            FlowKind::Fallthrough,
            None,
            DecodeStatus::Complete,
        ))
    }
    0x89 | 0x8b | 0x8d => {
        let modrm_offset = opcode_offset + 1;
        require_len(bytes, modrm_offset + 1)?;
        let modrm = parse_modrm(bytes[modrm_offset]);
        let reg = Operand::Register(reg64(extend_reg(modrm.reg, prefixes.rex.r)));
        let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
        let operands = match opcode {
            0x89 => vec![rm.clone(), reg],
            0x8b | 0x8d => vec![reg, rm.clone()],
            _ => Vec::new(),
        };
        let kind = match opcode {
            0x8d => InstructionKind::Address,
            0x89 if matches!(rm, Operand::Memory(_)) => InstructionKind::Store,
            0x8b if matches!(rm, Operand::Memory(_)) => InstructionKind::Load,
            _ => InstructionKind::Move,
        };
        Ok(base(
            bytes[..consumed].to_vec(),
            address,
            if opcode == 0x8d { "lea" } else { "mov" },
            operands,
            kind,
            FlowKind::Fallthrough,
            None,
            DecodeStatus::Complete,
        ))
    }
    _ => {
        let first = bytes[opcode_offset];
        Ok(unknown(first, address))
    }
}
```

When integrating this snippet, keep the Task 2 branch cases in the same `match opcode`, and make every match arm return `Result<Instruction>` with `Ok(base(...))`, a helper result, or `Ok(unknown(...))`.

- [ ] **Step 6: Run focused tests**

Run:

```bash
cargo test -p urdisassembly --test x86_64_decode
```

Expected: all x86-64 tests pass.

- [ ] **Step 7: Commit data movement decode**

Run:

```bash
git add crates/urdisassembly/src/arch/x86_64 crates/urdisassembly/tests/x86_64_decode.rs
git commit -m "feat: decode x86-64 data movement forms"
```

---

### Task 4: Decode X86-64 Arithmetic, Logical, And Stack Forms

**Files:**
- Modify: `crates/urdisassembly/src/arch/x86_64/decode.rs`
- Modify: `crates/urdisassembly/tests/x86_64_decode.rs`

- [ ] **Step 1: Add failing arithmetic, logical, and stack tests**

Append to `crates/urdisassembly/tests/x86_64_decode.rs`:

```rust
#[test]
fn decodes_x86_64_arithmetic_and_logical_forms() {
    let add_imm = decode(&[0x48, 0x83, 0xc0, 0x08], 0x401000);
    assert_eq!(add_imm.text, "add rax, 0x8");
    assert_eq!(add_imm.kind, InstructionKind::Arithmetic);

    let sub_reg = decode(&[0x48, 0x29, 0xd8], 0x401000);
    assert_eq!(sub_reg.text, "sub rax, rbx");
    assert_eq!(sub_reg.kind, InstructionKind::Arithmetic);

    let cmp_reg = decode(&[0x48, 0x39, 0xd8], 0x401000);
    assert_eq!(cmp_reg.text, "cmp rax, rbx");
    assert_eq!(cmp_reg.kind, InstructionKind::Compare);

    let test_reg = decode(&[0x48, 0x85, 0xc0], 0x401000);
    assert_eq!(test_reg.text, "test rax, rax");
    assert_eq!(test_reg.kind, InstructionKind::Compare);

    let xor_reg = decode(&[0x48, 0x31, 0xc0], 0x401000);
    assert_eq!(xor_reg.text, "xor rax, rax");
    assert_eq!(xor_reg.kind, InstructionKind::Logical);
}

#[test]
fn decodes_x86_64_push_and_pop() {
    let push = decode(&[0x50], 0x401000);
    assert_eq!(push.text, "push rax");
    assert_eq!(push.kind, InstructionKind::Store);

    let pop = decode(&[0x58], 0x401000);
    assert_eq!(pop.text, "pop rax");
    assert_eq!(pop.kind, InstructionKind::Load);

    let push_r8 = decode(&[0x41, 0x50], 0x401000);
    assert_eq!(push_r8.text, "push r8");
    assert_eq!(push_r8.size, 2);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cargo test -p urdisassembly --test x86_64_decode
```

Expected: new arithmetic, logical, and stack assertions fail because these opcodes still decode as unknown.

- [ ] **Step 3: Add binary operation helpers**

In `crates/urdisassembly/src/arch/x86_64/decode.rs`, add:

```rust
fn decode_reg_rm_binary(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    mnemonic: &str,
    kind: InstructionKind,
    reg_is_dst: bool,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(reg64(extend_reg(modrm.reg, prefixes.rex.r)));
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
    let operands = if reg_is_dst {
        vec![reg, rm]
    } else {
        vec![rm, reg]
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        operands,
        kind,
        FlowKind::Fallthrough,
        None,
        DecodeStatus::Complete,
    ))
}

fn decode_group83(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 2)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed_without_imm) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
    let imm = i64::from(read_i8(bytes, consumed_without_imm)?);
    let consumed = consumed_without_imm + 1;
    let (mnemonic, kind) = match modrm.reg {
        0 => ("add", InstructionKind::Arithmetic),
        5 => ("sub", InstructionKind::Arithmetic),
        7 => ("cmp", InstructionKind::Compare),
        _ => {
            return Ok(unknown(bytes[prefixes.opcode_offset], address));
        }
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![rm, Operand::Immediate(imm)],
        kind,
        FlowKind::Fallthrough,
        None,
        DecodeStatus::Complete,
    ))
}
```

- [ ] **Step 4: Add opcode cases for arithmetic, logical, push, and pop**

In the x86-64 opcode `match`, add:

```rust
0x01 => decode_reg_rm_binary(bytes, address, prefixes, "add", InstructionKind::Arithmetic, false),
0x03 => decode_reg_rm_binary(bytes, address, prefixes, "add", InstructionKind::Arithmetic, true),
0x29 => decode_reg_rm_binary(bytes, address, prefixes, "sub", InstructionKind::Arithmetic, false),
0x2b => decode_reg_rm_binary(bytes, address, prefixes, "sub", InstructionKind::Arithmetic, true),
0x21 => decode_reg_rm_binary(bytes, address, prefixes, "and", InstructionKind::Logical, false),
0x23 => decode_reg_rm_binary(bytes, address, prefixes, "and", InstructionKind::Logical, true),
0x09 => decode_reg_rm_binary(bytes, address, prefixes, "or", InstructionKind::Logical, false),
0x0b => decode_reg_rm_binary(bytes, address, prefixes, "or", InstructionKind::Logical, true),
0x31 => decode_reg_rm_binary(bytes, address, prefixes, "xor", InstructionKind::Logical, false),
0x33 => decode_reg_rm_binary(bytes, address, prefixes, "xor", InstructionKind::Logical, true),
0x39 => decode_reg_rm_binary(bytes, address, prefixes, "cmp", InstructionKind::Compare, false),
0x3b => decode_reg_rm_binary(bytes, address, prefixes, "cmp", InstructionKind::Compare, true),
0x85 => decode_reg_rm_binary(bytes, address, prefixes, "test", InstructionKind::Compare, false),
0x83 => decode_group83(bytes, address, prefixes),
0x50..=0x57 => Ok(base(
    bytes[..prefixes.opcode_offset + 1].to_vec(),
    address,
    "push",
    vec![Operand::Register(reg64(extend_reg(opcode - 0x50, prefixes.rex.b)))],
    InstructionKind::Store,
    FlowKind::Fallthrough,
    None,
    DecodeStatus::Complete,
)),
0x58..=0x5f => Ok(base(
    bytes[..prefixes.opcode_offset + 1].to_vec(),
    address,
    "pop",
    vec![Operand::Register(reg64(extend_reg(opcode - 0x58, prefixes.rex.b)))],
    InstructionKind::Load,
    FlowKind::Fallthrough,
    None,
    DecodeStatus::Complete,
)),
```

- [ ] **Step 5: Run x86-64 tests**

Run:

```bash
cargo test -p urdisassembly --test x86_64_decode
```

Expected: all x86-64 tests pass.

- [ ] **Step 6: Run full urdisassembly tests**

Run:

```bash
cargo test -p urdisassembly
```

Expected: all `urdisassembly` tests pass, including existing AArch64 tests.

- [ ] **Step 7: Commit arithmetic decode**

Run:

```bash
git add crates/urdisassembly/src/arch/x86_64/decode.rs crates/urdisassembly/tests/x86_64_decode.rs
git commit -m "feat: decode x86-64 arithmetic and stack forms"
```

---

### Task 5: Add Urdis2il Crate And IL Model

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/urdis2il/Cargo.toml`
- Create: `crates/urdis2il/src/lib.rs`
- Create: `crates/urdis2il/src/error.rs`
- Create: `crates/urdis2il/src/model.rs`
- Create: `crates/urdis2il/src/lifter.rs`
- Create: `crates/urdis2il/src/aarch64.rs`
- Create: `crates/urdis2il/src/x86_64.rs`
- Create: `crates/urdis2il/src/operand.rs`
- Create: `crates/urdis2il/tests/model.rs`

- [ ] **Step 1: Add failing IL model tests**

Create `crates/urdis2il/tests/model.rs`:

```rust
use urdis2il::{
    IlExpr, IlLocation, IlReg, IlStmt, Lifter,
};
use urdisassembly::{
    Architecture, DecodeOptions, DecodeStatus, Decoder, FlowKind, InstructionKind,
};

#[test]
fn il_registers_are_scoped_by_architecture_and_width() {
    let aarch64_x0 = IlReg {
        arch: Architecture::Aarch64,
        name: "x0".to_string(),
        width_bits: 64,
    };
    let x86_rax = IlReg {
        arch: Architecture::X86_64,
        name: "rax".to_string(),
        width_bits: 64,
    };

    assert_ne!(aarch64_x0, x86_rax);
    assert_eq!(IlExpr::Reg(aarch64_x0.clone()), IlExpr::Reg(aarch64_x0));
}

#[test]
fn unknown_instruction_lifts_to_unsupported_statement() {
    let decoder = Decoder::new(Architecture::X86_64, DecodeOptions::default()).unwrap();
    let insn = decoder.decode_one(&[0xcc], 0x401000).unwrap();
    assert_eq!(insn.status, DecodeStatus::Unknown);
    assert_eq!(insn.kind, InstructionKind::Unknown);
    assert_eq!(insn.flow, FlowKind::Fallthrough);

    let lifter = Lifter::new(Architecture::X86_64);
    let lifted = lifter.lift_instruction(&insn).unwrap();

    assert_eq!(lifted.address, 0x401000);
    assert_eq!(lifted.size, 1);
    assert_eq!(lifted.terminator, None);
    assert_eq!(lifted.statements.len(), 1);
    match &lifted.statements[0] {
        IlStmt::Unsupported {
            address,
            mnemonic,
            reason,
        } => {
            assert_eq!(*address, 0x401000);
            assert_eq!(mnemonic, ".byte");
            assert!(reason.contains("unknown decode status"));
        }
        other => panic!("expected unsupported statement, got {other:?}"),
    }
}

#[test]
fn il_locations_can_target_registers() {
    let reg = IlReg {
        arch: Architecture::X86_64,
        name: "rax".to_string(),
        width_bits: 64,
    };
    let location = IlLocation::Reg(reg.clone());

    assert_eq!(location, IlLocation::Reg(reg));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cargo test -p urdis2il --test model
```

Expected: Cargo fails because package `urdis2il` does not exist.

- [ ] **Step 3: Add workspace member and manifest**

Modify root `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/urdisassembly",
    "crates/urdis2il",
    "crates/ura-core",
    "crates/ura-cli",
    "crates/ura-daemon",
]
resolver = "2"
```

Add a workspace dependency:

```toml
urdis2il = { path = "crates/urdis2il" }
```

Create `crates/urdis2il/Cargo.toml`:

```toml
[package]
name = "urdis2il"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
thiserror.workspace = true
serde.workspace = true
urdisassembly.workspace = true
```

- [ ] **Step 4: Add public exports and error type**

Create `crates/urdis2il/src/lib.rs`:

```rust
mod aarch64;
mod error;
mod lifter;
mod model;
mod operand;
mod x86_64;

pub use error::{LiftError, Result};
pub use lifter::Lifter;
pub use model::{
    IlBlock, IlExpr, IlFlag, IlFunction, IlInstruction, IlLocation, IlReg, IlStmt, IlTerminator,
};
```

Create `crates/urdis2il/src/error.rs`:

```rust
use thiserror::Error;

pub type Result<T> = std::result::Result<T, LiftError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LiftError {
    #[error("instruction architecture mismatch: lifter={lifter:?} instruction={instruction:?}")]
    ArchitectureMismatch {
        lifter: urdisassembly::Architecture,
        instruction: urdisassembly::Architecture,
    },
}
```

- [ ] **Step 5: Add the IL model**

Create `crates/urdis2il/src/model.rs` with the exact types from the spec:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlInstruction {
    pub address: u64,
    pub size: u8,
    pub statements: Vec<IlStmt>,
    pub terminator: Option<IlTerminator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlBlock {
    pub start: u64,
    pub instructions: Vec<IlInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlFunction {
    pub address: u64,
    pub blocks: Vec<IlBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlStmt {
    Assign { dst: IlLocation, src: IlExpr },
    Load { dst: IlLocation, address: IlExpr, size: u16 },
    Store { address: IlExpr, value: IlExpr, size: u16 },
    SetFlag { flag: IlFlag, value: IlExpr },
    Intrinsic { name: String, inputs: Vec<IlExpr>, outputs: Vec<IlLocation> },
    Unsupported { address: u64, mnemonic: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlLocation {
    Reg(IlReg),
    Flag(IlFlag),
    Temp(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlReg {
    pub arch: urdisassembly::Architecture,
    pub name: String,
    pub width_bits: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlFlag {
    pub arch: urdisassembly::Architecture,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlTerminator {
    Jump { target: IlExpr },
    Branch { condition: IlExpr, true_target: IlExpr, false_target: IlExpr },
    Call { target: IlExpr, return_address: Option<u64> },
    Return,
    Fallthrough { target: u64 },
    Unknown,
}
```

- [ ] **Step 6: Add lifter entrypoint with unsupported fallback**

Create `crates/urdis2il/src/lifter.rs`:

```rust
use crate::{
    model::{IlInstruction, IlStmt},
    Result,
};

#[derive(Debug, Clone, Copy)]
pub struct Lifter {
    architecture: urdisassembly::Architecture,
}

impl Lifter {
    pub fn new(architecture: urdisassembly::Architecture) -> Self {
        Self { architecture }
    }

    pub fn architecture(&self) -> urdisassembly::Architecture {
        self.architecture
    }

    pub fn lift_instruction(
        &self,
        instruction: &urdisassembly::Instruction,
    ) -> Result<IlInstruction> {
        if instruction.status != urdisassembly::DecodeStatus::Complete {
            return Ok(unsupported_instruction(
                instruction,
                "unknown decode status",
            ));
        }
        match self.architecture {
            urdisassembly::Architecture::Aarch64 => crate::aarch64::lift(instruction),
            urdisassembly::Architecture::X86_64 => crate::x86_64::lift(instruction),
        }
    }
}

pub(crate) fn unsupported_instruction(
    instruction: &urdisassembly::Instruction,
    reason: &str,
) -> IlInstruction {
    IlInstruction {
        address: instruction.address,
        size: instruction.size,
        statements: vec![IlStmt::Unsupported {
            address: instruction.address,
            mnemonic: instruction.mnemonic.clone(),
            reason: reason.to_string(),
        }],
        terminator: None,
    }
}
```

Create `crates/urdis2il/src/aarch64.rs`:

```rust
use crate::{lifter::unsupported_instruction, model::IlInstruction, Result};

pub(crate) fn lift(instruction: &urdisassembly::Instruction) -> Result<IlInstruction> {
    Ok(unsupported_instruction(
        instruction,
        "aarch64 lifting rule not implemented for mnemonic",
    ))
}
```

Create `crates/urdis2il/src/x86_64.rs`:

```rust
use crate::{lifter::unsupported_instruction, model::IlInstruction, Result};

pub(crate) fn lift(instruction: &urdisassembly::Instruction) -> Result<IlInstruction> {
    Ok(unsupported_instruction(
        instruction,
        "x86-64 lifting rule not implemented for mnemonic",
    ))
}
```

Create `crates/urdis2il/src/operand.rs`:

```rust
use crate::model::{IlExpr, IlReg};

pub(crate) fn reg_expr(arch: urdisassembly::Architecture, name: &str, width_bits: u16) -> IlExpr {
    IlExpr::Reg(IlReg {
        arch,
        name: name.to_string(),
        width_bits,
    })
}
```

- [ ] **Step 7: Run model tests**

Run:

```bash
cargo test -p urdis2il --test model
```

Expected: all model tests pass.

- [ ] **Step 8: Commit IL crate skeleton**

Run:

```bash
git add Cargo.toml crates/urdis2il
git commit -m "feat: add urdis2il il model"
```

---

### Task 6: Lift AArch64 Core Instructions

**Files:**
- Modify: `crates/urdis2il/src/aarch64.rs`
- Modify: `crates/urdis2il/src/operand.rs`
- Create: `crates/urdis2il/tests/aarch64_lift.rs`

- [ ] **Step 1: Add failing AArch64 lift tests**

Create `crates/urdis2il/tests/aarch64_lift.rs`:

```rust
use urdis2il::{IlExpr, IlFlag, IlLocation, IlReg, IlStmt, IlTerminator, Lifter};
use urdisassembly::{Architecture, DecodeOptions, Decoder};

fn decode(word: u32, address: u64) -> urdisassembly::Instruction {
    Decoder::new(Architecture::Aarch64, DecodeOptions::default())
        .unwrap()
        .decode_one(&word.to_le_bytes(), address)
        .unwrap()
}

fn lift(word: u32, address: u64) -> urdis2il::IlInstruction {
    let insn = decode(word, address);
    Lifter::new(Architecture::Aarch64)
        .lift_instruction(&insn)
        .unwrap()
}

fn reg(name: &str) -> IlLocation {
    IlLocation::Reg(IlReg {
        arch: Architecture::Aarch64,
        name: name.to_string(),
        width_bits: 64,
    })
}

fn reg_expr(name: &str) -> IlExpr {
    IlExpr::Reg(IlReg {
        arch: Architecture::Aarch64,
        name: name.to_string(),
        width_bits: 64,
    })
}

#[test]
fn lifts_aarch64_load_store_and_add() {
    let load = lift(0xf9400420, 0x400100);
    assert_eq!(
        load.statements[0],
        IlStmt::Load {
            dst: reg("x0"),
            address: IlExpr::Add(
                Box::new(reg_expr("x1")),
                Box::new(IlExpr::Const {
                    value: 8,
                    width_bits: 64,
                }),
            ),
            size: 64,
        }
    );

    let store = lift(0xf9000822, 0x400100);
    assert_eq!(
        store.statements[0],
        IlStmt::Store {
            address: IlExpr::Add(
                Box::new(reg_expr("x1")),
                Box::new(IlExpr::Const {
                    value: 0x10,
                    width_bits: 64,
                }),
            ),
            value: reg_expr("x2"),
            size: 64,
        }
    );

    let add = lift(0x91002000, 0x400100);
    assert_eq!(
        add.statements[0],
        IlStmt::Assign {
            dst: reg("x0"),
            src: IlExpr::Add(
                Box::new(reg_expr("x0")),
                Box::new(IlExpr::Const {
                    value: 8,
                    width_bits: 64,
                }),
            ),
        }
    );
}

#[test]
fn lifts_aarch64_compare_and_conditional_branch() {
    let cmp = lift(0xf100001f, 0x400100);
    assert!(cmp.statements.iter().any(|stmt| matches!(
        stmt,
        IlStmt::Intrinsic { name, .. } if name == "aarch64_sub_flags"
    )));

    let branch = lift(0x54000080, 0x400100);
    assert_eq!(
        branch.terminator,
        Some(IlTerminator::Branch {
            condition: IlExpr::Eq(
                Box::new(IlExpr::Flag(IlFlag {
                    arch: Architecture::Aarch64,
                    name: "z".to_string(),
                })),
                Box::new(IlExpr::Const {
                    value: 1,
                    width_bits: 1,
                }),
            ),
            true_target: IlExpr::Const {
                value: 0x400110,
                width_bits: 64,
            },
            false_target: IlExpr::Const {
                value: 0x400104,
                width_bits: 64,
            },
        })
    );
}

#[test]
fn lifts_aarch64_call_return_and_nop() {
    let call = lift(0x94000002, 0x400100);
    assert_eq!(
        call.terminator,
        Some(IlTerminator::Call {
            target: IlExpr::Const {
                value: 0x400108,
                width_bits: 64,
            },
            return_address: Some(0x400104),
        })
    );

    let ret = lift(0xd65f03c0, 0x400100);
    assert_eq!(ret.terminator, Some(IlTerminator::Return));

    let nop = lift(0xd503201f, 0x400100);
    assert!(nop.statements.is_empty());
    assert_eq!(
        nop.terminator,
        Some(IlTerminator::Fallthrough { target: 0x400104 })
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cargo test -p urdis2il --test aarch64_lift
```

Expected: assertions fail because AArch64 lifting still returns unsupported statements.

- [ ] **Step 3: Add operand conversion helpers**

In `crates/urdis2il/src/operand.rs`, replace the file with:

```rust
use crate::model::{IlExpr, IlLocation, IlReg};

pub(crate) fn reg_expr(arch: urdisassembly::Architecture, name: &str, width_bits: u16) -> IlExpr {
    IlExpr::Reg(IlReg {
        arch,
        name: name.to_string(),
        width_bits,
    })
}

pub(crate) fn reg_location(
    arch: urdisassembly::Architecture,
    name: &str,
    width_bits: u16,
) -> IlLocation {
    IlLocation::Reg(IlReg {
        arch,
        name: name.to_string(),
        width_bits,
    })
}

pub(crate) fn const_expr(value: u64, width_bits: u16) -> IlExpr {
    IlExpr::Const { value, width_bits }
}

pub(crate) fn memory_address(
    arch: urdisassembly::Architecture,
    mem: &urdisassembly::MemoryOperand,
) -> IlExpr {
    let base = mem
        .base
        .as_ref()
        .map(|reg| reg_expr(arch, &reg.name, 64));
    let index = mem.index.as_ref().map(|reg| {
        let expr = reg_expr(arch, &reg.name, 64);
        if mem.scale > 1 {
            IlExpr::Shl(
                Box::new(expr),
                Box::new(const_expr((mem.scale.trailing_zeros()) as u64, 8)),
            )
        } else {
            expr
        }
    });
    let displacement = if mem.offset == 0 {
        None
    } else {
        Some(const_expr(mem.offset as u64, 64))
    };
    [base, index, displacement]
        .into_iter()
        .flatten()
        .reduce(|lhs, rhs| IlExpr::Add(Box::new(lhs), Box::new(rhs)))
        .unwrap_or_else(|| const_expr(0, 64))
}
```

- [ ] **Step 4: Implement AArch64 lifting rules**

Replace `crates/urdis2il/src/aarch64.rs` with:

```rust
use crate::{
    lifter::unsupported_instruction,
    model::{IlExpr, IlFlag, IlInstruction, IlStmt, IlTerminator},
    operand::{const_expr, memory_address, reg_expr, reg_location},
    Result,
};

const ARCH: urdisassembly::Architecture = urdisassembly::Architecture::Aarch64;

pub(crate) fn lift(instruction: &urdisassembly::Instruction) -> Result<IlInstruction> {
    let mut statements = Vec::new();
    let mut terminator = None;
    match instruction.mnemonic.as_str() {
        "nop" => {
            terminator = Some(fallthrough(instruction));
        }
        "ldr" => {
            if let [urdisassembly::Operand::Register(dst), urdisassembly::Operand::Memory(mem)] =
                instruction.operands.as_slice()
            {
                statements.push(IlStmt::Load {
                    dst: reg_location(ARCH, &dst.name, 64),
                    address: memory_address(ARCH, mem),
                    size: mem.width_bits.unwrap_or(64),
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "str" => {
            if let [urdisassembly::Operand::Register(src), urdisassembly::Operand::Memory(mem)] =
                instruction.operands.as_slice()
            {
                statements.push(IlStmt::Store {
                    address: memory_address(ARCH, mem),
                    value: reg_expr(ARCH, &src.name, 64),
                    size: mem.width_bits.unwrap_or(64),
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "add" | "sub" | "and" | "orr" | "eor" => {
            if let [
                urdisassembly::Operand::Register(dst),
                urdisassembly::Operand::Register(lhs),
                rhs,
            ] = instruction.operands.as_slice()
            {
                let rhs_expr = operand_expr(rhs);
                let lhs_expr = reg_expr(ARCH, &lhs.name, 64);
                let src = match instruction.mnemonic.as_str() {
                    "add" => IlExpr::Add(Box::new(lhs_expr), Box::new(rhs_expr)),
                    "sub" => IlExpr::Sub(Box::new(lhs_expr), Box::new(rhs_expr)),
                    "and" => IlExpr::And(Box::new(lhs_expr), Box::new(rhs_expr)),
                    "orr" => IlExpr::Or(Box::new(lhs_expr), Box::new(rhs_expr)),
                    _ => IlExpr::Xor(Box::new(lhs_expr), Box::new(rhs_expr)),
                };
                statements.push(IlStmt::Assign {
                    dst: reg_location(ARCH, &dst.name, 64),
                    src,
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "mov" | "movk" | "movn" => {
            if let [urdisassembly::Operand::Register(dst), src] = instruction.operands.as_slice() {
                statements.push(IlStmt::Assign {
                    dst: reg_location(ARCH, &dst.name, 64),
                    src: operand_expr(src),
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "adr" | "adrp" => {
            if let [
                urdisassembly::Operand::Register(dst),
                urdisassembly::Operand::AbsoluteAddress(addr),
            ] = instruction.operands.as_slice()
            {
                statements.push(IlStmt::Assign {
                    dst: reg_location(ARCH, &dst.name, 64),
                    src: const_expr(*addr, 64),
                });
                terminator = Some(fallthrough(instruction));
            }
        }
        "cmp" | "cmn" => {
            statements.push(IlStmt::Intrinsic {
                name: if instruction.mnemonic == "cmp" {
                    "aarch64_sub_flags".to_string()
                } else {
                    "aarch64_add_flags".to_string()
                },
                inputs: instruction.operands.iter().map(operand_expr).collect(),
                outputs: ["n", "z", "c", "v"]
                    .iter()
                    .map(|name| crate::model::IlLocation::Flag(flag(name)))
                    .collect(),
            });
            terminator = Some(fallthrough(instruction));
        }
        "b" => {
            if let Some(target) = instruction.branch_target {
                terminator = Some(IlTerminator::Jump {
                    target: const_expr(target, 64),
                });
            }
        }
        "bl" | "blr" => {
            terminator = Some(IlTerminator::Call {
                target: target_expr(instruction),
                return_address: Some(instruction.address + u64::from(instruction.size)),
            });
        }
        "ret" => {
            terminator = Some(IlTerminator::Return);
        }
        mnemonic if mnemonic.starts_with("b.") => {
            if let Some(target) = instruction.branch_target {
                terminator = Some(IlTerminator::Branch {
                    condition: condition_expr(mnemonic.trim_start_matches("b.")),
                    true_target: const_expr(target, 64),
                    false_target: const_expr(instruction.address + u64::from(instruction.size), 64),
                });
            }
        }
        _ => {
            return Ok(unsupported_instruction(
                instruction,
                "aarch64 lifting rule not implemented for mnemonic",
            ));
        }
    }

    if terminator.is_none() && statements.is_empty() {
        return Ok(unsupported_instruction(
            instruction,
            "aarch64 operands did not match lifting rule",
        ));
    }

    Ok(IlInstruction {
        address: instruction.address,
        size: instruction.size,
        statements,
        terminator,
    })
}

fn operand_expr(operand: &urdisassembly::Operand) -> IlExpr {
    match operand {
        urdisassembly::Operand::Register(reg) => reg_expr(ARCH, &reg.name, 64),
        urdisassembly::Operand::Immediate(value) => const_expr(*value as u64, 64),
        urdisassembly::Operand::AbsoluteAddress(addr) => const_expr(*addr, 64),
        urdisassembly::Operand::Memory(mem) => memory_address(ARCH, mem),
        urdisassembly::Operand::Condition(cond) => const_expr(condition_code(cond), 4),
    }
}

fn target_expr(instruction: &urdisassembly::Instruction) -> IlExpr {
    instruction
        .branch_target
        .map(|target| const_expr(target, 64))
        .unwrap_or(IlExpr::Reg(crate::model::IlReg {
            arch: ARCH,
            name: "unknown_target".to_string(),
            width_bits: 64,
        }))
}

fn fallthrough(instruction: &urdisassembly::Instruction) -> IlTerminator {
    IlTerminator::Fallthrough {
        target: instruction.address + u64::from(instruction.size),
    }
}

fn flag(name: &str) -> IlFlag {
    IlFlag {
        arch: ARCH,
        name: name.to_string(),
    }
}

fn condition_expr(cond: &str) -> IlExpr {
    match cond {
        "eq" => IlExpr::Eq(
            Box::new(IlExpr::Flag(flag("z"))),
            Box::new(const_expr(1, 1)),
        ),
        "ne" => IlExpr::Eq(
            Box::new(IlExpr::Flag(flag("z"))),
            Box::new(const_expr(0, 1)),
        ),
        _ => IlExpr::Flag(flag(cond)),
    }
}

fn condition_code(cond: &str) -> u64 {
    match cond {
        "eq" => 0,
        "ne" => 1,
        "cs" => 2,
        "cc" => 3,
        "mi" => 4,
        "pl" => 5,
        "vs" => 6,
        "vc" => 7,
        "hi" => 8,
        "ls" => 9,
        "ge" => 10,
        "lt" => 11,
        "gt" => 12,
        "le" => 13,
        _ => 14,
    }
}
```

- [ ] **Step 5: Run AArch64 lifter tests**

Run:

```bash
cargo test -p urdis2il --test aarch64_lift
```

Expected: all AArch64 lifter tests pass.

- [ ] **Step 6: Commit AArch64 lifter**

Run:

```bash
git add crates/urdis2il/src/aarch64.rs crates/urdis2il/src/operand.rs crates/urdis2il/tests/aarch64_lift.rs
git commit -m "feat: lift aarch64 instructions to il"
```

---

### Task 7: Lift X86-64 Core Instructions

**Files:**
- Modify: `crates/urdis2il/src/x86_64.rs`
- Create: `crates/urdis2il/tests/x86_64_lift.rs`

- [ ] **Step 1: Add failing x86-64 lift tests**

Create `crates/urdis2il/tests/x86_64_lift.rs`:

```rust
use urdis2il::{IlExpr, IlFlag, IlLocation, IlReg, IlStmt, IlTerminator, Lifter};
use urdisassembly::{Architecture, DecodeOptions, Decoder};

fn decode(bytes: &[u8], address: u64) -> urdisassembly::Instruction {
    Decoder::new(Architecture::X86_64, DecodeOptions::default())
        .unwrap()
        .decode_one(bytes, address)
        .unwrap()
}

fn lift(bytes: &[u8], address: u64) -> urdis2il::IlInstruction {
    let insn = decode(bytes, address);
    Lifter::new(Architecture::X86_64)
        .lift_instruction(&insn)
        .unwrap()
}

fn reg(name: &str) -> IlLocation {
    IlLocation::Reg(IlReg {
        arch: Architecture::X86_64,
        name: name.to_string(),
        width_bits: 64,
    })
}

fn reg_expr(name: &str) -> IlExpr {
    IlExpr::Reg(IlReg {
        arch: Architecture::X86_64,
        name: name.to_string(),
        width_bits: 64,
    })
}

#[test]
fn lifts_x86_64_mov_load_store_and_lea() {
    let load = lift(&[0x48, 0x8b, 0x43, 0x08], 0x401000);
    assert_eq!(
        load.statements[0],
        IlStmt::Load {
            dst: reg("rax"),
            address: IlExpr::Add(
                Box::new(reg_expr("rbx")),
                Box::new(IlExpr::Const {
                    value: 8,
                    width_bits: 64,
                }),
            ),
            size: 64,
        }
    );

    let store = lift(&[0x48, 0x89, 0x43, 0x08], 0x401000);
    assert_eq!(
        store.statements[0],
        IlStmt::Store {
            address: IlExpr::Add(
                Box::new(reg_expr("rbx")),
                Box::new(IlExpr::Const {
                    value: 8,
                    width_bits: 64,
                }),
            ),
            value: reg_expr("rax"),
            size: 64,
        }
    );

    let lea = lift(&[0x48, 0x8d, 0x44, 0x8b, 0x10], 0x401000);
    assert!(matches!(lea.statements[0], IlStmt::Assign { .. }));
}

#[test]
fn lifts_x86_64_cmp_and_conditional_jump() {
    let cmp = lift(&[0x48, 0x83, 0xf8, 0x00], 0x401000);
    assert!(cmp.statements.iter().any(|stmt| matches!(
        stmt,
        IlStmt::Intrinsic { name, .. } if name == "x86_sub_flags"
    )));

    let je = lift(&[0x74, 0x05], 0x401004);
    assert_eq!(
        je.terminator,
        Some(IlTerminator::Branch {
            condition: IlExpr::Eq(
                Box::new(IlExpr::Flag(IlFlag {
                    arch: Architecture::X86_64,
                    name: "zf".to_string(),
                })),
                Box::new(IlExpr::Const {
                    value: 1,
                    width_bits: 1,
                }),
            ),
            true_target: IlExpr::Const {
                value: 0x40100b,
                width_bits: 64,
            },
            false_target: IlExpr::Const {
                value: 0x401006,
                width_bits: 64,
            },
        })
    );
}

#[test]
fn lifts_x86_64_call_return_push_and_pop() {
    let call = lift(&[0xe8, 0x05, 0x00, 0x00, 0x00], 0x401000);
    assert_eq!(
        call.terminator,
        Some(IlTerminator::Call {
            target: IlExpr::Const {
                value: 0x40100a,
                width_bits: 64,
            },
            return_address: Some(0x401005),
        })
    );

    let ret = lift(&[0xc3], 0x401000);
    assert_eq!(ret.terminator, Some(IlTerminator::Return));

    let push = lift(&[0x50], 0x401000);
    assert!(push.statements.iter().any(|stmt| matches!(stmt, IlStmt::Store { .. })));

    let pop = lift(&[0x58], 0x401000);
    assert!(pop.statements.iter().any(|stmt| matches!(stmt, IlStmt::Load { .. })));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
cargo test -p urdis2il --test x86_64_lift
```

Expected: assertions fail because x86-64 lifting still returns unsupported statements.

- [ ] **Step 3: Implement x86-64 lifting rules**

Replace `crates/urdis2il/src/x86_64.rs` with:

```rust
use crate::{
    lifter::unsupported_instruction,
    model::{IlExpr, IlFlag, IlInstruction, IlLocation, IlReg, IlStmt, IlTerminator},
    operand::{const_expr, memory_address, reg_expr, reg_location},
    Result,
};

const ARCH: urdisassembly::Architecture = urdisassembly::Architecture::X86_64;

pub(crate) fn lift(instruction: &urdisassembly::Instruction) -> Result<IlInstruction> {
    let mut statements = Vec::new();
    let mut terminator = None;
    match instruction.mnemonic.as_str() {
        "mov" => lift_mov(instruction, &mut statements),
        "lea" => lift_lea(instruction, &mut statements),
        "add" | "sub" | "and" | "or" | "xor" => {
            lift_assignment_op(instruction, &mut statements);
            lift_flags(instruction, &mut statements);
        }
        "cmp" | "test" => lift_flags(instruction, &mut statements),
        "push" => lift_push(instruction, &mut statements),
        "pop" => lift_pop(instruction, &mut statements),
        "jmp" => {
            terminator = Some(IlTerminator::Jump {
                target: target_expr(instruction),
            });
        }
        "call" => {
            terminator = Some(IlTerminator::Call {
                target: target_expr(instruction),
                return_address: Some(instruction.address + u64::from(instruction.size)),
            });
        }
        "ret" => {
            terminator = Some(IlTerminator::Return);
        }
        mnemonic if is_jcc(mnemonic) => {
            if let Some(target) = instruction.branch_target {
                terminator = Some(IlTerminator::Branch {
                    condition: condition_expr(mnemonic),
                    true_target: const_expr(target, 64),
                    false_target: const_expr(instruction.address + u64::from(instruction.size), 64),
                });
            }
        }
        _ => {
            return Ok(unsupported_instruction(
                instruction,
                "x86-64 lifting rule not implemented for mnemonic",
            ));
        }
    }

    if terminator.is_none() && statements.is_empty() {
        terminator = Some(IlTerminator::Fallthrough {
            target: instruction.address + u64::from(instruction.size),
        });
    } else if terminator.is_none() {
        terminator = Some(IlTerminator::Fallthrough {
            target: instruction.address + u64::from(instruction.size),
        });
    }

    Ok(IlInstruction {
        address: instruction.address,
        size: instruction.size,
        statements,
        terminator,
    })
}

fn lift_mov(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    if let [dst, src] = instruction.operands.as_slice() {
        match (dst, src) {
            (urdisassembly::Operand::Register(dst), urdisassembly::Operand::Memory(mem)) => {
                statements.push(IlStmt::Load {
                    dst: reg_location(ARCH, &dst.name, 64),
                    address: memory_address(ARCH, mem),
                    size: mem.width_bits.unwrap_or(64),
                });
            }
            (urdisassembly::Operand::Memory(mem), urdisassembly::Operand::Register(src)) => {
                statements.push(IlStmt::Store {
                    address: memory_address(ARCH, mem),
                    value: reg_expr(ARCH, &src.name, 64),
                    size: mem.width_bits.unwrap_or(64),
                });
            }
            (urdisassembly::Operand::Register(dst), src) => {
                statements.push(IlStmt::Assign {
                    dst: reg_location(ARCH, &dst.name, 64),
                    src: operand_expr(src),
                });
            }
            _ => {}
        }
    }
}

fn lift_lea(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    if let [urdisassembly::Operand::Register(dst), urdisassembly::Operand::Memory(mem)] =
        instruction.operands.as_slice()
    {
        statements.push(IlStmt::Assign {
            dst: reg_location(ARCH, &dst.name, 64),
            src: memory_address(ARCH, mem),
        });
    }
}

fn lift_assignment_op(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    if let [urdisassembly::Operand::Register(dst), src] = instruction.operands.as_slice() {
        let lhs = reg_expr(ARCH, &dst.name, 64);
        let rhs = operand_expr(src);
        let expr = match instruction.mnemonic.as_str() {
            "add" => IlExpr::Add(Box::new(lhs), Box::new(rhs)),
            "sub" => IlExpr::Sub(Box::new(lhs), Box::new(rhs)),
            "and" => IlExpr::And(Box::new(lhs), Box::new(rhs)),
            "or" => IlExpr::Or(Box::new(lhs), Box::new(rhs)),
            _ => IlExpr::Xor(Box::new(lhs), Box::new(rhs)),
        };
        statements.push(IlStmt::Assign {
            dst: reg_location(ARCH, &dst.name, 64),
            src: expr,
        });
    }
}

fn lift_flags(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    let name = match instruction.mnemonic.as_str() {
        "add" => "x86_add_flags",
        "sub" | "cmp" => "x86_sub_flags",
        _ => "x86_logic_flags",
    };
    statements.push(IlStmt::Intrinsic {
        name: name.to_string(),
        inputs: instruction.operands.iter().map(operand_expr).collect(),
        outputs: ["zf", "cf", "of", "sf", "pf"]
            .iter()
            .map(|name| IlLocation::Flag(flag(name)))
            .collect(),
    });
}

fn lift_push(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    let rsp = reg_expr(ARCH, "rsp", 64);
    let new_rsp = IlExpr::Sub(Box::new(rsp.clone()), Box::new(const_expr(8, 64)));
    statements.push(IlStmt::Assign {
        dst: reg_location(ARCH, "rsp", 64),
        src: new_rsp.clone(),
    });
    if let Some(value) = instruction.operands.first() {
        statements.push(IlStmt::Store {
            address: new_rsp,
            value: operand_expr(value),
            size: 64,
        });
    }
}

fn lift_pop(instruction: &urdisassembly::Instruction, statements: &mut Vec<IlStmt>) {
    if let Some(urdisassembly::Operand::Register(dst)) = instruction.operands.first() {
        statements.push(IlStmt::Load {
            dst: reg_location(ARCH, &dst.name, 64),
            address: reg_expr(ARCH, "rsp", 64),
            size: 64,
        });
        statements.push(IlStmt::Assign {
            dst: reg_location(ARCH, "rsp", 64),
            src: IlExpr::Add(
                Box::new(reg_expr(ARCH, "rsp", 64)),
                Box::new(const_expr(8, 64)),
            ),
        });
    }
}

fn operand_expr(operand: &urdisassembly::Operand) -> IlExpr {
    match operand {
        urdisassembly::Operand::Register(reg) => reg_expr(ARCH, &reg.name, 64),
        urdisassembly::Operand::Immediate(value) => const_expr(*value as u64, 64),
        urdisassembly::Operand::AbsoluteAddress(addr) => const_expr(*addr, 64),
        urdisassembly::Operand::Memory(mem) => memory_address(ARCH, mem),
        urdisassembly::Operand::Condition(cond) => const_expr(condition_code(cond), 8),
    }
}

fn target_expr(instruction: &urdisassembly::Instruction) -> IlExpr {
    instruction
        .branch_target
        .map(|target| const_expr(target, 64))
        .unwrap_or_else(|| reg_expr(ARCH, "unknown_target", 64))
}

fn is_jcc(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "jo" | "jno" | "jb" | "jae" | "je" | "jne" | "jbe" | "ja" | "js" | "jns" | "jp"
            | "jnp" | "jl" | "jge" | "jle" | "jg"
    )
}

fn condition_expr(mnemonic: &str) -> IlExpr {
    match mnemonic {
        "je" => IlExpr::Eq(
            Box::new(IlExpr::Flag(flag("zf"))),
            Box::new(const_expr(1, 1)),
        ),
        "jne" => IlExpr::Eq(
            Box::new(IlExpr::Flag(flag("zf"))),
            Box::new(const_expr(0, 1)),
        ),
        _ => IlExpr::Flag(flag(mnemonic)),
    }
}

fn flag(name: &str) -> IlFlag {
    IlFlag {
        arch: ARCH,
        name: name.to_string(),
    }
}

fn condition_code(cond: &str) -> u64 {
    cond.bytes().fold(0u64, |acc, byte| acc + u64::from(byte))
}
```

- [ ] **Step 4: Run x86-64 lifter tests**

Run:

```bash
cargo test -p urdis2il --test x86_64_lift
```

Expected: all x86-64 lifter tests pass.

- [ ] **Step 5: Commit x86-64 lifter**

Run:

```bash
git add crates/urdis2il/src/x86_64.rs crates/urdis2il/tests/x86_64_lift.rs
git commit -m "feat: lift x86-64 instructions to il"
```

---

### Task 8: Add Coverage Docs And Workspace Verification

**Files:**
- Create: `docs/urdisassembly/x86_64-coverage.md`
- Create: `docs/urdis2il/coverage.md`

- [ ] **Step 1: Add x86-64 decode coverage document**

Create `docs/urdisassembly/x86_64-coverage.md`:

```markdown
# X86-64 Coverage Matrix

| Encoding group | Representative mnemonics | Decode | Format | Flow semantics | Golden tests | Corpus evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Return | `ret` | Implemented | Implemented | Implemented | Yes | Not measured | Near return only. |
| Relative call | `call rel32` | Implemented | Implemented | Implemented | Yes | Not measured | Direct relative call only. |
| Relative jump | `jmp rel8`, `jmp rel32` | Implemented | Implemented | Implemented | Yes | Not measured | Direct relative jump only. |
| Conditional jump | `jcc rel8`, `jcc rel32` | Implemented | Implemented | Implemented | Yes | Not measured | Common condition mnemonics covered. |
| Register move | `mov r64, imm64`, `mov r/m64, r64`, `mov r64, r/m64` | Partial | Implemented | Implemented | Yes | Not measured | 64-bit GPR forms only. |
| Address calculation | `lea r64, m` | Partial | Implemented | Implemented | Yes | Not measured | Common ModRM/SIB memory only. |
| Arithmetic | `add`, `sub` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit GPR and imm8 group forms only. |
| Compare and test | `cmp`, `test` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit GPR and imm8 group forms only. |
| Logical | `and`, `or`, `xor` | Partial | Implemented | Implemented | Yes | Not measured | Common 64-bit GPR forms only. |
| Stack | `push`, `pop` | Partial | Implemented | Implemented | Yes | Not measured | 64-bit GPR forms only. |
| SSE/AVX | `movaps`, `vaddps` | Not implemented | Not implemented | Not implemented | No | Not measured | Out of first scope. |
| System and privileged | `syscall`, `rdmsr`, `wrmsr` | Not implemented | Not implemented | Not implemented | No | Not measured | Out of first scope. |
| Segment/TLS | `fs:`, `gs:` | Not implemented | Not implemented | Not implemented | No | Not measured | Out of first scope. |
```

- [ ] **Step 2: Add IL coverage document**

Create `docs/urdis2il/coverage.md`:

```markdown
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
```

- [ ] **Step 3: Run formatting**

Run:

```bash
cargo fmt -- --check
```

Expected: command exits with status 0. If formatting fails, run `cargo fmt`, then run `cargo fmt -- --check` again and confirm status 0.

- [ ] **Step 4: Run focused crate tests**

Run:

```bash
cargo test -p urdisassembly
cargo test -p urdis2il
```

Expected: both commands pass.

- [ ] **Step 5: Run full workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: all workspace tests pass. `ura-core`, `ura-cli`, and `ura-daemon` behavior remains unchanged.

- [ ] **Step 6: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: command exits with status 0.

- [ ] **Step 7: Commit coverage docs and verification fixes**

Run:

```bash
git add docs/urdisassembly/x86_64-coverage.md docs/urdis2il/coverage.md Cargo.lock Cargo.toml crates
git commit -m "docs: track x86-64 and il coverage"
```

---

## Final Verification

After all tasks are complete, run:

```bash
git status --short
cargo fmt -- --check
cargo test -p urdisassembly
cargo test -p urdis2il
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected:

- `git status --short` prints no uncommitted changes.
- All Cargo commands exit with status 0.
- The implementation has not modified `ura-core`, `ura-cli`, or `ura-daemon` behavior beyond dependency resolution changes caused by adding the new workspace crate.

## Implementation Checkpoints

- X86-64 unsupported bytes decode to `.byte` with `DecodeStatus::Unknown`.
- X86-64 direct branches, calls, conditional jumps, moves, LEA, arithmetic, logical operations, push, and pop have structural tests.
- AArch64 existing tests remain green after expanding `MemoryOperand`.
- `urdis2il` emits `Unsupported` for unknown or unsupported instructions.
- AArch64 and x86-64 load/store examples both produce `Load` and `Store` IL.
- AArch64 `b.eq` and x86-64 `je` both use explicit zero-flag branch conditions.
- `ura-core` integration is not added in this plan.
