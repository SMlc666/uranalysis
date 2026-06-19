use crate::{
    error::DecodeError,
    form::{
        ByteStreamLayout, DecodeLayout, EncodeRule, FieldSource, FieldSpec, FormId, FormSchema,
        Matcher, MemorySpec, OperandSpec, TextRule,
    },
    model::{Architecture, DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

static NO_FIELDS: &[FieldSpec] = &[];
static NO_OPERANDS: &[OperandSpec] = &[];
static IMM16_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "imm",
    source: FieldSource::Immediate16,
}];
static IMM16_OPERAND: &[OperandSpec] = &[OperandSpec::Immediate { field: "imm" }];
static IMM8_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "imm",
    source: FieldSource::Immediate8,
}];
static IMM32_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "imm",
    source: FieldSource::Immediate32,
}];
static IMM8_OPERAND: &[OperandSpec] = &[OperandSpec::Immediate { field: "imm" }];
static ENTER_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "frame",
        source: FieldSource::Immediate16,
    },
    FieldSpec {
        name: "nesting",
        source: FieldSource::ByteAt { offset: 3 },
    },
];
static ENTER_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Immediate { field: "frame" },
    OperandSpec::Immediate { field: "nesting" },
];
static REL8_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "disp",
    source: FieldSource::SignedImmediate8,
}];
static REL32_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "disp",
    source: FieldSource::SignedImmediate32,
}];
static TARGET_OPERAND: &[OperandSpec] = &[OperandSpec::RelativeTarget {
    field: "disp",
    scale: 1,
    add_instruction_size: true,
}];
static RM64_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "rm",
    source: FieldSource::ModrmRm,
}];
static RM64_OPERAND: &[OperandSpec] = &[OperandSpec::Register {
    field: "rm",
    bank: "x86_64.r64",
}];
static REG64_OPCODE_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "reg",
    source: FieldSource::OpcodeRegister { offset: 0 },
}];
static REG64_OPCODE_OPERAND: &[OperandSpec] = &[OperandSpec::Register {
    field: "reg",
    bank: "x86_64.r64",
}];
static REG_RM64_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "reg",
        source: FieldSource::ModrmReg,
    },
];
static REG_RM64_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r64",
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r64",
    },
];
static MEM64_AND_REG64_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 64 },
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r64",
    },
];
static REG64_AND_MEM64_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r64",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 64 },
    },
];
static REG_RM32_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "reg",
        source: FieldSource::ModrmReg,
    },
];
static REG_RM32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r32",
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
];
static REG_RM16_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "reg",
        source: FieldSource::ModrmReg,
    },
];
static REG_RM16_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r16",
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r16",
    },
];
static REG_RM8_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "reg",
        source: FieldSource::ModrmReg,
    },
];
static REG_RM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r8",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r8",
    },
];
static RM_REG8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r8",
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r8",
    },
];
static MEM8_AND_REG8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 8 },
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r8",
    },
];
static REG8_AND_MEM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r8",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 8 },
    },
];
static REG32_AND_MEM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 8 },
    },
];
static REG32_AND_MEM32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 32 },
    },
];
static REG32_AND_MEM16_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 16 },
    },
];
static REG64_AND_MEM16_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r64",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 16 },
    },
];
static MEM32_AND_REG32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 32 },
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
];
static REGMM_AND_MEM64_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.mm",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 64 },
    },
];
static REGXMM_AND_MEM128_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 128 },
    },
];
static MEM128_AND_REGXMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 128 },
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
];
static REGMM_AND_REGMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.mm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.mm",
    },
];
static REG32_AND_REGXMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.xmm",
    },
];
static REG32_AND_REGMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.mm",
    },
];
static REGMM_AND_REGXMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.mm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.xmm",
    },
];
static REGXMM_AND_REGMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.mm",
    },
];
static REGMM_AND_REG32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.mm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r32",
    },
];
static REGXMM_AND_REG32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r32",
    },
];
static RM64_AND_REGXMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r64",
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
];
static REGXMM_AND_REGXMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.xmm",
    },
];
static REGXMM_AND_MEM64_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 64 },
    },
];
static REGYMM_AND_MEM256_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.ymm",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 256 },
    },
];
static MEM256_AND_REGYMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 256 },
    },
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.ymm",
    },
];
static REG_RM32_IMM32_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "reg",
        source: FieldSource::ModrmReg,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate32,
    },
];
static REG_RM64_IMM8_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "reg",
        source: FieldSource::ModrmReg,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate8,
    },
];
static REG32_REG32_IMM32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r32",
    },
    OperandSpec::Immediate { field: "imm" },
];
static REG64_REG64_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r64",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r64",
    },
    OperandSpec::Immediate { field: "imm" },
];
static REG_RM_IMM8_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "reg",
        source: FieldSource::ModrmReg,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate8,
    },
];
static REGXMM_REGXMM_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.xmm",
    },
    OperandSpec::Immediate { field: "imm" },
];
static REGXMM_MEM128_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 128 },
    },
    OperandSpec::Immediate { field: "imm" },
];
static REGMM_REGMM_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.mm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.mm",
    },
    OperandSpec::Immediate { field: "imm" },
];
static RMMM_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.mm",
    },
    OperandSpec::Immediate { field: "imm" },
];
static RMXMM_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.xmm",
    },
    OperandSpec::Immediate { field: "imm" },
];
static REG_VVVV_RM_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "reg",
        source: FieldSource::ModrmReg,
    },
    FieldSpec {
        name: "vvvv",
        source: FieldSource::VexVvvv,
    },
];
static REG_VVVV_RM_IMM8_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "reg",
        source: FieldSource::ModrmReg,
    },
    FieldSpec {
        name: "vvvv",
        source: FieldSource::VexVvvv,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate8,
    },
];
static VVVV_RM_IMM8_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "vvvv",
        source: FieldSource::VexVvvv,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate8,
    },
];
static XMM_TERNARY_REG_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
    OperandSpec::Register {
        field: "vvvv",
        bank: "x86_64.xmm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.xmm",
    },
];
static XMM_TERNARY_MEM128_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.xmm",
    },
    OperandSpec::Register {
        field: "vvvv",
        bank: "x86_64.xmm",
    },
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 128 },
    },
];
static YMM_XMM_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.ymm",
    },
    OperandSpec::Register {
        field: "vvvv",
        bank: "x86_64.ymm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.xmm",
    },
    OperandSpec::Immediate { field: "imm" },
];
static VVVV_XMM_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "vvvv",
        bank: "x86_64.xmm",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.xmm",
    },
    OperandSpec::Immediate { field: "imm" },
];
static MEM8_OPERAND: &[OperandSpec] = &[OperandSpec::Memory {
    kind: MemorySpec::X86Modrm { width_bits: 8 },
}];
static MEM64_OPERAND: &[OperandSpec] = &[OperandSpec::Memory {
    kind: MemorySpec::X86Modrm { width_bits: 64 },
}];
static MEM32_OPERAND: &[OperandSpec] = &[OperandSpec::Memory {
    kind: MemorySpec::X86Modrm { width_bits: 32 },
}];
static REG32_OPCODE_OPERAND: &[OperandSpec] = &[OperandSpec::Register {
    field: "rd",
    bank: "x86_64.r32",
}];
static REG32_OPCODE_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "rd",
    source: FieldSource::OpcodeRegister { offset: 1 },
}];
static REG32_OPCODE0_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "reg",
    source: FieldSource::OpcodeRegister { offset: 0 },
}];
static REG_REG64_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r64",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r64",
    },
];
static REG_REG32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r32",
    },
];
static RM8_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "rm",
    source: FieldSource::ModrmRm,
}];
static RM8_OPERAND: &[OperandSpec] = &[OperandSpec::Register {
    field: "rm",
    bank: "x86_64.r8",
}];
static RM32_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "rm",
    source: FieldSource::ModrmRm,
}];
static RM64_IMM8_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate8,
    },
];
static RM64_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r64",
    },
    OperandSpec::Immediate { field: "imm" },
];
static MEM8_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 8 },
    },
    OperandSpec::Immediate { field: "imm" },
];
static RM8_IMM8_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate8,
    },
];
static RM8_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r8",
    },
    OperandSpec::Immediate { field: "imm" },
];
static RM32_IMM8_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate8,
    },
];
static RM32_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r32",
    },
    OperandSpec::Immediate { field: "imm" },
];
static MEM32_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 32 },
    },
    OperandSpec::Immediate { field: "imm" },
];
static RM32_ONE_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Literal(1),
    },
];
static RM64_IMM32_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate32,
    },
];
static RM64_IMM32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r64",
    },
    OperandSpec::Immediate { field: "imm" },
];
static MEM64_IMM32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 64 },
    },
    OperandSpec::Immediate { field: "imm" },
];
static RM64_ONE_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rm",
        source: FieldSource::ModrmRm,
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Literal(1),
    },
];
static MEM16_IMM16_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 16 },
    },
    OperandSpec::Immediate { field: "imm" },
];
static REG32_AND_EAX_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r32",
    },
    OperandSpec::FixedRegister { name: "eax" },
];
static REG64_AND_RAX_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r64",
    },
    OperandSpec::FixedRegister { name: "rax" },
];
static REG64_AND_REG32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "reg",
        bank: "x86_64.r64",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r32",
    },
];
static REG64_OPCODE_REX_FIELD: &[FieldSpec] = &[FieldSpec {
    name: "reg",
    source: FieldSource::OpcodeRegister { offset: 1 },
}];
static REG32_IMM32_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rd",
        source: FieldSource::OpcodeRegister { offset: 0 },
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate32,
    },
];
static REG32_IMM32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "x86_64.r32",
    },
    OperandSpec::Immediate { field: "imm" },
];
static REG8_IMM8_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rd",
        source: FieldSource::OpcodeRegister { offset: 0 },
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate8,
    },
];
static REG8_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "x86_64.r8",
    },
    OperandSpec::Immediate { field: "imm" },
];
static AL_AND_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedRegister { name: "al" },
    OperandSpec::Immediate { field: "imm" },
];
static EAX_AND_IMM32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedRegister { name: "eax" },
    OperandSpec::Immediate { field: "imm" },
];
static RAX_AND_IMM32_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedRegister { name: "rax" },
    OperandSpec::Immediate { field: "imm" },
];
static EAX_AND_IMM8_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedRegister { name: "eax" },
    OperandSpec::Immediate { field: "imm" },
];
static RM8_AND_CL_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r8",
    },
    OperandSpec::FixedRegister { name: "cl" },
];
static MEM8_AND_CL_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Memory {
        kind: MemorySpec::X86Modrm { width_bits: 8 },
    },
    OperandSpec::FixedRegister { name: "cl" },
];
static RM32_AND_CL_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r32",
    },
    OperandSpec::FixedRegister { name: "cl" },
];
static RM64_AND_CL_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rm",
        bank: "x86_64.r64",
    },
    OperandSpec::FixedRegister { name: "cl" },
];
static IMM8_AND_AL_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Immediate { field: "imm" },
    OperandSpec::FixedRegister { name: "al" },
];
static MOVSB_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedMemory {
        base: "rdi",
        width_bits: 8,
    },
    OperandSpec::FixedMemory {
        base: "rsi",
        width_bits: 8,
    },
];
static MOVSD_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedMemory {
        base: "rdi",
        width_bits: 32,
    },
    OperandSpec::FixedMemory {
        base: "rsi",
        width_bits: 32,
    },
];
static CMPSB_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedMemory {
        base: "rsi",
        width_bits: 8,
    },
    OperandSpec::FixedMemory {
        base: "rdi",
        width_bits: 8,
    },
];
static CMPSD_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedMemory {
        base: "rsi",
        width_bits: 32,
    },
    OperandSpec::FixedMemory {
        base: "rdi",
        width_bits: 32,
    },
];
static STOSB_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedMemory {
        base: "rdi",
        width_bits: 8,
    },
    OperandSpec::FixedRegister { name: "al" },
];
static STOSD_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedMemory {
        base: "rdi",
        width_bits: 32,
    },
    OperandSpec::FixedRegister { name: "eax" },
];
static LODSB_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedRegister { name: "al" },
    OperandSpec::FixedMemory {
        base: "rsi",
        width_bits: 8,
    },
];
static LODSD_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedRegister { name: "eax" },
    OperandSpec::FixedMemory {
        base: "rsi",
        width_bits: 32,
    },
];
static SCASB_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedRegister { name: "al" },
    OperandSpec::FixedMemory {
        base: "rdi",
        width_bits: 8,
    },
];
static SCASD_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedRegister { name: "eax" },
    OperandSpec::FixedMemory {
        base: "rdi",
        width_bits: 32,
    },
];
static INSB_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedMemory {
        base: "rdi",
        width_bits: 8,
    },
    OperandSpec::FixedRegister { name: "dx" },
];
static OUTSD_OPERANDS: &[OperandSpec] = &[
    OperandSpec::FixedRegister { name: "dx" },
    OperandSpec::FixedMemory {
        base: "rsi",
        width_bits: 32,
    },
];
static MOV_R64_IMM64_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rd",
        source: FieldSource::OpcodeRegister { offset: 1 },
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Immediate64,
    },
];
static MOV_R64_IMM64_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "x86_64.r64",
    },
    OperandSpec::Immediate { field: "imm" },
];

static FORMS: &[FormSchema] = &[
    FormSchema::new(
        FormId::new(Architecture::X86_64, "int3"),
        "int3",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xcc])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "int3",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "breakpoint interrupt",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sfence"),
        "sfence",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xae,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xf8,
            },
        ],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "sfence",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "sfence",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "int_imm8"),
        "int",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0xcd])],
        IMM8_FIELD,
        IMM8_OPERAND,
        TextRule {
            mnemonic: "int",
            operand_order: &["imm"],
        },
        &[],
        EncodeRule {
            require: &["imm8"],
            canonical_preference: "software interrupt",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "int1"),
        "int1",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xf1])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "int1",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "icebp interrupt",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmc"),
        "cmc",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xf5])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "cmc",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "complement carry",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sti"),
        "sti",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xfb])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "sti",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "set interrupt flag",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "in_al_imm8"),
        "in",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0xe4])],
        IMM8_FIELD,
        AL_AND_IMM8_OPERANDS,
        TextRule {
            mnemonic: "in",
            operand_order: &["al", "imm"],
        },
        &[],
        EncodeRule {
            require: &["al", "imm8"],
            canonical_preference: "in al, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "in_eax_imm8"),
        "in",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0xe5])],
        IMM8_FIELD,
        EAX_AND_IMM8_OPERANDS,
        TextRule {
            mnemonic: "in",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm8"],
            canonical_preference: "in eax, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "out_imm8_al"),
        "out",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0xe6])],
        IMM8_FIELD,
        IMM8_AND_AL_OPERANDS,
        TextRule {
            mnemonic: "out",
            operand_order: &["imm", "al"],
        },
        &[],
        EncodeRule {
            require: &["imm8", "al"],
            canonical_preference: "out imm8, al",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "insb"),
        "insb",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x6c])],
        NO_FIELDS,
        INSB_OPERANDS,
        TextRule {
            mnemonic: "insb",
            operand_order: &["rdi", "dx"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "insb",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "outsd"),
        "outsd",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x6f])],
        NO_FIELDS,
        OUTSD_OPERANDS,
        TextRule {
            mnemonic: "outsd",
            operand_order: &["dx", "rsi"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "outsd",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xgetbv"),
        "xgetbv",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x0f, 0x01, 0xd0])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "xgetbv",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "xcr read",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cpuid"),
        "cpuid",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x0f, 0xa2])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "cpuid",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "cpuid",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "iretd"),
        "iretd",
        InstructionKind::System,
        FlowKind::Return,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xcf])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "iretd",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "32-bit interrupt return",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "iretq"),
        "iretq",
        InstructionKind::System,
        FlowKind::Return,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x48, 0xcf])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "iretq",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "64-bit interrupt return",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "nop"),
        "nop",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x90])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "nop",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "single-byte nop",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "nop_4"),
        "nop",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 4,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x0f, 0x1f, 0x40, 0x00])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "nop",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "four-byte nop",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "nop_5"),
        "nop",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 5,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x0f, 0x1f, 0x44, 0x00, 0x00])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "nop",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "five-byte nop",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "nop_9"),
        "nop",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 9,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[
            0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "nop",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "nine-byte nop",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "ud2"),
        "ud2",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x0f, 0x0b])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "ud2",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "undefined instruction",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "enter"),
        "enter",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(3),
        }),
        &[Matcher::OpcodeEq(&[0xc8])],
        ENTER_FIELDS,
        ENTER_OPERANDS,
        TextRule {
            mnemonic: "enter",
            operand_order: &["frame", "nesting"],
        },
        &[],
        EncodeRule {
            require: &["imm16", "imm8"],
            canonical_preference: "stack frame setup",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "leave"),
        "leave",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xc9])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "leave",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "stack frame teardown",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cwde"),
        "cwde",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x98])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "cwde",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "sign extend ax into eax",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cdqe"),
        "cdqe",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x48, 0x98])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "cdqe",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "sign extend eax into rax",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cdq"),
        "cdq",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x99])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "cdq",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "sign extend eax into edx:eax",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cqo"),
        "cqo",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x48, 0x99])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "cqo",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "sign extend rax into rdx:rax",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pushfq"),
        "pushfq",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x9c])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "pushfq",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "push rflags",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "popfq"),
        "popfq",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x9d])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "popfq",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "pop rflags",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sahf"),
        "sahf",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x9e])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "sahf",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "store ah into flags",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "lahf"),
        "lahf",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x9f])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "lahf",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "load ah from flags",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movsb"),
        "movsb",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xa4])],
        NO_FIELDS,
        MOVSB_OPERANDS,
        TextRule {
            mnemonic: "movsb",
            operand_order: &["dst", "src"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "movsb",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movsd"),
        "movsd",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xa5])],
        NO_FIELDS,
        MOVSD_OPERANDS,
        TextRule {
            mnemonic: "movsd",
            operand_order: &["dst", "src"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "movsd",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movsq"),
        "movsq",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0x48, 0xa5])],
        NO_FIELDS,
        MOVSD_OPERANDS,
        TextRule {
            mnemonic: "movsq",
            operand_order: &["dst", "src"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "movsq",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmpsb"),
        "cmpsb",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xa6])],
        NO_FIELDS,
        CMPSB_OPERANDS,
        TextRule {
            mnemonic: "cmpsb",
            operand_order: &["lhs", "rhs"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "cmpsb",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmpsd"),
        "cmpsd",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xa7])],
        NO_FIELDS,
        CMPSD_OPERANDS,
        TextRule {
            mnemonic: "cmpsd",
            operand_order: &["lhs", "rhs"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "cmpsd",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "stosb"),
        "stosb",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xaa])],
        NO_FIELDS,
        STOSB_OPERANDS,
        TextRule {
            mnemonic: "stosb",
            operand_order: &["dst", "src"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "stosb",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "stosd"),
        "stosd",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xab])],
        NO_FIELDS,
        STOSD_OPERANDS,
        TextRule {
            mnemonic: "stosd",
            operand_order: &["dst", "src"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "stosd",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "lodsb"),
        "lodsb",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xac])],
        NO_FIELDS,
        LODSB_OPERANDS,
        TextRule {
            mnemonic: "lodsb",
            operand_order: &["dst", "src"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "lodsb",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "lodsd"),
        "lodsd",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xad])],
        NO_FIELDS,
        LODSD_OPERANDS,
        TextRule {
            mnemonic: "lodsd",
            operand_order: &["dst", "src"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "lodsd",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "scasb"),
        "scasb",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xae])],
        NO_FIELDS,
        SCASB_OPERANDS,
        TextRule {
            mnemonic: "scasb",
            operand_order: &["lhs", "rhs"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "scasb",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "scasd"),
        "scasd",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xaf])],
        NO_FIELDS,
        SCASD_OPERANDS,
        TextRule {
            mnemonic: "scasd",
            operand_order: &["lhs", "rhs"],
        },
        &[],
        EncodeRule {
            require: &["fixed operands"],
            canonical_preference: "scasd",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "push_r64"),
        "push",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xf8,
            value: 0x50,
        }],
        REG64_OPCODE_FIELD,
        REG64_OPCODE_OPERAND,
        TextRule {
            mnemonic: "push",
            operand_order: &["reg"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "push register",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "push_r64_rex"),
        "push",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::OpcodeEq(&[0x41]),
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xf8,
                value: 0x50,
            },
        ],
        REG64_OPCODE_REX_FIELD,
        REG64_OPCODE_OPERAND,
        TextRule {
            mnemonic: "push",
            operand_order: &["reg"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "push high register",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pop_r64"),
        "pop",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xf8,
            value: 0x58,
        }],
        REG64_OPCODE_FIELD,
        REG64_OPCODE_OPERAND,
        TextRule {
            mnemonic: "pop",
            operand_order: &["reg"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "pop register",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pop_r64_rex"),
        "pop",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::OpcodeEq(&[0x41]),
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xf8,
                value: 0x58,
            },
        ],
        REG64_OPCODE_REX_FIELD,
        REG64_OPCODE_OPERAND,
        TextRule {
            mnemonic: "pop",
            operand_order: &["reg"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "pop high register",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_r8_imm8"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xf8,
            value: 0xb0,
        }],
        REG8_IMM8_FIELDS,
        REG8_IMM8_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rd", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r8", "imm8"],
            canonical_preference: "mov r8, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_m8_r8"),
        "mov",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x88,
        }],
        REG_RM8_FIELDS,
        MEM8_AND_REG8_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m8", "r8"],
            canonical_preference: "mov m8, r8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_r8_m8"),
        "mov",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x8a,
        }],
        REG_RM8_FIELDS,
        REG8_AND_MEM8_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r8", "m8"],
            canonical_preference: "mov r8, m8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_m8_imm8"),
        "mov",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc6,
            },
            Matcher::OpcodeExt { reg: 0 },
        ],
        RM64_IMM8_FIELDS,
        MEM8_IMM8_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["m8", "imm8"],
            canonical_preference: "mov m8, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movsx_r32_m8"),
        "movsx",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xbe,
            },
        ],
        REG_RM32_FIELDS,
        REG32_AND_MEM8_OPERANDS,
        TextRule {
            mnemonic: "movsx",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "m8"],
            canonical_preference: "movsx r32, m8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movzx_r32_m8"),
        "movzx",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xb6,
            },
        ],
        REG_RM32_FIELDS,
        REG32_AND_MEM8_OPERANDS,
        TextRule {
            mnemonic: "movzx",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "m8"],
            canonical_preference: "movzx r32, m8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movsxd_r32_m32"),
        "movsxd",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x63,
        }],
        REG_RM32_FIELDS,
        REG32_AND_MEM32_OPERANDS,
        TextRule {
            mnemonic: "movsxd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "m32"],
            canonical_preference: "movsxd r32, m32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movsxd_r64_r32"),
        "movsxd",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x63,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG64_AND_REG32_OPERANDS,
        TextRule {
            mnemonic: "movsxd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "r32"],
            canonical_preference: "movsxd r64, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_r32_imm32"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xf8,
            value: 0xb8,
        }],
        REG32_IMM32_FIELDS,
        REG32_IMM32_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rd", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "imm32"],
            canonical_preference: "mov r32, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_r64_imm32_c7"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xc7,
            },
            Matcher::OpcodeExt { reg: 0 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM32_FIELDS,
        RM64_IMM32_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm32"],
            canonical_preference: "mov r64, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_m64_imm32_c7"),
        "mov",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xc7,
            },
            Matcher::OpcodeExt { reg: 0 },
        ],
        RM64_IMM32_FIELDS,
        MEM64_IMM32_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["m64", "imm32"],
            canonical_preference: "mov m64, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_m16_imm16_c7"),
        "mov",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(2),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xc7,
            },
            Matcher::OpcodeExt { reg: 0 },
        ],
        IMM16_FIELD,
        MEM16_IMM16_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["m16", "imm16"],
            canonical_preference: "mov m16, imm16",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_r64_r64"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x89,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM64_FIELDS,
        REG_RM64_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r64", "r64"],
            canonical_preference: "mov r64, r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_m64_r64"),
        "mov",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x89,
            },
        ],
        REG_RM64_FIELDS,
        MEM64_AND_REG64_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m64", "r64"],
            canonical_preference: "mov m64, r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_r64_m64"),
        "mov",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x8b,
            },
        ],
        REG_RM64_FIELDS,
        REG64_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "m64"],
            canonical_preference: "mov r64, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "lea_r64_m"),
        "lea",
        InstructionKind::Address,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x8d,
            },
        ],
        REG_RM64_FIELDS,
        REG64_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "lea",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "m64"],
            canonical_preference: "lea r64, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmovb_r32_r32"),
        "cmovb",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x42,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_REG32_OPERANDS,
        TextRule {
            mnemonic: "cmovb",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "cmovb r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "adc_r32_r32"),
        "adc",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x13,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_REG32_OPERANDS,
        TextRule {
            mnemonic: "adc",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "adc r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sbb_r32_r32"),
        "sbb",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x1b,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_REG32_OPERANDS,
        TextRule {
            mnemonic: "sbb",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "sbb r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmpxchg_lock_m8_r8"),
        "cmpxchg",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xf0,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xb0,
            },
        ],
        REG_RM8_FIELDS,
        MEM8_AND_REG8_OPERANDS,
        TextRule {
            mnemonic: "cmpxchg",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m8", "r8"],
            canonical_preference: "cmpxchg lock m8, r8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmpxchg_r16_r16"),
        "cmpxchg",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xb1,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM16_FIELDS,
        REG_RM16_OPERANDS,
        TextRule {
            mnemonic: "cmpxchg",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r16", "r16"],
            canonical_preference: "cmpxchg r16, r16",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmpxchg_r32_r32"),
        "cmpxchg",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xb1,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_RM32_OPERANDS,
        TextRule {
            mnemonic: "cmpxchg",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "cmpxchg r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmpxchg_m64_r64"),
        "cmpxchg",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xb1,
            },
        ],
        REG_RM64_FIELDS,
        MEM64_AND_REG64_OPERANDS,
        TextRule {
            mnemonic: "cmpxchg",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m64", "r64"],
            canonical_preference: "cmpxchg m64, r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xadd_lock_m32_r32"),
        "xadd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xf0,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xc1,
            },
        ],
        REG_RM32_FIELDS,
        MEM32_AND_REG32_OPERANDS,
        TextRule {
            mnemonic: "xadd",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m32", "r32"],
            canonical_preference: "xadd lock m32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movups_m128_xmm"),
        "movups",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x11,
            },
        ],
        REG_RM32_FIELDS,
        MEM128_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "movups",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m128", "xmm"],
            canonical_preference: "movups m128, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movups_xmm_m128"),
        "movups",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x10,
            },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_MEM128_OPERANDS,
        TextRule {
            mnemonic: "movups",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "m128"],
            canonical_preference: "movups xmm, m128",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movaps_m128_xmm"),
        "movaps",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x29,
            },
        ],
        REG_RM32_FIELDS,
        MEM128_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "movaps",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m128", "xmm"],
            canonical_preference: "movaps m128, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movaps_xmm_m128"),
        "movaps",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x28,
            },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_MEM128_OPERANDS,
        TextRule {
            mnemonic: "movaps",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "m128"],
            canonical_preference: "movaps xmm, m128",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmovae_r64_r64"),
        "cmovae",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x43,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM64_FIELDS,
        REG_REG64_OPERANDS,
        TextRule {
            mnemonic: "cmovae",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "r64"],
            canonical_preference: "cmovae r64, r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "bswap_r32"),
        "bswap",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xf8,
                value: 0xc8,
            },
        ],
        REG32_OPCODE_FIELD,
        REG32_OPCODE_OPERAND,
        TextRule {
            mnemonic: "bswap",
            operand_order: &["rd"],
        },
        &[],
        EncodeRule {
            require: &["r32"],
            canonical_preference: "bswap r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "add_r64_imm8"),
        "add",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x83,
            },
            Matcher::OpcodeExt { reg: 0 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM8_FIELDS,
        RM64_IMM8_OPERANDS,
        TextRule {
            mnemonic: "add",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm8"],
            canonical_preference: "add r64, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "or_r64_imm8"),
        "or",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x83,
            },
            Matcher::OpcodeExt { reg: 1 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM8_FIELDS,
        RM64_IMM8_OPERANDS,
        TextRule {
            mnemonic: "or",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm8"],
            canonical_preference: "or r64, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "adc_r64_imm8"),
        "adc",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x83,
            },
            Matcher::OpcodeExt { reg: 2 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM8_FIELDS,
        RM64_IMM8_OPERANDS,
        TextRule {
            mnemonic: "adc",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm8"],
            canonical_preference: "adc r64, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sbb_r64_imm8"),
        "sbb",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x83,
            },
            Matcher::OpcodeExt { reg: 3 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM8_FIELDS,
        RM64_IMM8_OPERANDS,
        TextRule {
            mnemonic: "sbb",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm8"],
            canonical_preference: "sbb r64, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "and_r64_imm8"),
        "and",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x83,
            },
            Matcher::OpcodeExt { reg: 4 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM8_FIELDS,
        RM64_IMM8_OPERANDS,
        TextRule {
            mnemonic: "and",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm8"],
            canonical_preference: "and r64, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xor_r64_imm8"),
        "xor",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x83,
            },
            Matcher::OpcodeExt { reg: 6 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM8_FIELDS,
        RM64_IMM8_OPERANDS,
        TextRule {
            mnemonic: "xor",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm8"],
            canonical_preference: "xor r64, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmp_r64_imm8"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x83,
            },
            Matcher::OpcodeExt { reg: 7 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM8_FIELDS,
        RM64_IMM8_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm8"],
            canonical_preference: "cmp r64, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmp_m8_imm8"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x80,
            },
            Matcher::OpcodeExt { reg: 7 },
        ],
        IMM8_FIELD,
        MEM8_IMM8_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["m8", "imm8"],
            canonical_preference: "cmp m8, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmp_al_imm8"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x3c,
        }],
        IMM8_FIELD,
        AL_AND_IMM8_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["al", "imm"],
        },
        &[],
        EncodeRule {
            require: &["al", "imm8"],
            canonical_preference: "cmp al, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "or_al_imm8"),
        "or",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x0c,
        }],
        IMM8_FIELD,
        AL_AND_IMM8_OPERANDS,
        TextRule {
            mnemonic: "or",
            operand_order: &["al", "imm"],
        },
        &[],
        EncodeRule {
            require: &["al", "imm8"],
            canonical_preference: "or al, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "adc_al_imm8"),
        "adc",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x14,
        }],
        IMM8_FIELD,
        AL_AND_IMM8_OPERANDS,
        TextRule {
            mnemonic: "adc",
            operand_order: &["al", "imm"],
        },
        &[],
        EncodeRule {
            require: &["al", "imm8"],
            canonical_preference: "adc al, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sbb_al_imm8"),
        "sbb",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x1c,
        }],
        IMM8_FIELD,
        AL_AND_IMM8_OPERANDS,
        TextRule {
            mnemonic: "sbb",
            operand_order: &["al", "imm"],
        },
        &[],
        EncodeRule {
            require: &["al", "imm8"],
            canonical_preference: "sbb al, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "and_al_imm8"),
        "and",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x24,
        }],
        IMM8_FIELD,
        AL_AND_IMM8_OPERANDS,
        TextRule {
            mnemonic: "and",
            operand_order: &["al", "imm"],
        },
        &[],
        EncodeRule {
            require: &["al", "imm8"],
            canonical_preference: "and al, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sub_al_imm8"),
        "sub",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x2c,
        }],
        IMM8_FIELD,
        AL_AND_IMM8_OPERANDS,
        TextRule {
            mnemonic: "sub",
            operand_order: &["al", "imm"],
        },
        &[],
        EncodeRule {
            require: &["al", "imm8"],
            canonical_preference: "sub al, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "add_r8_r8"),
        "add",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x02,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM8_FIELDS,
        REG_RM8_OPERANDS,
        TextRule {
            mnemonic: "add",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r8", "r8"],
            canonical_preference: "add r8, r8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "or_r8_r8"),
        "or",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x08,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM8_FIELDS,
        RM_REG8_OPERANDS,
        TextRule {
            mnemonic: "or",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r8", "r8"],
            canonical_preference: "or r8, r8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmp_r8_r8"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x38,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM8_FIELDS,
        RM_REG8_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r8", "r8"],
            canonical_preference: "cmp r8, r8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "bt_r32_r32"),
        "bt",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xa3,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_RM32_OPERANDS,
        TextRule {
            mnemonic: "bt",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "bt r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "bsf_r32_r32"),
        "bsf",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xbc,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_REG32_OPERANDS,
        TextRule {
            mnemonic: "bsf",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "bsf r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "bsf_r64_m64"),
        "bsf",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xbc,
            },
        ],
        REG_RM64_FIELDS,
        REG64_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "bsf",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "m64"],
            canonical_preference: "bsf r64, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "bsr_r32_r32"),
        "bsr",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xbd,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_REG32_OPERANDS,
        TextRule {
            mnemonic: "bsr",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "bsr r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movzx_r32_m16"),
        "movzx",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xb7,
            },
        ],
        REG_RM32_FIELDS,
        REG32_AND_MEM16_OPERANDS,
        TextRule {
            mnemonic: "movzx",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "m16"],
            canonical_preference: "movzx r32, m16",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movzx_r64_m16"),
        "movzx",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xb7,
            },
        ],
        REG_RM64_FIELDS,
        REG64_AND_MEM16_OPERANDS,
        TextRule {
            mnemonic: "movzx",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "m16"],
            canonical_preference: "movzx r64, m16",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "bt_r32_imm8"),
        "bt",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xba,
            },
            Matcher::OpcodeExt { reg: 4 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM32_IMM8_FIELDS,
        RM32_IMM8_OPERANDS,
        TextRule {
            mnemonic: "bt",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "imm8"],
            canonical_preference: "bt r32, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "bts_m32_imm8"),
        "bts",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xba,
            },
            Matcher::OpcodeExt { reg: 5 },
        ],
        IMM8_FIELD,
        MEM32_IMM8_OPERANDS,
        TextRule {
            mnemonic: "bts",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["m32", "imm8"],
            canonical_preference: "bts m32, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "bts_r32_r32"),
        "bts",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xab,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_RM32_OPERANDS,
        TextRule {
            mnemonic: "bts",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "bts r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "btr_m32_imm8"),
        "btr",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xba,
            },
            Matcher::OpcodeExt { reg: 6 },
        ],
        IMM8_FIELD,
        MEM32_IMM8_OPERANDS,
        TextRule {
            mnemonic: "btr",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["m32", "imm8"],
            canonical_preference: "btr m32, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "btc_m32_imm8"),
        "btc",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xba,
            },
            Matcher::OpcodeExt { reg: 7 },
        ],
        IMM8_FIELD,
        MEM32_IMM8_OPERANDS,
        TextRule {
            mnemonic: "btc",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["m32", "imm8"],
            canonical_preference: "btc m32, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "add_r64_imm32"),
        "add",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x81,
            },
            Matcher::OpcodeExt { reg: 0 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM32_FIELDS,
        RM64_IMM32_OPERANDS,
        TextRule {
            mnemonic: "add",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm32"],
            canonical_preference: "add r64, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xor_r64_imm32"),
        "xor",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x81,
            },
            Matcher::OpcodeExt { reg: 6 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM32_FIELDS,
        RM64_IMM32_OPERANDS,
        TextRule {
            mnemonic: "xor",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm32"],
            canonical_preference: "xor r64, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmp_m64_imm32"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x81,
            },
            Matcher::OpcodeExt { reg: 7 },
        ],
        IMM32_FIELD,
        MEM64_IMM32_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["m64", "imm32"],
            canonical_preference: "cmp m64, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmp_eax_imm32"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x3d,
        }],
        IMM32_FIELD,
        EAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm32"],
            canonical_preference: "cmp eax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmp_rax_imm32"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x3d,
            },
        ],
        IMM32_FIELD,
        RAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["rax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["rax", "imm32"],
            canonical_preference: "cmp rax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "test_eax_imm32"),
        "test",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0xa9,
        }],
        IMM32_FIELD,
        EAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "test",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm32"],
            canonical_preference: "test eax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "test_rax_imm32"),
        "test",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xa9,
            },
        ],
        IMM32_FIELD,
        RAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "test",
            operand_order: &["rax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["rax", "imm32"],
            canonical_preference: "test rax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "test_m8_r8"),
        "test",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x84,
        }],
        REG_RM8_FIELDS,
        MEM8_AND_REG8_OPERANDS,
        TextRule {
            mnemonic: "test",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m8", "r8"],
            canonical_preference: "test m8, r8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "test_r8_imm8"),
        "test",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xf6,
            },
            Matcher::OpcodeExt { reg: 0 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM8_IMM8_FIELDS,
        RM8_IMM8_OPERANDS,
        TextRule {
            mnemonic: "test",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r8", "imm8"],
            canonical_preference: "test r8, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "test_al_imm8"),
        "test",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0xa8,
        }],
        IMM8_FIELD,
        AL_AND_IMM8_OPERANDS,
        TextRule {
            mnemonic: "test",
            operand_order: &["al", "imm"],
        },
        &[],
        EncodeRule {
            require: &["al", "imm8"],
            canonical_preference: "test al, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "and_eax_imm32"),
        "and",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x25,
        }],
        IMM32_FIELD,
        EAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "and",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm32"],
            canonical_preference: "and eax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "add_eax_imm32"),
        "add",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x05,
        }],
        IMM32_FIELD,
        EAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "add",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm32"],
            canonical_preference: "add eax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "or_eax_imm32"),
        "or",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x0d,
        }],
        IMM32_FIELD,
        EAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "or",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm32"],
            canonical_preference: "or eax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "adc_eax_imm32"),
        "adc",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x15,
        }],
        IMM32_FIELD,
        EAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "adc",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm32"],
            canonical_preference: "adc eax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sbb_eax_imm32"),
        "sbb",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x1d,
        }],
        IMM32_FIELD,
        EAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "sbb",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm32"],
            canonical_preference: "sbb eax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sub_eax_imm32"),
        "sub",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x2d,
        }],
        IMM32_FIELD,
        EAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "sub",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm32"],
            canonical_preference: "sub eax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xor_eax_imm32"),
        "xor",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x35,
        }],
        IMM32_FIELD,
        EAX_AND_IMM32_OPERANDS,
        TextRule {
            mnemonic: "xor",
            operand_order: &["eax", "imm"],
        },
        &[],
        EncodeRule {
            require: &["eax", "imm32"],
            canonical_preference: "xor eax, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "test_r64_imm32"),
        "test",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xf7,
            },
            Matcher::OpcodeExt { reg: 0 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM32_FIELDS,
        RM64_IMM32_OPERANDS,
        TextRule {
            mnemonic: "test",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm32"],
            canonical_preference: "test r64, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "not_r64"),
        "not",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xf7,
            },
            Matcher::OpcodeExt { reg: 2 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_FIELD,
        RM64_OPERAND,
        TextRule {
            mnemonic: "not",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "not r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "neg_r64"),
        "neg",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xf7,
            },
            Matcher::OpcodeExt { reg: 3 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_FIELD,
        RM64_OPERAND,
        TextRule {
            mnemonic: "neg",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "neg r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "imul_r32_r32"),
        "imul",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xaf,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_REG32_OPERANDS,
        TextRule {
            mnemonic: "imul",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "imul r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "imul_r64_m64"),
        "imul",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xaf,
            },
        ],
        REG_RM64_FIELDS,
        REG64_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "imul",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "m64"],
            canonical_preference: "imul r64, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "imul_m64"),
        "imul",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xf7,
            },
            Matcher::OpcodeExt { reg: 5 },
        ],
        NO_FIELDS,
        MEM64_OPERAND,
        TextRule {
            mnemonic: "imul",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["m64"],
            canonical_preference: "imul m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "idiv_r64"),
        "idiv",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xf7,
            },
            Matcher::OpcodeExt { reg: 7 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_FIELD,
        RM64_OPERAND,
        TextRule {
            mnemonic: "idiv",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "idiv r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sub_r64_r64"),
        "sub",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x29,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM64_FIELDS,
        REG_RM64_OPERANDS,
        TextRule {
            mnemonic: "sub",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r64", "r64"],
            canonical_preference: "sub r64, r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmp_r64_r64"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x39,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM64_FIELDS,
        REG_RM64_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r64", "r64"],
            canonical_preference: "cmp r64, r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "test_r64_r64"),
        "test",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x85,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM64_FIELDS,
        REG_RM64_OPERANDS,
        TextRule {
            mnemonic: "test",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r64", "r64"],
            canonical_preference: "test r64, r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xor_r64_r64"),
        "xor",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x31,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM64_FIELDS,
        REG_RM64_OPERANDS,
        TextRule {
            mnemonic: "xor",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r64", "r64"],
            canonical_preference: "xor r64, r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "inc_m8_groupfe"),
        "inc",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xfe,
            },
            Matcher::OpcodeExt { reg: 0 },
        ],
        NO_FIELDS,
        MEM8_OPERAND,
        TextRule {
            mnemonic: "inc",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["m8"],
            canonical_preference: "inc m8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "dec_r8_groupfe"),
        "dec",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xfe,
            },
            Matcher::OpcodeExt { reg: 1 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM8_FIELD,
        RM8_OPERAND,
        TextRule {
            mnemonic: "dec",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r8"],
            canonical_preference: "dec r8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "shr_r8_imm8"),
        "shr",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc0,
            },
            Matcher::OpcodeExt { reg: 5 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM8_IMM8_FIELDS,
        RM8_IMM8_OPERANDS,
        TextRule {
            mnemonic: "shr",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r8", "imm8"],
            canonical_preference: "shr r8, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "rol_m32_imm8"),
        "rol",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc1,
            },
            Matcher::OpcodeExt { reg: 0 },
        ],
        IMM8_FIELD,
        MEM32_IMM8_OPERANDS,
        TextRule {
            mnemonic: "rol",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["m32", "imm8"],
            canonical_preference: "rol m32, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sar_r64_imm8"),
        "sar",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xc1,
            },
            Matcher::OpcodeExt { reg: 7 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_IMM8_FIELDS,
        RM64_IMM8_OPERANDS,
        TextRule {
            mnemonic: "sar",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm8"],
            canonical_preference: "sar r64, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "shl_r32_one"),
        "shl",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xd1,
            },
            Matcher::OpcodeExt { reg: 4 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM32_ONE_FIELDS,
        &[
            OperandSpec::Register {
                field: "rm",
                bank: "x86_64.r32",
            },
            OperandSpec::Immediate { field: "imm" },
        ],
        TextRule {
            mnemonic: "shl",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "imm8"],
            canonical_preference: "shl r32, 1",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "shr_r64_one"),
        "shr",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xd1,
            },
            Matcher::OpcodeExt { reg: 5 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_ONE_FIELDS,
        &[
            OperandSpec::Register {
                field: "rm",
                bank: "x86_64.r64",
            },
            OperandSpec::Immediate { field: "imm" },
        ],
        TextRule {
            mnemonic: "shr",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm8"],
            canonical_preference: "shr r64, 1",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "rcl_r8_cl"),
        "rcl",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xd2,
            },
            Matcher::OpcodeExt { reg: 2 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM8_FIELD,
        RM8_AND_CL_OPERANDS,
        TextRule {
            mnemonic: "rcl",
            operand_order: &["rm", "cl"],
        },
        &[],
        EncodeRule {
            require: &["r8", "cl"],
            canonical_preference: "rcl r8, cl",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "rcl_m8_cl"),
        "rcl",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xd2,
            },
            Matcher::OpcodeExt { reg: 2 },
        ],
        NO_FIELDS,
        MEM8_AND_CL_OPERANDS,
        TextRule {
            mnemonic: "rcl",
            operand_order: &["rm", "cl"],
        },
        &[],
        EncodeRule {
            require: &["m8", "cl"],
            canonical_preference: "rcl m8, cl",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "ror_r32_cl"),
        "ror",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xd3,
            },
            Matcher::OpcodeExt { reg: 1 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM32_FIELD,
        RM32_AND_CL_OPERANDS,
        TextRule {
            mnemonic: "ror",
            operand_order: &["rm", "cl"],
        },
        &[],
        EncodeRule {
            require: &["r32", "cl"],
            canonical_preference: "ror r32, cl",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "rcl_r32_cl"),
        "rcl",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xd3,
            },
            Matcher::OpcodeExt { reg: 2 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM32_FIELD,
        RM32_AND_CL_OPERANDS,
        TextRule {
            mnemonic: "rcl",
            operand_order: &["rm", "cl"],
        },
        &[],
        EncodeRule {
            require: &["r32", "cl"],
            canonical_preference: "rcl r32, cl",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "shr_r64_cl"),
        "shr",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xd3,
            },
            Matcher::OpcodeExt { reg: 5 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_FIELD,
        RM64_AND_CL_OPERANDS,
        TextRule {
            mnemonic: "shr",
            operand_order: &["rm", "cl"],
        },
        &[],
        EncodeRule {
            require: &["r64", "cl"],
            canonical_preference: "shr r64, cl",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "inc_r64_groupff"),
        "inc",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xff,
            },
            Matcher::OpcodeExt { reg: 0 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_FIELD,
        RM64_OPERAND,
        TextRule {
            mnemonic: "inc",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "inc r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "dec_r64_groupff"),
        "dec",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xff,
            },
            Matcher::OpcodeExt { reg: 1 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_FIELD,
        RM64_OPERAND,
        TextRule {
            mnemonic: "dec",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "dec r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "push_r64_groupff"),
        "push",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xff,
            },
            Matcher::OpcodeExt { reg: 6 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_FIELD,
        RM64_OPERAND,
        TextRule {
            mnemonic: "push",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "push r64 via ff",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xchg_r32_r32"),
        "xchg",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x87,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG_RM32_OPERANDS,
        TextRule {
            mnemonic: "xchg",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32"],
            canonical_preference: "xchg r32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xchg_m8_r8"),
        "xchg",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x86,
        }],
        REG_RM8_FIELDS,
        MEM8_AND_REG8_OPERANDS,
        TextRule {
            mnemonic: "xchg",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m8", "r8"],
            canonical_preference: "xchg m8, r8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xchg_m32_r32"),
        "xchg",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xff,
            value: 0x87,
        }],
        REG_RM32_FIELDS,
        MEM32_AND_REG32_OPERANDS,
        TextRule {
            mnemonic: "xchg",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m32", "r32"],
            canonical_preference: "xchg m32, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xchg_eax_r32"),
        "xchg",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::ByteMaskedEq {
            offset: 0,
            mask: 0xf8,
            value: 0x90,
        }],
        REG32_OPCODE0_FIELD,
        REG32_AND_EAX_OPERANDS,
        TextRule {
            mnemonic: "xchg",
            operand_order: &["reg", "eax"],
        },
        &[],
        EncodeRule {
            require: &["r32"],
            canonical_preference: "xchg eax, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xchg_rax_r64"),
        "xchg",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xf8,
                value: 0x90,
            },
        ],
        REG64_OPCODE_REX_FIELD,
        REG64_AND_RAX_OPERANDS,
        TextRule {
            mnemonic: "xchg",
            operand_order: &["reg", "rax"],
        },
        &[],
        EncodeRule {
            require: &["r64"],
            canonical_preference: "xchg rax, r64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "sete_r8"),
        "sete",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x94,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM8_FIELD,
        RM8_OPERAND,
        TextRule {
            mnemonic: "sete",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r8"],
            canonical_preference: "sete r8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "setne_m8"),
        "setne",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x95,
            },
        ],
        RM8_FIELD,
        MEM8_OPERAND,
        TextRule {
            mnemonic: "setne",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["m8"],
            canonical_preference: "setne m8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "stmxcsr_m32"),
        "stmxcsr",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xae,
            },
            Matcher::OpcodeExt { reg: 3 },
        ],
        NO_FIELDS,
        MEM32_OPERAND,
        TextRule {
            mnemonic: "stmxcsr",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["m32"],
            canonical_preference: "stmxcsr m32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "ldmxcsr_m32"),
        "ldmxcsr",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xae,
            },
            Matcher::OpcodeExt { reg: 2 },
        ],
        NO_FIELDS,
        MEM32_OPERAND,
        TextRule {
            mnemonic: "ldmxcsr",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["m32"],
            canonical_preference: "ldmxcsr m32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "fimul_m32"),
        "fimul",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xda,
            },
            Matcher::OpcodeExt { reg: 1 },
        ],
        NO_FIELDS,
        MEM32_OPERAND,
        TextRule {
            mnemonic: "fimul",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["m32"],
            canonical_preference: "fimul m32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "fistp_m32"),
        "fistp",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xdb,
            },
            Matcher::OpcodeExt { reg: 3 },
        ],
        NO_FIELDS,
        MEM32_OPERAND,
        TextRule {
            mnemonic: "fistp",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["m32"],
            canonical_preference: "fistp m32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "fstp_m64"),
        "fstp",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xdd,
            },
            Matcher::OpcodeExt { reg: 3 },
        ],
        NO_FIELDS,
        MEM64_OPERAND,
        TextRule {
            mnemonic: "fstp",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["m64"],
            canonical_preference: "fstp m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "fisttp_m64"),
        "fisttp",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xdd,
            },
            Matcher::OpcodeExt { reg: 1 },
        ],
        NO_FIELDS,
        MEM64_OPERAND,
        TextRule {
            mnemonic: "fisttp",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["m64"],
            canonical_preference: "fisttp m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vzeroupper"),
        "vzeroupper",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xf8,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x77,
            },
        ],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "vzeroupper",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "vzeroupper",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movq_mm_m64"),
        "movq",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x6f,
            },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "movq",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "m64"],
            canonical_preference: "movq mm, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pavgb_mm_mm"),
        "pavgb",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xe0,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "pavgb",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "mm"],
            canonical_preference: "pavgb mm, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vmovdqa_xmm_m128"),
        "vmovdqa",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x7f,
                value: 0x79,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x6f,
            },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_MEM128_OPERANDS,
        TextRule {
            mnemonic: "vmovdqa",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "m128"],
            canonical_preference: "vmovdqa xmm, m128",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vmovdqu_ymm_m256_c5"),
        "vmovdqu",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x7f,
                value: 0x7e,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x6f,
            },
        ],
        REG_RM32_FIELDS,
        REGYMM_AND_MEM256_OPERANDS,
        TextRule {
            mnemonic: "vmovdqu",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["ymm", "m256"],
            canonical_preference: "vmovdqu ymm, m256",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vmovdqu_ymm_m256_c4"),
        "vmovdqu",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 4,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc4,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x1f,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0x87,
                value: 0x06,
            },
            Matcher::ByteMaskedEq {
                offset: 3,
                mask: 0xff,
                value: 0x6f,
            },
        ],
        REG_RM32_FIELDS,
        REGYMM_AND_MEM256_OPERANDS,
        TextRule {
            mnemonic: "vmovdqu",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["ymm", "m256"],
            canonical_preference: "vmovdqu ymm, m256 long-vex",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vmovdqu_m256_ymm_c4"),
        "vmovdqu",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 4,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc4,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x1f,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0x87,
                value: 0x06,
            },
            Matcher::ByteMaskedEq {
                offset: 3,
                mask: 0xff,
                value: 0x7f,
            },
        ],
        REG_RM32_FIELDS,
        MEM256_AND_REGYMM_OPERANDS,
        TextRule {
            mnemonic: "vmovdqu",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m256", "ymm"],
            canonical_preference: "vmovdqu m256, ymm long-vex",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vmovntdq_m256_ymm_c4"),
        "vmovntdq",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 4,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc4,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x1f,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0x87,
                value: 0x05,
            },
            Matcher::ByteMaskedEq {
                offset: 3,
                mask: 0xff,
                value: 0xe7,
            },
        ],
        REG_RM32_FIELDS,
        MEM256_AND_REGYMM_OPERANDS,
        TextRule {
            mnemonic: "vmovntdq",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["m256", "ymm"],
            canonical_preference: "vmovntdq m256, ymm long-vex",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vpmovmskb_r32_xmm"),
        "vpmovmskb",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x7f,
                value: 0x79,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xd7,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG32_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "vpmovmskb",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "xmm"],
            canonical_preference: "vpmovmskb r32, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vmulps_xmm_xmm_xmm"),
        "vmulps",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x00,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x59,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_REG_OPERANDS,
        TextRule {
            mnemonic: "vmulps",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "xmm"],
            canonical_preference: "vmulps xmm, xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vpand_xmm_xmm_m128"),
        "vpand",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xdb,
            },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_MEM128_OPERANDS,
        TextRule {
            mnemonic: "vpand",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "m128"],
            canonical_preference: "vpand xmm, xmm, m128",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vpor_xmm_xmm_m128"),
        "vpor",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xeb,
            },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_MEM128_OPERANDS,
        TextRule {
            mnemonic: "vpor",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "m128"],
            canonical_preference: "vpor xmm, xmm, m128",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vpaddq_xmm_xmm_xmm"),
        "vpaddq",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xd4,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_REG_OPERANDS,
        TextRule {
            mnemonic: "vpaddq",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "xmm"],
            canonical_preference: "vpaddq xmm, xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vsubsd_xmm_xmm_xmm"),
        "vsubsd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x03,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x5c,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_REG_OPERANDS,
        TextRule {
            mnemonic: "vsubsd",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "xmm"],
            canonical_preference: "vsubsd xmm, xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vcomisd_xmm_xmm"),
        "vcomisd",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x2f,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "vcomisd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "vcomisd xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vcomisd_xmm_m64"),
        "vcomisd",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x2f,
            },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "vcomisd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "m64"],
            canonical_preference: "vcomisd xmm, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vcvtdq2pd_xmm_xmm"),
        "vcvtdq2pd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x02,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xe6,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "vcvtdq2pd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "vcvtdq2pd xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vmovq_r64_xmm_vex"),
        "vmovq",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 4,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc4,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x1f,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0x87,
                value: 0x81,
            },
            Matcher::ByteMaskedEq {
                offset: 3,
                mask: 0xff,
                value: 0x7e,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM64_FIELDS,
        RM64_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "vmovq",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r64", "xmm"],
            canonical_preference: "vmovq r64, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vfmsub213sd_xmm_xmm_xmm"),
        "vfmsub213sd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 4,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc4,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x1f,
                value: 0x02,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0x87,
                value: 0x81,
            },
            Matcher::ByteMaskedEq {
                offset: 3,
                mask: 0xff,
                value: 0xab,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_REG_OPERANDS,
        TextRule {
            mnemonic: "vfmsub213sd",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "xmm"],
            canonical_preference: "vfmsub213sd xmm, xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vfmadd231sd_xmm_xmm_xmm"),
        "vfmadd231sd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 4,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc4,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x1f,
                value: 0x02,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0x87,
                value: 0x81,
            },
            Matcher::ByteMaskedEq {
                offset: 3,
                mask: 0xff,
                value: 0xb9,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_REG_OPERANDS,
        TextRule {
            mnemonic: "vfmadd231sd",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "xmm"],
            canonical_preference: "vfmadd231sd xmm, xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vinsertf128_ymm_ymm_xmm_imm8"),
        "vinsertf128",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 4,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc4,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x1f,
                value: 0x03,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0x87,
                value: 0x05,
            },
            Matcher::ByteMaskedEq {
                offset: 3,
                mask: 0xff,
                value: 0x18,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_VVVV_RM_IMM8_FIELDS,
        YMM_XMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "vinsertf128",
            operand_order: &["reg", "vvvv", "rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["ymm", "ymm", "xmm", "imm8"],
            canonical_preference: "vinsertf128 ymm, ymm, xmm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vmovsd_xmm_m64"),
        "vmovsd",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x03,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x10,
            },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "vmovsd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "m64"],
            canonical_preference: "vmovsd xmm, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vmovapd_xmm_xmm"),
        "vmovapd",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x28,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "vmovapd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "vmovapd xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vaddsd_xmm_xmm_xmm"),
        "vaddsd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x03,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x58,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_REG_OPERANDS,
        TextRule {
            mnemonic: "vaddsd",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "xmm"],
            canonical_preference: "vaddsd xmm, xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vdivsd_xmm_xmm_xmm"),
        "vdivsd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x03,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x5e,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_REG_OPERANDS,
        TextRule {
            mnemonic: "vdivsd",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "xmm"],
            canonical_preference: "vdivsd xmm, xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vpxor_xmm_xmm_xmm"),
        "vpxor",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xef,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_REG_OPERANDS,
        TextRule {
            mnemonic: "vpxor",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "xmm"],
            canonical_preference: "vpxor xmm, xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vpsubd_xmm_xmm_m128"),
        "vpsubd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xfa,
            },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_MEM128_OPERANDS,
        TextRule {
            mnemonic: "vpsubd",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "m128"],
            canonical_preference: "vpsubd xmm, xmm, m128",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vpsubq_xmm_xmm_m128"),
        "vpsubq",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xfb,
            },
        ],
        REG_VVVV_RM_FIELDS,
        XMM_TERNARY_MEM128_OPERANDS,
        TextRule {
            mnemonic: "vpsubq",
            operand_order: &["reg", "vvvv", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "m128"],
            canonical_preference: "vpsubq xmm, xmm, m128",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vpsrlq_xmm_xmm_imm8"),
        "vpsrlq",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x73,
            },
            Matcher::OpcodeExt { reg: 2 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        VVVV_RM_IMM8_FIELDS,
        VVVV_XMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "vpsrlq",
            operand_order: &["vvvv", "rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "imm8"],
            canonical_preference: "vpsrlq xmm, xmm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "vpsllq_xmm_xmm_imm8"),
        "vpsllq",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xc5,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0x07,
                value: 0x01,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x73,
            },
            Matcher::OpcodeExt { reg: 6 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        VVVV_RM_IMM8_FIELDS,
        VVVV_XMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "vpsllq",
            operand_order: &["vvvv", "rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "imm8"],
            canonical_preference: "vpsllq xmm, xmm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "imul_r32_r32_imm32"),
        "imul",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x69,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_IMM32_FIELDS,
        REG32_REG32_IMM32_OPERANDS,
        TextRule {
            mnemonic: "imul",
            operand_order: &["reg", "rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "r32", "imm32"],
            canonical_preference: "imul r32, r32, imm32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "imul_r64_r64_imm8"),
        "imul",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x6b,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM64_IMM8_FIELDS,
        REG64_REG64_IMM8_OPERANDS,
        TextRule {
            mnemonic: "imul",
            operand_order: &["reg", "rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "r64", "imm8"],
            canonical_preference: "imul r64, r64, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "xorps_xmm_xmm"),
        "xorps",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x57,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "xorps",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "xorps xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "orps_xmm_xmm"),
        "orps",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x56,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "orps",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "orps xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "orpd_xmm_xmm"),
        "orpd",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x56,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "orpd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "orpd xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmpps_xmm_xmm_imm8"),
        "cmpps",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xc2,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM_IMM8_FIELDS,
        REGXMM_REGXMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "cmpps",
            operand_order: &["reg", "rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "imm8"],
            canonical_preference: "cmpps xmm, xmm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cmpps_xmm_m128_imm8"),
        "cmpps",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xc2,
            },
        ],
        REG_RM_IMM8_FIELDS,
        REGXMM_MEM128_IMM8_OPERANDS,
        TextRule {
            mnemonic: "cmpps",
            operand_order: &["reg", "rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "m128", "imm8"],
            canonical_preference: "cmpps xmm, m128, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mulps_xmm_xmm"),
        "mulps",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x59,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "mulps",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "mulps xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mulsd_xmm_xmm"),
        "mulsd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xf2,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x59,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "mulsd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "mulsd xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "addps_xmm_xmm"),
        "addps",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x58,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "addps",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "addps xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "addsd_xmm_xmm"),
        "addsd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0xf2,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x58,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "addsd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "addsd xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "subps_xmm_xmm"),
        "subps",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x5c,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "subps",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "subps xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "divps_xmm_xmm"),
        "divps",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x5e,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "divps",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "divps xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "andps_xmm_xmm"),
        "andps",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x54,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "andps",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "andps xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "ucomiss_xmm_xmm"),
        "ucomiss",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x2e,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "ucomiss",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "ucomiss xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "comisd_xmm_xmm"),
        "comisd",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x2f,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "comisd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "comisd xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pmaddwd_mm_mm"),
        "pmaddwd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xf5,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "pmaddwd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "mm"],
            canonical_preference: "pmaddwd mm, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "psllw_mm_mm"),
        "psllw",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xf1,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "psllw",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "mm"],
            canonical_preference: "psllw mm, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "paddw_mm_mm"),
        "paddw",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xfd,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "paddw",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "mm"],
            canonical_preference: "paddw mm, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pmovmskb_r32_mm"),
        "pmovmskb",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xd7,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG32_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "pmovmskb",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "mm"],
            canonical_preference: "pmovmskb r32, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cvtps2pi_mm_xmm"),
        "cvtps2pi",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x2d,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "cvtps2pi",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "xmm"],
            canonical_preference: "cvtps2pi mm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "cvtpi2ps_xmm_mm"),
        "cvtpi2ps",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x2a,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "cvtpi2ps",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "mm"],
            canonical_preference: "cvtpi2ps xmm, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movd_r32_mm"),
        "movd",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x7e,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REG32_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "movd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["r32", "mm"],
            canonical_preference: "movd r32, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movd_mm_r32"),
        "movd",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x6e,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_REG32_OPERANDS,
        TextRule {
            mnemonic: "movd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "r32"],
            canonical_preference: "movd mm, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movd_xmm_r32"),
        "movd",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x6e,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REG32_OPERANDS,
        TextRule {
            mnemonic: "movd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "r32"],
            canonical_preference: "movd xmm, r32",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "movq_r64_xmm"),
        "movq",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 4,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 3,
                mask: 0xff,
                value: 0x7e,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM64_FIELDS,
        RM64_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "movq",
            operand_order: &["rm", "reg"],
        },
        &[],
        EncodeRule {
            require: &["r64", "xmm"],
            canonical_preference: "movq r64, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pcmpeqb_mm_mm"),
        "pcmpeqb",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x74,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "pcmpeqb",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "mm"],
            canonical_preference: "pcmpeqb mm, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pcmpeqb_xmm_xmm"),
        "pcmpeqb",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x74,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "pcmpeqb",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "pcmpeqb xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "punpcklbw_mm_mm"),
        "punpcklbw",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x60,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "punpcklbw",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "mm"],
            canonical_preference: "punpcklbw mm, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "punpcklbw_xmm_xmm"),
        "punpcklbw",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x60,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "punpcklbw",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "punpcklbw xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pcmpgtb_mm_m64"),
        "pcmpgtb",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x64,
            },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "pcmpgtb",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "m64"],
            canonical_preference: "pcmpgtb mm, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pand_xmm_m128"),
        "pand",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xdb,
            },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_MEM128_OPERANDS,
        TextRule {
            mnemonic: "pand",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "m128"],
            canonical_preference: "pand xmm, m128",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "psubd_mm_m64"),
        "psubd",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xfa,
            },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "psubd",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "m64"],
            canonical_preference: "psubd mm, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "psubq_mm_m64"),
        "psubq",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xfb,
            },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_MEM64_OPERANDS,
        TextRule {
            mnemonic: "psubq",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "m64"],
            canonical_preference: "psubq mm, m64",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "psrlq_mm_imm8"),
        "psrlq",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x73,
            },
            Matcher::OpcodeExt { reg: 2 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM8_IMM8_FIELDS,
        RMMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "psrlq",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "imm8"],
            canonical_preference: "psrlq mm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "psllq_mm_imm8"),
        "psllq",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x73,
            },
            Matcher::OpcodeExt { reg: 6 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM8_IMM8_FIELDS,
        RMMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "psllq",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "imm8"],
            canonical_preference: "psllq mm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "psrldq_xmm_imm8"),
        "psrldq",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x73,
            },
            Matcher::OpcodeExt { reg: 3 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM8_IMM8_FIELDS,
        RMXMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "psrldq",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "imm8"],
            canonical_preference: "psrldq xmm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pslldq_xmm_imm8"),
        "pslldq",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x73,
            },
            Matcher::OpcodeExt { reg: 7 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM8_IMM8_FIELDS,
        RMXMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "pslldq",
            operand_order: &["rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "imm8"],
            canonical_preference: "pslldq xmm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "por_mm_mm"),
        "por",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0xeb,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGMM_AND_REGMM_OPERANDS,
        TextRule {
            mnemonic: "por",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "mm"],
            canonical_preference: "por mm, mm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pxor_xmm_xmm"),
        "pxor",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0xef,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM32_FIELDS,
        REGXMM_AND_REGXMM_OPERANDS,
        TextRule {
            mnemonic: "pxor",
            operand_order: &["reg", "rm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm"],
            canonical_preference: "pxor xmm, xmm",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pshufw_mm_mm_imm8"),
        "pshufw",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x70,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM_IMM8_FIELDS,
        REGMM_REGMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "pshufw",
            operand_order: &["reg", "rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["mm", "mm", "imm8"],
            canonical_preference: "pshufw mm, mm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "pshufd_xmm_xmm_imm8"),
        "pshufd",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 3,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xff,
                value: 0x66,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xff,
                value: 0x0f,
            },
            Matcher::ByteMaskedEq {
                offset: 2,
                mask: 0xff,
                value: 0x70,
            },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        REG_RM_IMM8_FIELDS,
        REGXMM_REGXMM_IMM8_OPERANDS,
        TextRule {
            mnemonic: "pshufd",
            operand_order: &["reg", "rm", "imm"],
        },
        &[],
        EncodeRule {
            require: &["xmm", "xmm", "imm8"],
            canonical_preference: "pshufd xmm, xmm, imm8",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "ret"),
        "ret",
        InstructionKind::Return,
        FlowKind::Return,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xc3])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "ret",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "single-byte ret",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "ret_imm16"),
        "ret",
        InstructionKind::Return,
        FlowKind::Return,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(2),
        }),
        &[Matcher::OpcodeEq(&[0xc2])],
        IMM16_FIELD,
        IMM16_OPERAND,
        TextRule {
            mnemonic: "ret",
            operand_order: &["imm"],
        },
        &[],
        EncodeRule {
            require: &["imm16"],
            canonical_preference: "near return with pop count",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "retf"),
        "retf",
        InstructionKind::Return,
        FlowKind::Return,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[Matcher::OpcodeEq(&[0xcb])],
        NO_FIELDS,
        NO_OPERANDS,
        TextRule {
            mnemonic: "retf",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "far return",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "retf_imm16"),
        "retf",
        InstructionKind::Return,
        FlowKind::Return,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(2),
        }),
        &[Matcher::OpcodeEq(&[0xca])],
        IMM16_FIELD,
        IMM16_OPERAND,
        TextRule {
            mnemonic: "retf",
            operand_order: &["imm"],
        },
        &[],
        EncodeRule {
            require: &["imm16"],
            canonical_preference: "far return with pop count",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "call_rel32"),
        "call",
        InstructionKind::Call,
        FlowKind::Call,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::OpcodeEq(&[0xe8])],
        REL32_FIELD,
        TARGET_OPERAND,
        TextRule {
            mnemonic: "call",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["rel32"],
            canonical_preference: "direct near call",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "call_rm64"),
        "call",
        InstructionKind::Call,
        FlowKind::IndirectCall,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::OpcodeEq(&[0x48, 0xff]),
            Matcher::OpcodeExt { reg: 2 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_FIELD,
        RM64_OPERAND,
        TextRule {
            mnemonic: "call",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r/m64 register"],
            canonical_preference: "indirect call register",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "jmp_rel8"),
        "jmp",
        InstructionKind::Branch,
        FlowKind::Branch,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0xeb])],
        REL8_FIELD,
        TARGET_OPERAND,
        TextRule {
            mnemonic: "jmp",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["rel8"],
            canonical_preference: "short jump",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "jmp_rel32"),
        "jmp",
        InstructionKind::Branch,
        FlowKind::Branch,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::OpcodeEq(&[0xe9])],
        REL32_FIELD,
        TARGET_OPERAND,
        TextRule {
            mnemonic: "jmp",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["rel32"],
            canonical_preference: "near jump",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "jmp_rm64"),
        "jmp",
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: true,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: None,
        }),
        &[
            Matcher::OpcodeEq(&[0x48, 0xff]),
            Matcher::OpcodeExt { reg: 4 },
            Matcher::ModrmMode { mode: 0b11 },
        ],
        RM64_FIELD,
        RM64_OPERAND,
        TextRule {
            mnemonic: "jmp",
            operand_order: &["rm"],
        },
        &[],
        EncodeRule {
            require: &["r/m64 register"],
            canonical_preference: "indirect jump register",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "je_rel8"),
        "je",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0x74])],
        REL8_FIELD,
        TARGET_OPERAND,
        TextRule {
            mnemonic: "je",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["rel8"],
            canonical_preference: "short je",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "jne_rel32"),
        "jne",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(4),
        }),
        &[Matcher::OpcodeEq(&[0x0f, 0x85])],
        REL32_FIELD,
        TARGET_OPERAND,
        TextRule {
            mnemonic: "jne",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["rel32"],
            canonical_preference: "near jne",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "loopne"),
        "loopne",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0xe0])],
        REL8_FIELD,
        TARGET_OPERAND,
        TextRule {
            mnemonic: "loopne",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["rel8"],
            canonical_preference: "loop while not equal",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "loope"),
        "loope",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0xe1])],
        REL8_FIELD,
        TARGET_OPERAND,
        TextRule {
            mnemonic: "loope",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["rel8"],
            canonical_preference: "loop while equal",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "loop"),
        "loop",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0xe2])],
        REL8_FIELD,
        TARGET_OPERAND,
        TextRule {
            mnemonic: "loop",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["rel8"],
            canonical_preference: "loop",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "jrcxz"),
        "jrcxz",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 1,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(1),
        }),
        &[Matcher::OpcodeEq(&[0xe3])],
        REL8_FIELD,
        TARGET_OPERAND,
        TextRule {
            mnemonic: "jrcxz",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["rel8"],
            canonical_preference: "jrcxz",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::X86_64, "mov_r64_imm64"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::ByteStream(ByteStreamLayout {
            opcode_len: 2,
            uses_modrm: false,
            uses_sib: false,
            displacement_bytes: None,
            immediate_bytes: Some(8),
        }),
        &[
            Matcher::ByteMaskedEq {
                offset: 0,
                mask: 0xf8,
                value: 0x48,
            },
            Matcher::ByteMaskedEq {
                offset: 1,
                mask: 0xf8,
                value: 0xb8,
            },
        ],
        MOV_R64_IMM64_FIELDS,
        MOV_R64_IMM64_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rd", "imm"],
        },
        &[],
        EncodeRule {
            require: &["r64", "imm64"],
            canonical_preference: "movabs r64, imm64",
        },
    ),
];

pub fn all_forms() -> &'static [FormSchema] {
    FORMS
}

#[allow(dead_code)]
fn require_len(bytes: &[u8], expected: usize) -> Result<(), DecodeError> {
    if bytes.len() < expected {
        return Err(DecodeError::TruncatedInstruction {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

#[allow(dead_code)]
fn base(
    bytes: Vec<u8>,
    address: u64,
    mnemonic: &str,
    operands: Vec<Operand>,
    kind: InstructionKind,
    flow: FlowKind,
    branch_target: Option<u64>,
) -> Instruction {
    Instruction {
        architecture: Architecture::X86_64,
        address,
        size: bytes.len() as u8,
        bytes,
        mnemonic: mnemonic.to_string(),
        text: String::new(),
        operands,
        kind,
        flow,
        branch_target,
        status: DecodeStatus::Complete,
        form: Some(format!("x86_64.{}", mnemonic)),
    }
}
