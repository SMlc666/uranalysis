use crate::{
    form::{
        DecodeLayout, EncodeRule, FieldSource, FieldSpec, FormId, FormSchema, Matcher, MemorySpec,
        OperandSpec, TextRule,
    },
    model::{Architecture, FlowKind, InstructionKind},
};

static RET_FIELDS: &[FieldSpec] = &[FieldSpec {
    name: "rn",
    source: FieldSource::Bits { start: 5, end: 9 },
}];

static BR_FIELDS: &[FieldSpec] = &[FieldSpec {
    name: "rn",
    source: FieldSource::Bits { start: 5, end: 9 },
}];

static RET_OPERANDS: &[OperandSpec] = &[OperandSpec::Register {
    field: "rn",
    bank: "aarch64.ret",
}];

static BR_OPERANDS: &[OperandSpec] = &[OperandSpec::Register {
    field: "rn",
    bank: "aarch64.x_only",
}];

static B_FIELDS: &[FieldSpec] = &[FieldSpec {
    name: "imm26",
    source: FieldSource::SignedBits { start: 0, end: 25 },
}];

static B_OPERANDS: &[OperandSpec] = &[OperandSpec::RelativeTarget {
    field: "imm26",
    scale: 4,
    add_instruction_size: false,
}];

static B_COND_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "cond",
        source: FieldSource::Bits { start: 0, end: 3 },
    },
    FieldSpec {
        name: "imm19",
        source: FieldSource::SignedBits { start: 5, end: 23 },
    },
];

static B_COND_OPERANDS: &[OperandSpec] = &[OperandSpec::RelativeTarget {
    field: "imm19",
    scale: 4,
    add_instruction_size: false,
}];

static BRK_FIELDS: &[FieldSpec] = &[FieldSpec {
    name: "imm",
    source: FieldSource::Bits { start: 5, end: 20 },
}];

static BRK_OPERANDS: &[OperandSpec] = &[OperandSpec::Immediate { field: "imm" }];

static CB_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "imm19",
        source: FieldSource::SignedBits { start: 5, end: 23 },
    },
    FieldSpec {
        name: "rt",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static CB_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.width_gp",
    },
    OperandSpec::RelativeTarget {
        field: "imm19",
        scale: 4,
        add_instruction_size: false,
    },
];

static TB_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rt",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "bit",
        source: FieldSource::Aarch64TbzBit,
    },
    FieldSpec {
        name: "imm14",
        source: FieldSource::SignedBits { start: 5, end: 18 },
    },
];

static TB_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.tb_width_gp",
    },
    OperandSpec::Immediate { field: "bit" },
    OperandSpec::RelativeTarget {
        field: "imm14",
        scale: 4,
        add_instruction_size: false,
    },
];

static ADR_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "target",
        source: FieldSource::Aarch64AdrTarget { page: false },
    },
];

static ADRP_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "target",
        source: FieldSource::Aarch64AdrTarget { page: true },
    },
];

static ADR_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.x_only",
    },
    OperandSpec::AbsoluteTarget { field: "target" },
];

static ADD_SUB_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Aarch64AddSubImmediate,
    },
];

static ADD_SUB_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.sp_width_gp",
    },
    OperandSpec::Register {
        field: "rn",
        bank: "aarch64.sp_width_gp",
    },
    OperandSpec::Immediate { field: "imm" },
];

static ADD_REG_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rm",
        source: FieldSource::Bits { start: 16, end: 20 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static ADD_SHIFTED_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "shift_kind",
        source: FieldSource::Bits { start: 22, end: 23 },
    },
    FieldSpec {
        name: "rm",
        source: FieldSource::Bits { start: 16, end: 20 },
    },
    FieldSpec {
        name: "shift_amount",
        source: FieldSource::Bits { start: 10, end: 15 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static ADD_REG_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Register {
        field: "rn",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "aarch64.width_gp_zr",
    },
];

static ADD_SHIFTED_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Register {
        field: "rn",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::ShiftedRegister {
        reg_field: "rm",
        shift_field: "shift_kind",
        amount_field: "shift_amount",
        bank: "aarch64.width_gp_zr",
    },
];

static CMP_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Aarch64AddSubImmediate,
    },
];

static CMP_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rn",
        bank: "aarch64.sp_width_gp",
    },
    OperandSpec::Immediate { field: "imm" },
];

static CMP_REG_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rm",
        source: FieldSource::Bits { start: 16, end: 20 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
];

static CMP_REG_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rn",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "aarch64.width_gp_zr",
    },
];

static CSEL_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rm",
        source: FieldSource::Bits { start: 16, end: 20 },
    },
    FieldSpec {
        name: "cond",
        source: FieldSource::Bits { start: 12, end: 15 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static CSEL_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Register {
        field: "rn",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Condition {
        field: "cond",
        table: "aarch64.condsel",
    },
];

static CSET_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Condition {
        field: "cond",
        table: "aarch64.condsel_inverted",
    },
];

static MOVE_WIDE_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "hw",
        source: FieldSource::Bits { start: 21, end: 22 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Aarch64MoveWideImmediate,
    },
];

static MOVE_WIDE_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp",
    },
    OperandSpec::Immediate { field: "imm" },
];

static MOVI_ZERO_2D_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Literal(0),
    },
];

static MOVI_ZERO_2D_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.v2d",
    },
    OperandSpec::Immediate { field: "imm" },
];

static MOV_REG_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rm",
        source: FieldSource::Bits { start: 16, end: 20 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static MOV_REG_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "aarch64.width_gp",
    },
];

static LOGICAL_IMM_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "imm",
        source: FieldSource::Aarch64LogicalImmediate,
    },
];

static LOGICAL_IMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp",
    },
    OperandSpec::Register {
        field: "rn",
        bank: "aarch64.width_gp",
    },
    OperandSpec::Immediate { field: "imm" },
];

static MOV_IMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp",
    },
    OperandSpec::Immediate { field: "imm" },
];

static LSR_IMM_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "shift",
        source: FieldSource::Aarch64BitfieldLsrImmediate,
    },
];

static LSL_IMM_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "shift",
        source: FieldSource::Aarch64BitfieldLslImmediate,
    },
];

static ASR_IMM_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
    FieldSpec {
        name: "shift",
        source: FieldSource::Aarch64BitfieldAsrImmediate,
    },
];

static BITFIELD_IMM_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp",
    },
    OperandSpec::Register {
        field: "rn",
        bank: "aarch64.width_gp",
    },
    OperandSpec::Immediate { field: "shift" },
];

static LSR_REG_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "sf",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "rm",
        source: FieldSource::Bits { start: 16, end: 20 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rd",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static LSR_REG_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rd",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Register {
        field: "rn",
        bank: "aarch64.width_gp_zr",
    },
    OperandSpec::Register {
        field: "rm",
        bank: "aarch64.width_gp_zr",
    },
];

static LOAD_STORE_UNSIGNED_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "size",
        source: FieldSource::Bits { start: 30, end: 31 },
    },
    FieldSpec {
        name: "imm12",
        source: FieldSource::Bits { start: 10, end: 21 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rt",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static LOAD_STORE_SIGNED_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "size",
        source: FieldSource::Bits { start: 30, end: 31 },
    },
    FieldSpec {
        name: "imm9",
        source: FieldSource::SignedBits { start: 12, end: 20 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rt",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static LOAD_STORE_REG_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "size",
        source: FieldSource::Bits { start: 30, end: 31 },
    },
    FieldSpec {
        name: "rm",
        source: FieldSource::Bits { start: 16, end: 20 },
    },
    FieldSpec {
        name: "scaled",
        source: FieldSource::Bits { start: 12, end: 12 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rt",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static LOAD_STORE_PAIR_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "pair_high",
        source: FieldSource::Bits { start: 31, end: 31 },
    },
    FieldSpec {
        name: "pair_vector",
        source: FieldSource::Bits { start: 26, end: 26 },
    },
    FieldSpec {
        name: "imm7",
        source: FieldSource::SignedBits { start: 15, end: 21 },
    },
    FieldSpec {
        name: "rt2",
        source: FieldSource::Bits { start: 10, end: 14 },
    },
    FieldSpec {
        name: "rn",
        source: FieldSource::Bits { start: 5, end: 9 },
    },
    FieldSpec {
        name: "rt",
        source: FieldSource::Bits { start: 0, end: 4 },
    },
];

static LOAD_STORE_UNSIGNED_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.access_gp",
    },
    OperandSpec::Memory {
        kind: MemorySpec::Aarch64UnsignedOffset {
            base_field: "rn",
            offset_field: "imm12",
        },
    },
];

static LOAD_STORE_SIGNED_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.access_gp",
    },
    OperandSpec::Memory {
        kind: MemorySpec::Aarch64SignedOffset {
            base_field: "rn",
            offset_field: "imm9",
            writeback: false,
            post_index: false,
        },
    },
];

static LOAD_STORE_PRE_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.access_gp",
    },
    OperandSpec::Memory {
        kind: MemorySpec::Aarch64SignedOffset {
            base_field: "rn",
            offset_field: "imm9",
            writeback: true,
            post_index: false,
        },
    },
];

static LOAD_STORE_POST_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.access_gp",
    },
    OperandSpec::Memory {
        kind: MemorySpec::Aarch64SignedOffset {
            base_field: "rn",
            offset_field: "imm9",
            writeback: false,
            post_index: true,
        },
    },
];

static LOAD_STORE_REG_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.access_gp",
    },
    OperandSpec::Memory {
        kind: MemorySpec::Aarch64RegisterOffset {
            base_field: "rn",
            index_field: "rm",
            scaled_field: "scaled",
        },
    },
];

static LOAD_STORE_PAIR_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.pair_reg",
    },
    OperandSpec::Register {
        field: "rt2",
        bank: "aarch64.pair_reg",
    },
    OperandSpec::Memory {
        kind: MemorySpec::Aarch64PairOffset {
            base_field: "rn",
            offset_field: "imm7",
            writeback: false,
            post_index: false,
        },
    },
];

static LOAD_STORE_PAIR_PRE_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.pair_reg",
    },
    OperandSpec::Register {
        field: "rt2",
        bank: "aarch64.pair_reg",
    },
    OperandSpec::Memory {
        kind: MemorySpec::Aarch64PairOffset {
            base_field: "rn",
            offset_field: "imm7",
            writeback: true,
            post_index: false,
        },
    },
];

static LOAD_STORE_PAIR_POST_OPERANDS: &[OperandSpec] = &[
    OperandSpec::Register {
        field: "rt",
        bank: "aarch64.pair_reg",
    },
    OperandSpec::Register {
        field: "rt2",
        bank: "aarch64.pair_reg",
    },
    OperandSpec::Memory {
        kind: MemorySpec::Aarch64PairOffset {
            base_field: "rn",
            offset_field: "imm7",
            writeback: false,
            post_index: true,
        },
    },
];

static FORMS: &[FormSchema] = &[
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "nop"),
        "nop",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: u32::MAX,
            value: 0xd503_201f,
        }],
        &[],
        &[],
        TextRule {
            mnemonic: "nop",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["no operands"],
            canonical_preference: "plain nop",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "ret"),
        "ret",
        InstructionKind::Return,
        FlowKind::Return,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0xffff_fc1f,
            value: 0xd65f_0000,
        }],
        RET_FIELDS,
        RET_OPERANDS,
        TextRule {
            mnemonic: "ret",
            operand_order: &[],
        },
        &[],
        EncodeRule {
            require: &["ret register in rn"],
            canonical_preference: "omit x30 operand",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "br"),
        "br",
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0xffff_fc1f,
            value: 0xd61f_0000,
        }],
        BR_FIELDS,
        BR_OPERANDS,
        TextRule {
            mnemonic: "br",
            operand_order: &["rn"],
        },
        &[],
        EncodeRule {
            require: &["x register in rn"],
            canonical_preference: "plain br register",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "blr"),
        "blr",
        InstructionKind::Call,
        FlowKind::IndirectCall,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0xffff_fc1f,
            value: 0xd63f_0000,
        }],
        BR_FIELDS,
        BR_OPERANDS,
        TextRule {
            mnemonic: "blr",
            operand_order: &["rn"],
        },
        &[],
        EncodeRule {
            require: &["x register in rn"],
            canonical_preference: "plain blr register",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "b"),
        "b",
        InstructionKind::Branch,
        FlowKind::Branch,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0xfc00_0000,
            value: 0x1400_0000,
        }],
        B_FIELDS,
        B_OPERANDS,
        TextRule {
            mnemonic: "b",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["aligned branch target"],
            canonical_preference: "plain b target",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "bl"),
        "bl",
        InstructionKind::Call,
        FlowKind::Call,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0xfc00_0000,
            value: 0x9400_0000,
        }],
        B_FIELDS,
        B_OPERANDS,
        TextRule {
            mnemonic: "bl",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["aligned call target"],
            canonical_preference: "plain bl target",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "b_cond"),
        "b.cond",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0xff00_0010,
            value: 0x5400_0000,
        }],
        B_COND_FIELDS,
        B_COND_OPERANDS,
        TextRule {
            mnemonic: "b.cond",
            operand_order: &["target"],
        },
        &[],
        EncodeRule {
            require: &["conditional branch target"],
            canonical_preference: "mnemonic keeps condition suffix",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "cbz"),
        "cbz",
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f00_0000,
            value: 0x3400_0000,
        }],
        CB_FIELDS,
        CB_OPERANDS,
        TextRule {
            mnemonic: "cbz",
            operand_order: &["rt", "target"],
        },
        &[],
        EncodeRule {
            require: &["register and target"],
            canonical_preference: "preserve width",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "cbnz"),
        "cbnz",
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f00_0000,
            value: 0x3500_0000,
        }],
        CB_FIELDS,
        CB_OPERANDS,
        TextRule {
            mnemonic: "cbnz",
            operand_order: &["rt", "target"],
        },
        &[],
        EncodeRule {
            require: &["register and target"],
            canonical_preference: "preserve width",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "tbz"),
        "tbz",
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f00_0000,
            value: 0x3600_0000,
        }],
        TB_FIELDS,
        TB_OPERANDS,
        TextRule {
            mnemonic: "tbz",
            operand_order: &["rt", "bit", "target"],
        },
        &[],
        EncodeRule {
            require: &["test-bit zero operands"],
            canonical_preference: "tbz preserves bit/register width coupling",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "tbnz"),
        "tbnz",
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f00_0000,
            value: 0x3700_0000,
        }],
        TB_FIELDS,
        TB_OPERANDS,
        TextRule {
            mnemonic: "tbnz",
            operand_order: &["rt", "bit", "target"],
        },
        &[],
        EncodeRule {
            require: &["test-bit nonzero operands"],
            canonical_preference: "tbnz preserves bit/register width coupling",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "adr"),
        "adr",
        InstructionKind::Address,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x9f00_0000,
            value: 0x1000_0000,
        }],
        ADR_FIELDS,
        ADR_OPERANDS,
        TextRule {
            mnemonic: "adr",
            operand_order: &["rd", "target"],
        },
        &[],
        EncodeRule {
            require: &["x register and target"],
            canonical_preference: "adr with absolute target",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "adrp"),
        "adrp",
        InstructionKind::Address,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x9f00_0000,
            value: 0x9000_0000,
        }],
        ADRP_FIELDS,
        ADR_OPERANDS,
        TextRule {
            mnemonic: "adrp",
            operand_order: &["rd", "target"],
        },
        &[],
        EncodeRule {
            require: &["x register and page target"],
            canonical_preference: "adrp with absolute page target",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "add_imm"),
        "add",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f00_0000,
            value: 0x1100_0000,
        }],
        ADD_SUB_FIELDS,
        ADD_SUB_OPERANDS,
        TextRule {
            mnemonic: "add",
            operand_order: &["rd", "rn", "imm"],
        },
        &[],
        EncodeRule {
            require: &["register, register, immediate"],
            canonical_preference: "add immediate canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "sub_imm"),
        "sub",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f00_0000,
            value: 0x5100_0000,
        }],
        ADD_SUB_FIELDS,
        ADD_SUB_OPERANDS,
        TextRule {
            mnemonic: "sub",
            operand_order: &["rd", "rn", "imm"],
        },
        &[],
        EncodeRule {
            require: &["register, register, immediate"],
            canonical_preference: "sub immediate canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "cmp_imm"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x7f00_0000,
                value: 0x7100_0000,
            },
            Matcher::MaskEq {
                mask: 0x1f,
                value: 0x1f,
            },
        ],
        CMP_FIELDS,
        CMP_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["rn", "imm"],
        },
        &[],
        EncodeRule {
            require: &["register and immediate"],
            canonical_preference: "cmp immediate alias",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "cmn_imm"),
        "cmn",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x7f00_0000,
                value: 0x3100_0000,
            },
            Matcher::MaskEq {
                mask: 0x1f,
                value: 0x1f,
            },
        ],
        CMP_FIELDS,
        CMP_OPERANDS,
        TextRule {
            mnemonic: "cmn",
            operand_order: &["rn", "imm"],
        },
        &[],
        EncodeRule {
            require: &["register and immediate"],
            canonical_preference: "cmn immediate alias",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "add_reg"),
        "add",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x1f00_0000,
                value: 0x0b00_0000,
            },
            Matcher::MaskEq {
                mask: 0x6000_0000,
                value: 0x0000_0000,
            },
            Matcher::MaskEq {
                mask: 0x00c0_fc00,
                value: 0x0000_0000,
            },
        ],
        ADD_REG_FIELDS,
        ADD_REG_OPERANDS,
        TextRule {
            mnemonic: "add",
            operand_order: &["rd", "rn", "rm"],
        },
        &[],
        EncodeRule {
            require: &["register arithmetic operands"],
            canonical_preference: "add register canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "add_shifted_reg"),
        "add",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x1f00_0000,
                value: 0x0b00_0000,
            },
            Matcher::MaskEq {
                mask: 0x6000_0000,
                value: 0x0000_0000,
            },
        ],
        ADD_SHIFTED_FIELDS,
        ADD_SHIFTED_OPERANDS,
        TextRule {
            mnemonic: "add",
            operand_order: &["rd", "rn", "rm"],
        },
        &[],
        EncodeRule {
            require: &["shifted register arithmetic operands"],
            canonical_preference: "add shifted register canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "cmp_reg"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x1f00_0000,
                value: 0x0b00_0000,
            },
            Matcher::MaskEq {
                mask: 0x6000_0000,
                value: 0x6000_0000,
            },
            Matcher::MaskEq {
                mask: 0x00c0_fc00,
                value: 0x0000_0000,
            },
            Matcher::MaskEq {
                mask: 0x1f,
                value: 0x1f,
            },
        ],
        CMP_REG_FIELDS,
        CMP_REG_OPERANDS,
        TextRule {
            mnemonic: "cmp",
            operand_order: &["rn", "rm"],
        },
        &[],
        EncodeRule {
            require: &["compare register operands"],
            canonical_preference: "compare register canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "csel"),
        "csel",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x1fe0_0400,
            value: 0x1a80_0000,
        }],
        CSEL_FIELDS,
        CSEL_OPERANDS,
        TextRule {
            mnemonic: "csel",
            operand_order: &["rd", "rn", "rm", "cond"],
        },
        &[],
        EncodeRule {
            require: &["conditional select operands"],
            canonical_preference: "csel canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "cset"),
        "cset",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x1fe0_0400,
                value: 0x1a80_0400,
            },
            Matcher::MaskEq {
                mask: 0x001f_0000,
                value: 0x001f_0000,
            },
            Matcher::MaskEq {
                mask: 0x0000_03e0,
                value: 0x0000_03e0,
            },
        ],
        CSEL_FIELDS,
        CSET_OPERANDS,
        TextRule {
            mnemonic: "cset",
            operand_order: &["rd", "cond"],
        },
        &[],
        EncodeRule {
            require: &["conditional set alias operands"],
            canonical_preference: "cset alias form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "stp"),
        "stp",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x7b80_0000,
                value: 0x2900_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0,
            },
        ],
        LOAD_STORE_PAIR_FIELDS,
        LOAD_STORE_PAIR_OPERANDS,
        TextRule {
            mnemonic: "stp",
            operand_order: &["rt", "rt2", "mem"],
        },
        &[],
        EncodeRule {
            require: &["pair store registers and base+offset memory"],
            canonical_preference: "stp pair offset canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "ldp"),
        "ldp",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x7b80_0000,
                value: 0x2900_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0x0040_0000,
            },
        ],
        LOAD_STORE_PAIR_FIELDS,
        LOAD_STORE_PAIR_OPERANDS,
        TextRule {
            mnemonic: "ldp",
            operand_order: &["rt", "rt2", "mem"],
        },
        &[],
        EncodeRule {
            require: &["pair load registers and base+offset memory"],
            canonical_preference: "ldp pair offset canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "stp_pre"),
        "stp",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x7b80_0000,
                value: 0x2980_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0,
            },
        ],
        LOAD_STORE_PAIR_FIELDS,
        LOAD_STORE_PAIR_PRE_OPERANDS,
        TextRule {
            mnemonic: "stp",
            operand_order: &["rt", "rt2", "mem"],
        },
        &[],
        EncodeRule {
            require: &["pair store registers and pre-indexed memory"],
            canonical_preference: "stp pair pre-index form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "ldp_pre"),
        "ldp",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x7b80_0000,
                value: 0x2980_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0x0040_0000,
            },
        ],
        LOAD_STORE_PAIR_FIELDS,
        LOAD_STORE_PAIR_PRE_OPERANDS,
        TextRule {
            mnemonic: "ldp",
            operand_order: &["rt", "rt2", "mem"],
        },
        &[],
        EncodeRule {
            require: &["pair load registers and pre-indexed memory"],
            canonical_preference: "ldp pair pre-index form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "stp_post"),
        "stp",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x7b80_0000,
                value: 0x2880_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0,
            },
        ],
        LOAD_STORE_PAIR_FIELDS,
        LOAD_STORE_PAIR_POST_OPERANDS,
        TextRule {
            mnemonic: "stp",
            operand_order: &["rt", "rt2", "mem"],
        },
        &[],
        EncodeRule {
            require: &["pair store registers and post-indexed memory"],
            canonical_preference: "stp pair post-index form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "ldp_post"),
        "ldp",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x7b80_0000,
                value: 0x2880_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0x0040_0000,
            },
        ],
        LOAD_STORE_PAIR_FIELDS,
        LOAD_STORE_PAIR_POST_OPERANDS,
        TextRule {
            mnemonic: "ldp",
            operand_order: &["rt", "rt2", "mem"],
        },
        &[],
        EncodeRule {
            require: &["pair load registers and post-indexed memory"],
            canonical_preference: "ldp pair post-index form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "ldr_unsigned"),
        "ldr",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b00_0000,
                value: 0x3900_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0x0040_0000,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_UNSIGNED_FIELDS,
        LOAD_STORE_UNSIGNED_OPERANDS,
        TextRule {
            mnemonic: "ldr",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["load register and unsigned-offset memory"],
            canonical_preference: "ldr unsigned offset canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "str_unsigned"),
        "str",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b00_0000,
                value: 0x3900_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_UNSIGNED_FIELDS,
        LOAD_STORE_UNSIGNED_OPERANDS,
        TextRule {
            mnemonic: "str",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["store register and unsigned-offset memory"],
            canonical_preference: "str unsigned offset canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "ldur"),
        "ldur",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b20_0c00,
                value: 0x3800_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0x0040_0000,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_SIGNED_FIELDS,
        LOAD_STORE_SIGNED_OPERANDS,
        TextRule {
            mnemonic: "ldur",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["load register and unscaled memory"],
            canonical_preference: "ldur signed offset canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "stur"),
        "stur",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b20_0c00,
                value: 0x3800_0000,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_SIGNED_FIELDS,
        LOAD_STORE_SIGNED_OPERANDS,
        TextRule {
            mnemonic: "stur",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["store register and unscaled memory"],
            canonical_preference: "stur signed offset canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "ldr_pre"),
        "ldr",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b20_0400,
                value: 0x3800_0400,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0x0040_0000,
            },
            Matcher::MaskEq {
                mask: 0x0000_0800,
                value: 0x0000_0800,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_SIGNED_FIELDS,
        LOAD_STORE_PRE_OPERANDS,
        TextRule {
            mnemonic: "ldr",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["load register and pre-indexed memory"],
            canonical_preference: "ldr pre-index canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "str_pre"),
        "str",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b20_0400,
                value: 0x3800_0400,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0,
            },
            Matcher::MaskEq {
                mask: 0x0000_0800,
                value: 0x0000_0800,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_SIGNED_FIELDS,
        LOAD_STORE_PRE_OPERANDS,
        TextRule {
            mnemonic: "str",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["store register and pre-indexed memory"],
            canonical_preference: "str pre-index canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "ldr_post"),
        "ldr",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b20_0400,
                value: 0x3800_0400,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0x0040_0000,
            },
            Matcher::MaskEq {
                mask: 0x0000_0800,
                value: 0,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_SIGNED_FIELDS,
        LOAD_STORE_POST_OPERANDS,
        TextRule {
            mnemonic: "ldr",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["load register and post-indexed memory"],
            canonical_preference: "ldr post-index canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "str_post"),
        "str",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b20_0400,
                value: 0x3800_0400,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0,
            },
            Matcher::MaskEq {
                mask: 0x0000_0800,
                value: 0,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_SIGNED_FIELDS,
        LOAD_STORE_POST_OPERANDS,
        TextRule {
            mnemonic: "str",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["store register and post-indexed memory"],
            canonical_preference: "str post-index canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "ldr_reg"),
        "ldr",
        InstructionKind::Load,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b20_0c00,
                value: 0x3820_0800,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0x0040_0000,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_REG_FIELDS,
        LOAD_STORE_REG_OPERANDS,
        TextRule {
            mnemonic: "ldr",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["load register and register-offset memory"],
            canonical_preference: "ldr register offset canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "str_reg"),
        "str",
        InstructionKind::Store,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x3b20_0c00,
                value: 0x3820_0800,
            },
            Matcher::MaskEq {
                mask: 0x0040_0000,
                value: 0,
            },
            Matcher::MaskEq {
                mask: 0x0400_0000,
                value: 0,
            },
        ],
        LOAD_STORE_REG_FIELDS,
        LOAD_STORE_REG_OPERANDS,
        TextRule {
            mnemonic: "str",
            operand_order: &["rt", "mem"],
        },
        &[],
        EncodeRule {
            require: &["store register and register-offset memory"],
            canonical_preference: "str register offset canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "movi_zero_2d"),
        "movi",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0xffe0_fc00,
            value: 0x6f00_e400,
        }],
        MOVI_ZERO_2D_FIELDS,
        MOVI_ZERO_2D_OPERANDS,
        TextRule {
            mnemonic: "movi",
            operand_order: &["rd", "imm"],
        },
        &[],
        EncodeRule {
            require: &["vector register and zero immediate"],
            canonical_preference: "movi zero 2d canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "brk"),
        "brk",
        InstructionKind::System,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0xffe0_001f,
            value: 0xd420_0000,
        }],
        BRK_FIELDS,
        BRK_OPERANDS,
        TextRule {
            mnemonic: "brk",
            operand_order: &["imm"],
        },
        &[],
        EncodeRule {
            require: &["breakpoint immediate"],
            canonical_preference: "brk canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "mov_wide"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f80_0000,
            value: 0x5280_0000,
        }],
        MOVE_WIDE_FIELDS,
        MOVE_WIDE_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rd", "imm"],
        },
        &[],
        EncodeRule {
            require: &["register and move-wide immediate"],
            canonical_preference: "mov text maps to movz encoding",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "movk"),
        "movk",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f80_0000,
            value: 0x7280_0000,
        }],
        MOVE_WIDE_FIELDS,
        MOVE_WIDE_OPERANDS,
        TextRule {
            mnemonic: "movk",
            operand_order: &["rd", "imm"],
        },
        &[],
        EncodeRule {
            require: &["register and move-wide immediate"],
            canonical_preference: "movk immediate canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "movn"),
        "movn",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f80_0000,
            value: 0x1280_0000,
        }],
        MOVE_WIDE_FIELDS,
        MOVE_WIDE_OPERANDS,
        TextRule {
            mnemonic: "movn",
            operand_order: &["rd", "imm"],
        },
        &[],
        EncodeRule {
            require: &["register and move-wide immediate"],
            canonical_preference: "movn immediate canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "mov_reg"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7fe0_ffe0,
            value: 0x2a00_03e0,
        }],
        MOV_REG_FIELDS,
        MOV_REG_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rd", "rm"],
        },
        &[],
        EncodeRule {
            require: &["register to register move alias"],
            canonical_preference: "mov register alias",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "and_imm"),
        "and",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f80_0000,
            value: 0x1200_0000,
        }],
        LOGICAL_IMM_FIELDS,
        LOGICAL_IMM_OPERANDS,
        TextRule {
            mnemonic: "and",
            operand_order: &["rd", "rn", "imm"],
        },
        &[],
        EncodeRule {
            require: &["logical immediate operands"],
            canonical_preference: "and immediate canonical form",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "mov_imm"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[
            Matcher::MaskEq {
                mask: 0x7f80_0000,
                value: 0x3200_0000,
            },
            Matcher::MaskEq {
                mask: 0x3e0,
                value: 0x3e0,
            },
        ],
        LOGICAL_IMM_FIELDS,
        MOV_IMM_OPERANDS,
        TextRule {
            mnemonic: "mov",
            operand_order: &["rd", "imm"],
        },
        &[],
        EncodeRule {
            require: &["logical immediate move alias"],
            canonical_preference: "mov logical immediate alias",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "lsr_imm"),
        "lsr",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f80_0000,
            value: 0x5300_0000,
        }],
        LSR_IMM_FIELDS,
        BITFIELD_IMM_OPERANDS,
        TextRule {
            mnemonic: "lsr",
            operand_order: &["rd", "rn", "shift"],
        },
        &[],
        EncodeRule {
            require: &["bitfield lsr alias operands"],
            canonical_preference: "lsr immediate alias",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "lsl_imm"),
        "lsl",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f80_0000,
            value: 0x5300_0000,
        }],
        LSL_IMM_FIELDS,
        BITFIELD_IMM_OPERANDS,
        TextRule {
            mnemonic: "lsl",
            operand_order: &["rd", "rn", "shift"],
        },
        &[],
        EncodeRule {
            require: &["bitfield lsl alias operands"],
            canonical_preference: "lsl immediate alias",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "asr_imm"),
        "asr",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7f80_0000,
            value: 0x1300_0000,
        }],
        ASR_IMM_FIELDS,
        BITFIELD_IMM_OPERANDS,
        TextRule {
            mnemonic: "asr",
            operand_order: &["rd", "rn", "shift"],
        },
        &[],
        EncodeRule {
            require: &["bitfield asr alias operands"],
            canonical_preference: "asr immediate alias",
        },
    ),
    FormSchema::new(
        FormId::new(Architecture::Aarch64, "lsr_reg"),
        "lsr",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        DecodeLayout::FixedWidthBits { width: 32 },
        &[Matcher::MaskEq {
            mask: 0x7fe0_fc00,
            value: 0x1ac0_2400,
        }],
        LSR_REG_FIELDS,
        LSR_REG_OPERANDS,
        TextRule {
            mnemonic: "lsr",
            operand_order: &["rd", "rn", "rm"],
        },
        &[],
        EncodeRule {
            require: &["register shift operands"],
            canonical_preference: "lsr register canonical form",
        },
    ),
];

pub fn all_forms() -> &'static [FormSchema] {
    FORMS
}
