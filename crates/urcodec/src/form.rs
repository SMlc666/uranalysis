use crate::{
    error::DecodeError,
    model::{Architecture, FlowKind, Instruction, InstructionKind},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FormId {
    architecture: Architecture,
    local_name: &'static str,
}

impl FormId {
    pub const fn new(architecture: Architecture, local_name: &'static str) -> Self {
        Self {
            architecture,
            local_name,
        }
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn local_name(&self) -> &'static str {
        self.local_name
    }

    pub fn name(&self) -> String {
        let arch = match self.architecture {
            Architecture::Aarch64 => "aarch64",
            Architecture::X86_64 => "x86_64",
        };
        format!("{arch}.{}", self.local_name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeLayout {
    FixedWidthBits { width: u8 },
    ByteStream(ByteStreamLayout),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteStreamLayout {
    pub opcode_len: u8,
    pub uses_modrm: bool,
    pub uses_sib: bool,
    pub displacement_bytes: Option<u8>,
    pub immediate_bytes: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matcher {
    MaskEq { mask: u32, value: u32 },
    OpcodeEq(&'static [u8]),
    ByteMaskedEq { offset: u8, mask: u8, value: u8 },
    OpcodeExt { reg: u8 },
    ModrmMode { mode: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSource {
    Bits { start: u8, end: u8 },
    SignedBits { start: u8, end: u8 },
    Literal(i64),
    Aarch64AdrTarget { page: bool },
    Aarch64AddSubImmediate,
    Aarch64TbzBit,
    Aarch64MoveWideImmediate,
    Aarch64LogicalImmediate,
    Aarch64BitfieldLsrImmediate,
    Aarch64BitfieldLslImmediate,
    Aarch64BitfieldAsrImmediate,
    OpcodeLowBits { offset: u8, mask: u8 },
    OpcodeRegister { offset: u8 },
    VexVvvv,
    ModrmReg,
    ModrmRm,
    ByteAt { offset: u8 },
    Immediate8,
    SignedImmediate8,
    Immediate16,
    Immediate32,
    SignedImmediate32,
    Immediate64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: &'static str,
    pub source: FieldSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperandSpec {
    FixedRegister {
        name: &'static str,
    },
    FixedMemory {
        base: &'static str,
        width_bits: u16,
    },
    Register {
        field: &'static str,
        bank: &'static str,
    },
    ShiftedRegister {
        reg_field: &'static str,
        shift_field: &'static str,
        amount_field: &'static str,
        bank: &'static str,
    },
    Immediate {
        field: &'static str,
    },
    RelativeTarget {
        field: &'static str,
        scale: u8,
        add_instruction_size: bool,
    },
    AbsoluteTarget {
        field: &'static str,
    },
    Condition {
        field: &'static str,
        table: &'static str,
    },
    Memory {
        kind: MemorySpec,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemorySpec {
    X86Modrm {
        width_bits: u16,
    },
    Aarch64UnsignedOffset {
        base_field: &'static str,
        offset_field: &'static str,
    },
    Aarch64SignedOffset {
        base_field: &'static str,
        offset_field: &'static str,
        writeback: bool,
        post_index: bool,
    },
    Aarch64RegisterOffset {
        base_field: &'static str,
        index_field: &'static str,
        scaled_field: &'static str,
    },
    Aarch64PairOffset {
        base_field: &'static str,
        offset_field: &'static str,
        writeback: bool,
        post_index: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasRule {
    pub mnemonic: &'static str,
    pub when: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeRule {
    pub require: &'static [&'static str],
    pub canonical_preference: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextRule {
    pub mnemonic: &'static str,
    pub operand_order: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormSchema {
    id: FormId,
    mnemonic: &'static str,
    kind: InstructionKind,
    flow: FlowKind,
    decode_layout: DecodeLayout,
    matchers: &'static [Matcher],
    fields: &'static [FieldSpec],
    operands: &'static [OperandSpec],
    text_rule: TextRule,
    aliases: &'static [AliasRule],
    encode_rule: EncodeRule,
}

impl FormSchema {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        id: FormId,
        mnemonic: &'static str,
        kind: InstructionKind,
        flow: FlowKind,
        decode_layout: DecodeLayout,
        matchers: &'static [Matcher],
        fields: &'static [FieldSpec],
        operands: &'static [OperandSpec],
        text_rule: TextRule,
        aliases: &'static [AliasRule],
        encode_rule: EncodeRule,
    ) -> Self {
        Self {
            id,
            mnemonic,
            kind,
            flow,
            decode_layout,
            matchers,
            fields,
            operands,
            text_rule,
            aliases,
            encode_rule,
        }
    }

    pub const fn id(&self) -> &FormId {
        &self.id
    }

    pub const fn mnemonic(&self) -> &'static str {
        self.mnemonic
    }

    pub const fn kind(&self) -> InstructionKind {
        self.kind
    }

    pub const fn flow(&self) -> FlowKind {
        self.flow
    }

    pub const fn decode_layout(&self) -> DecodeLayout {
        self.decode_layout
    }

    pub const fn matchers(&self) -> &'static [Matcher] {
        self.matchers
    }

    pub const fn fields(&self) -> &'static [FieldSpec] {
        self.fields
    }

    pub const fn operands(&self) -> &'static [OperandSpec] {
        self.operands
    }

    pub const fn text_rule(&self) -> &TextRule {
        &self.text_rule
    }

    pub const fn aliases(&self) -> &'static [AliasRule] {
        self.aliases
    }

    pub const fn encode_rule(&self) -> &EncodeRule {
        &self.encode_rule
    }
}

#[derive(Debug, Clone)]
pub struct InstructionForm {
    id: FormId,
    mnemonic: &'static str,
    kind: InstructionKind,
    flow: FlowKind,
    decode: fn(&[u8], u64) -> Result<Option<Instruction>, DecodeError>,
    encode: fn(&Instruction) -> Option<Vec<u8>>,
    parse: fn(&str, u64) -> Option<Instruction>,
}

impl InstructionForm {
    pub const fn new(
        id: FormId,
        mnemonic: &'static str,
        kind: InstructionKind,
        flow: FlowKind,
        decode: fn(&[u8], u64) -> Result<Option<Instruction>, DecodeError>,
        encode: fn(&Instruction) -> Option<Vec<u8>>,
        parse: fn(&str, u64) -> Option<Instruction>,
    ) -> Self {
        Self {
            id,
            mnemonic,
            kind,
            flow,
            decode,
            encode,
            parse,
        }
    }

    pub fn id(&self) -> &FormId {
        &self.id
    }

    pub fn mnemonic(&self) -> &'static str {
        self.mnemonic
    }

    pub fn kind(&self) -> InstructionKind {
        self.kind
    }

    pub fn flow(&self) -> FlowKind {
        self.flow
    }

    pub fn decode(&self, bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
        (self.decode)(bytes, address)
    }

    pub fn encode(&self, instruction: &Instruction) -> Option<Vec<u8>> {
        (self.encode)(instruction)
    }

    pub fn parse(&self, text: &str, address: u64) -> Option<Instruction> {
        (self.parse)(text, address)
    }
}
