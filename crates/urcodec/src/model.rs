use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodeOptions {
    pub endian: Endian,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            endian: Endian::Little,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub size: u8,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Vec<Operand>,
    pub text: String,
    pub kind: InstructionKind,
    pub flow: FlowKind,
    pub branch_target: Option<u64>,
    pub status: DecodeStatus,
}

impl Instruction {
    pub fn operand_text(&self) -> String {
        self.text
            .strip_prefix(&self.mnemonic)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operand {
    Register(Register),
    ShiftedRegister(ShiftedRegisterOperand),
    Immediate(i64),
    AbsoluteAddress(u64),
    Memory(MemoryOperand),
    Condition(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftedRegisterOperand {
    pub register: Register,
    pub shift: String,
    pub amount: u8,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstructionKind {
    Branch,
    Call,
    Return,
    Compare,
    Load,
    Store,
    Address,
    Arithmetic,
    Logical,
    Move,
    System,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowKind {
    Fallthrough,
    Branch,
    ConditionalBranch,
    Call,
    Return,
    IndirectBranch,
    IndirectCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodeStatus {
    Complete,
    Partial,
    Unknown,
}
