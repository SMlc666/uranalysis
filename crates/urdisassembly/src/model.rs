use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
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
pub struct MemoryOperand {
    pub base: Register,
    pub offset: i64,
    pub writeback: bool,
    pub post_index: bool,
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
