use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadProfile {
    SharedObject,
    Executable,
    Relocatable,
    KernelStyle,
    StrippedLike,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub schema_version: i64,
    pub engine_version: String,
    pub source_hash: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub profile: LoadProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub id: i64,
    pub name: String,
    pub vaddr: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub id: i64,
    pub name: String,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub id: i64,
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: String,
    pub is_import: bool,
    pub is_export: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub addr: u64,
    pub size: u8,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub text: String,
    pub kind: String,
    pub flow: String,
    pub fallthrough: Option<u64>,
    pub branch_target: Option<u64>,
    pub decode_status: String,
    pub decoder: String,
    pub decoder_version: String,
    pub function_addr: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    pub addr: u64,
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub source: FunctionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FunctionSource {
    Symbol,
    Entry,
    BranchTarget,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: i64,
    pub function_addr: u64,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XrefKind {
    Code,
    Call,
    Data,
    String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Xref {
    pub from_addr: u64,
    pub to_addr: u64,
    pub kind: XrefKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringRef {
    pub addr: u64,
    pub value: String,
    pub encoding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub addr: Option<u64>,
    pub severity: String,
    pub message: String,
}
