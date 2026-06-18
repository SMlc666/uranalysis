use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageClass {
    Bits32,
    Bits64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
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
    pub class: ImageClass,
    pub endian: Endian,
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
    pub kind: InstructionKind,
    pub flow: FlowKind,
    pub fallthrough: Option<u64>,
    pub branch_target: Option<u64>,
    pub decode_status: DecodeStatus,
    pub decoder: String,
    pub decoder_version: String,
    pub function_addr: Option<u64>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UserFacts {
    pub renames: BTreeMap<u64, String>,
    pub comments: BTreeMap<u64, String>,
    pub manual_function_roots: BTreeSet<u64>,
    pub manual_function_ranges: BTreeMap<u64, (u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PassId {
    Decode,
    Strings,
    Cfg,
    Functions,
    Xrefs,
    Diagnostics,
}

impl PassId {
    pub fn as_str(self) -> &'static str {
        match self {
            PassId::Decode => "decode",
            PassId::Strings => "strings",
            PassId::Cfg => "cfg",
            PassId::Functions => "functions",
            PassId::Xrefs => "xrefs",
            PassId::Diagnostics => "diagnostics",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BasicBlockSource {
    Entry,
    BranchTarget,
    Fallthrough,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: i64,
    pub function_addr: Option<u64>,
    pub start: u64,
    pub end: u64,
    pub terminal_addr: Option<u64>,
    pub instruction_count: usize,
    pub source: BasicBlockSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgEdgeKind {
    Fallthrough,
    Branch,
    ConditionalTrue,
    ConditionalFalse,
    Call,
    Return,
    Indirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from_block: i64,
    pub to_block: Option<i64>,
    pub from_addr: u64,
    pub to_addr: Option<u64>,
    pub kind: CfgEdgeKind,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AnalysisState {
    pub instructions: Vec<Instruction>,
    pub strings: Vec<StringRef>,
    pub basic_blocks: Vec<BasicBlock>,
    pub cfg_edges: Vec<CfgEdge>,
    pub functions: Vec<Function>,
    pub xrefs: Vec<Xref>,
    pub diagnostics: Vec<Diagnostic>,
}
