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
