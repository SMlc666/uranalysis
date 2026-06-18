use crate::{
    error::EncodeError,
    model::{Architecture, Instruction},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncodeOptions {
    _reserved: (),
}

#[derive(Debug, Clone)]
pub struct Encoder {
    architecture: Architecture,
    options: EncodeOptions,
}

impl Encoder {
    pub fn new(architecture: Architecture, options: EncodeOptions) -> Result<Self, EncodeError> {
        Ok(Self {
            architecture,
            options,
        })
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn options(&self) -> EncodeOptions {
        self.options
    }

    pub fn encode_one(&self, instruction: &Instruction) -> Result<Vec<u8>, EncodeError> {
        match self.architecture {
            Architecture::Aarch64 => crate::arch::aarch64::forms::encode(instruction),
            Architecture::X86_64 => crate::arch::x86_64::forms::encode(instruction),
        }
    }
}
