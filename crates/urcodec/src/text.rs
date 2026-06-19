use crate::{
    error::TextError,
    model::{Architecture, Instruction},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TextOptions {
    _reserved: (),
}

#[derive(Debug, Clone)]
pub struct TextParser {
    architecture: Architecture,
    options: TextOptions,
}

impl TextParser {
    pub fn new(architecture: Architecture, options: TextOptions) -> Result<Self, TextError> {
        Ok(Self {
            architecture,
            options,
        })
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn options(&self) -> TextOptions {
        self.options
    }

    pub fn parse_one(&self, text: &str, address: u64) -> Result<Instruction, TextError> {
        match self.architecture {
            Architecture::Aarch64 => crate::runtime::parse_one(
                self.architecture,
                crate::arch::aarch64::forms::all_forms(),
                text,
                address,
            ),
            Architecture::X86_64 => crate::runtime::parse_one(
                self.architecture,
                crate::arch::x86_64::forms::all_forms(),
                text,
                address,
            ),
        }
    }
}

pub fn format_instruction(instruction: &Instruction) -> String {
    match instruction.architecture {
        Architecture::Aarch64 => crate::runtime::format_instruction(
            crate::arch::aarch64::forms::all_forms(),
            instruction,
        ),
        Architecture::X86_64 => {
            crate::runtime::format_instruction(crate::arch::x86_64::forms::all_forms(), instruction)
        }
    }
}
