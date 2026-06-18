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
            Architecture::Aarch64 => crate::arch::aarch64::forms::parse(text, address),
            Architecture::X86_64 => crate::arch::x86_64::forms::parse(text, address),
        }
    }
}

pub fn format_instruction(instruction: &Instruction) -> String {
    let operands = instruction.operand_text();
    if operands.is_empty() {
        instruction.mnemonic.clone()
    } else {
        format!("{} {operands}", instruction.mnemonic)
    }
}
