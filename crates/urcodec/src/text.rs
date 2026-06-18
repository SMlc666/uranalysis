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
    let operands = if instruction.text.is_empty() {
        instruction
            .operands
            .iter()
            .map(|operand| match operand {
                crate::model::Operand::Register(register) => register.name.clone(),
                crate::model::Operand::ShiftedRegister(shifted) => {
                    format!(
                        "{}, {} #0x{:x}",
                        shifted.register.name, shifted.shift, shifted.amount
                    )
                }
                crate::model::Operand::Immediate(value) => format!("#0x{:x}", value),
                crate::model::Operand::AbsoluteAddress(addr) => format!("0x{addr:x}"),
                crate::model::Operand::Memory(memory) => {
                    if let Some(base) = &memory.base {
                        if memory.offset == 0 {
                            format!("[{}]", base.name)
                        } else {
                            format!("[{}, #0x{:x}]", base.name, memory.offset)
                        }
                    } else {
                        "[]".to_string()
                    }
                }
                crate::model::Operand::Condition(condition) => condition.clone(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        instruction.operand_text()
    };
    if operands.is_empty() {
        instruction.mnemonic.clone()
    } else {
        format!("{} {operands}", instruction.mnemonic)
    }
}
