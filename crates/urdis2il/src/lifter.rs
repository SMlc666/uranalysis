use crate::{
    model::{IlInstruction, IlStmt},
    Result,
};

#[derive(Debug, Clone, Copy)]
pub struct Lifter {
    architecture: urcodec::Architecture,
}

impl Lifter {
    pub fn new(architecture: urcodec::Architecture) -> Self {
        Self { architecture }
    }

    pub fn architecture(&self) -> urcodec::Architecture {
        self.architecture
    }

    pub fn lift_instruction(&self, instruction: &urcodec::Instruction) -> Result<IlInstruction> {
        if instruction.status != urcodec::DecodeStatus::Complete {
            return Ok(unsupported_instruction(
                instruction,
                "unknown decode status",
            ));
        }
        match self.architecture {
            urcodec::Architecture::Aarch64 => crate::aarch64::lift(instruction),
            urcodec::Architecture::X86_64 => crate::x86_64::lift(instruction),
        }
    }
}

pub(crate) fn unsupported_instruction(
    instruction: &urcodec::Instruction,
    reason: &str,
) -> IlInstruction {
    IlInstruction {
        address: instruction.address,
        size: instruction.size,
        statements: vec![IlStmt::Unsupported {
            address: instruction.address,
            mnemonic: instruction.mnemonic.clone(),
            reason: reason.to_string(),
        }],
        terminator: None,
    }
}
