use crate::{
    model::{IlInstruction, IlStmt},
    Result,
};

#[derive(Debug, Clone, Copy)]
pub struct Lifter {
    architecture: urdisassembly::Architecture,
}

impl Lifter {
    pub fn new(architecture: urdisassembly::Architecture) -> Self {
        Self { architecture }
    }

    pub fn architecture(&self) -> urdisassembly::Architecture {
        self.architecture
    }

    pub fn lift_instruction(
        &self,
        instruction: &urdisassembly::Instruction,
    ) -> Result<IlInstruction> {
        if instruction.status != urdisassembly::DecodeStatus::Complete {
            return Ok(unsupported_instruction(
                instruction,
                "unknown decode status",
            ));
        }
        match self.architecture {
            urdisassembly::Architecture::Aarch64 => crate::aarch64::lift(instruction),
            urdisassembly::Architecture::X86_64 => crate::x86_64::lift(instruction),
        }
    }
}

pub(crate) fn unsupported_instruction(
    instruction: &urdisassembly::Instruction,
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
