use crate::{
    arch::{aarch64, x86_64},
    error::{DecodeError, Result},
    model::{Architecture, DecodeOptions, Endian, Instruction},
};

#[derive(Debug, Clone)]
pub struct Decoder {
    architecture: Architecture,
    options: DecodeOptions,
}

impl Decoder {
    pub fn new(architecture: Architecture, options: DecodeOptions) -> Result<Self> {
        match (architecture, options.endian) {
            (Architecture::Aarch64 | Architecture::X86_64, Endian::Little) => Ok(Self {
                architecture,
                options,
            }),
        }
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn options(&self) -> DecodeOptions {
        self.options
    }

    pub fn decode_one(&self, bytes: &[u8], address: u64) -> Result<Instruction> {
        match self.architecture {
            Architecture::Aarch64 => {
                if let Some(instruction) = aarch64::forms::decode(bytes, address)? {
                    Ok(instruction)
                } else {
                    let word = Self::require_word(bytes)?;
                    Ok(aarch64::decode::decode_word(word, address))
                }
            }
            Architecture::X86_64 => {
                if let Some(instruction) = x86_64::forms::decode(bytes, address)? {
                    Ok(instruction)
                } else {
                    x86_64::decode::decode_instruction(bytes, address)
                }
            }
        }
    }

    pub fn require_word(bytes: &[u8]) -> Result<u32> {
        let word = bytes.get(..4).ok_or(DecodeError::TruncatedInstruction {
            expected: 4,
            actual: bytes.len(),
        })?;
        Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
    }
}
