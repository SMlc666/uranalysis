use crate::{error::DecodeError, model::Architecture};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutView {
    Aarch64Word { word: u32, address: u64 },
    X86ByteStream { bytes: Vec<u8>, address: u64 },
}

pub fn read_layout(
    architecture: Architecture,
    bytes: &[u8],
    address: u64,
) -> Result<LayoutView, DecodeError> {
    match architecture {
        Architecture::Aarch64 => {
            let word = bytes.get(..4).ok_or(DecodeError::TruncatedInstruction {
                expected: 4,
                actual: bytes.len(),
            })?;
            Ok(LayoutView::Aarch64Word {
                word: u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
                address,
            })
        }
        Architecture::X86_64 => {
            if bytes.is_empty() {
                return Err(DecodeError::TruncatedInstruction {
                    expected: 1,
                    actual: 0,
                });
            }
            Ok(LayoutView::X86ByteStream {
                bytes: bytes.to_vec(),
                address,
            })
        }
    }
}
