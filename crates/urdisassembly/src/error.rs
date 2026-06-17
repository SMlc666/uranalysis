use thiserror::Error;

pub type Result<T> = std::result::Result<T, DecodeError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unsupported architecture/endian combination")]
    UnsupportedTarget,
    #[error("expected at least {expected} bytes, got {actual}")]
    TruncatedInstruction { expected: usize, actual: usize },
}
