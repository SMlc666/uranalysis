use thiserror::Error;

pub type Result<T> = std::result::Result<T, DecodeError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unsupported architecture/endian combination")]
    UnsupportedTarget,
    #[error("expected at least {expected} bytes, got {actual}")]
    TruncatedInstruction { expected: usize, actual: usize },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodeError {
    #[error("unsupported instruction form: {0}")]
    UnsupportedForm(String),
    #[error("operand mismatch for {0}")]
    OperandMismatch(String),
    #[error("target out of range for {0}")]
    TargetOutOfRange(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TextError {
    #[error("unknown mnemonic: {0}")]
    UnknownMnemonic(String),
    #[error("invalid operand syntax: {0}")]
    InvalidOperand(String),
}
