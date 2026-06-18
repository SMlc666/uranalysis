use thiserror::Error;

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported project format: {0}")]
    UnsupportedFormat(String),
    #[error("decode project payload: {0}")]
    Decode(String),
    #[error("encode project payload: {0}")]
    Encode(String),
}
