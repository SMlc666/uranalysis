use thiserror::Error;

pub type Result<T> = std::result::Result<T, UraError>;

#[derive(Debug, Error)]
pub enum UraError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("ELF parse error: {0}")]
    Elf(String),
    #[error("unsupported binary: {0}")]
    Unsupported(String),
    #[error("invalid address: 0x{0:x}")]
    InvalidAddress(u64),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("analysis error: {0}")]
    Analysis(String),
}
