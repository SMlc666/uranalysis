use thiserror::Error;

pub type Result<T> = std::result::Result<T, LiftError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LiftError {
    #[error("instruction architecture mismatch: lifter={lifter:?} instruction={instruction:?}")]
    ArchitectureMismatch {
        lifter: urcodec::Architecture,
        instruction: urcodec::Architecture,
    },
}
