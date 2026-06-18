use thiserror::Error;

pub type Result<T> = std::result::Result<T, LoadError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoadError {
    #[error("unknown binary format")]
    UnknownFormat,
    #[error("{format}: truncated {field}")]
    Truncated {
        format: &'static str,
        field: &'static str,
    },
    #[error("{format}: unsupported {field}: {value}")]
    Unsupported {
        format: &'static str,
        field: &'static str,
        value: String,
    },
    #[error("{format}: malformed {field}: {message}")]
    Malformed {
        format: &'static str,
        field: &'static str,
        message: String,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ViewBuildError {
    #[error("front-end view missing executable mapping")]
    MissingExecutableMapping,
    #[error("front-end view missing analysis entry")]
    MissingAnalysisEntry,
}
