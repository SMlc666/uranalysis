use crate::{LoadError, LoadedImage, Result};

pub fn load(_bytes: &[u8]) -> Result<LoadedImage> {
    Err(LoadError::Unsupported {
        format: "PE",
        field: "parser",
        value: "awaiting format-specific test".to_string(),
    })
}
