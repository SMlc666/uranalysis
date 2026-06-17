mod elf;
mod error;
mod model;
mod pe;

pub use error::{LoadError, Result};
pub use model::{
    Architecture, Diagnostic, Endian, Export, FormatDetails, ImageClass, ImageFormat, Import,
    LoadProfile, LoadedImage, Section, Segment, Symbol,
};

pub fn load(bytes: &[u8]) -> Result<LoadedImage> {
    if bytes.starts_with(b"\x7fELF") {
        return elf::load(bytes);
    }
    if bytes.starts_with(b"MZ") {
        return pe::load(bytes);
    }
    Err(LoadError::UnknownFormat)
}
