mod elf;
mod error;
mod model;
mod normalize;
mod pe;
mod view;

pub use error::{LoadError, Result, ViewBuildError};
pub use model::{
    Architecture, BinaryTarget, BinaryView, CapabilitySet, Diagnostic, Endian, Export,
    FormatDetails, ImageClass, ImageFormat, Import, LineEntry, LoadProfile, LoaderDiagnostic,
    MappedRange, MetadataConfidence, NormalizedExport, NormalizedImport, NormalizedRelocation,
    NormalizedSymbol, RawImage, RawSection, RawSegment, Section, Segment, Symbol, UnwindView,
    ViewSection,
};

pub fn load(bytes: &[u8]) -> Result<RawImage> {
    if bytes.starts_with(b"\x7fELF") {
        return elf::load(bytes);
    }
    if bytes.starts_with(b"MZ") {
        return pe::load(bytes);
    }
    Err(LoadError::UnknownFormat)
}
