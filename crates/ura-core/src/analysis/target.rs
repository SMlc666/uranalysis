use crate::{
    model::{Architecture, BinaryFormat, Endian, ImageClass},
    Result, UraError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisTarget {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub class: ImageClass,
    pub endian: Endian,
}

impl AnalysisTarget {
    pub fn from_loaded(image: &urloader::LoadedImage) -> Result<Self> {
        let target = Self {
            format: convert_format(image.format),
            architecture: convert_architecture(image.architecture)?,
            class: convert_class(image.class),
            endian: convert_endian(image.endian)?,
        };
        target.ensure_supported()?;
        Ok(target)
    }

    fn ensure_supported(self) -> Result<()> {
        match (self.format, self.architecture, self.class, self.endian) {
            (BinaryFormat::Elf, Architecture::Aarch64, ImageClass::Bits64, Endian::Little)
            | (BinaryFormat::Elf, Architecture::X86_64, ImageClass::Bits64, Endian::Little)
            | (BinaryFormat::Pe, Architecture::X86_64, ImageClass::Bits64, Endian::Little) => {
                Ok(())
            }
            _ => Err(UraError::Unsupported(format!(
                "unsupported analysis target: format={:?} architecture={:?} class={:?} endian={:?}",
                self.format, self.architecture, self.class, self.endian
            ))),
        }
    }
}

fn convert_format(format: urloader::ImageFormat) -> BinaryFormat {
    match format {
        urloader::ImageFormat::Elf => BinaryFormat::Elf,
        urloader::ImageFormat::Pe => BinaryFormat::Pe,
    }
}

fn convert_architecture(architecture: urloader::Architecture) -> Result<Architecture> {
    match architecture {
        urloader::Architecture::Aarch64 => Ok(Architecture::Aarch64),
        urloader::Architecture::X86_64 => Ok(Architecture::X86_64),
        urloader::Architecture::Unknown(value) => Err(UraError::Unsupported(format!(
            "unsupported architecture: {value}"
        ))),
    }
}

fn convert_class(class: urloader::ImageClass) -> ImageClass {
    match class {
        urloader::ImageClass::Bits32 => ImageClass::Bits32,
        urloader::ImageClass::Bits64 => ImageClass::Bits64,
    }
}

fn convert_endian(endian: urloader::Endian) -> Result<Endian> {
    match endian {
        urloader::Endian::Little => Ok(Endian::Little),
        urloader::Endian::Big => Err(UraError::Unsupported(
            "unsupported big-endian image".to_string(),
        )),
    }
}
