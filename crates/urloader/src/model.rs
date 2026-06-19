use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageFormat {
    Elf,
    Pe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Aarch64,
    X86_64,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageClass {
    Bits32,
    Bits64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryTarget {
    pub format: ImageFormat,
    pub architecture: Architecture,
    pub class: ImageClass,
    pub endian: Endian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadProfile {
    SharedObject,
    Executable,
    Relocatable,
    KernelStyle,
    StrippedLike,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub id: i64,
    pub name: String,
    pub vaddr: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub id: i64,
    pub name: String,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub permissions: String,
    pub flags: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub id: i64,
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: String,
    pub is_import: bool,
    pub is_export: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    pub library: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub addr: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoaderDiagnostic {
    pub code: &'static str,
    pub severity: String,
    pub subject: String,
    pub addr: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetadataConfidence {
    Exact,
    Derived,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormatDetails {
    Elf { file_type: u16, machine: u16 },
    Pe { machine: u16, image_base: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawImage {
    pub format: ImageFormat,
    pub architecture: Architecture,
    pub class: ImageClass,
    pub endian: Endian,
    pub profile: LoadProfile,
    pub entry: u64,
    pub image_base: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<NormalizedRelocation>,
    pub diagnostics: Vec<Diagnostic>,
    pub format_details: FormatDetails,
}

pub type RawSegment = Segment;
pub type RawSection = Section;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappedRange {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub permissions: String,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewSection {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub permissions: String,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub can_map_executable_bytes: bool,
    pub can_translate_va: bool,
    pub can_translate_rva: bool,
    pub has_named_sections: bool,
    pub has_symbols: bool,
    pub has_imports: bool,
    pub has_exports: bool,
    pub has_relocations: bool,
    pub has_debug_lines: bool,
    pub has_debug_function_ranges: bool,
    pub has_unwind_ranges: bool,
    pub supports_analysis_entry: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedSymbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: String,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedImport {
    pub library: Option<String>,
    pub name: Option<String>,
    pub slot_addr: Option<u64>,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedExport {
    pub name: Option<String>,
    pub addr: u64,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedRelocation {
    pub addr: u64,
    pub kind: String,
    pub target: Option<u64>,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRange {
    pub start: u64,
    pub end: u64,
    pub name: Option<String>,
    pub source: String,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineEntry {
    pub addr: u64,
    pub file: String,
    pub line: u64,
    pub column: u64,
    pub confidence: MetadataConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugView {
    pub function_ranges: Vec<FunctionRange>,
    pub line_entries: Vec<LineEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwindView {
    pub function_ranges: Vec<FunctionRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryView<'a> {
    pub target: BinaryTarget,
    pub entry: Option<u64>,
    pub image_base: Option<u64>,
    pub bytes: &'a [u8],
    pub ranges: Vec<MappedRange>,
    pub sections: Vec<ViewSection>,
    pub symbols: Vec<NormalizedSymbol>,
    pub imports: Vec<NormalizedImport>,
    pub exports: Vec<NormalizedExport>,
    pub relocations: Vec<NormalizedRelocation>,
    pub debug: Option<DebugView>,
    pub unwind: Option<UnwindView>,
    pub capabilities: CapabilitySet,
    pub diagnostics: Vec<LoaderDiagnostic>,
}

impl BinaryView<'_> {
    pub fn va_to_offset(&self, addr: u64) -> Option<u64> {
        self.ranges.iter().find_map(|range| {
            let end = range.start.checked_add(range.file_size)?;
            if addr >= range.start && addr < end {
                Some(range.file_offset + (addr - range.start))
            } else {
                None
            }
        })
    }

    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        self.va_to_offset(self.image_base?.checked_add(rva)?)
    }

    pub fn executable_ranges(&self) -> Vec<(u64, u64)> {
        self.ranges
            .iter()
            .filter(|range| range.permissions.contains('x'))
            .map(|range| (range.start, range.end))
            .collect()
    }

    pub fn bytes_at(&self, addr: u64, size: usize) -> Option<&[u8]> {
        let offset = self.va_to_offset(addr)? as usize;
        self.bytes.get(offset..offset.checked_add(size)?)
    }
}
