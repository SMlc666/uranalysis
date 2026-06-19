use crate::{
    model::{
        BinaryTarget, BinaryView, CapabilitySet, FunctionRange, LoadedImage, LoaderDiagnostic,
        MappedRange, MetadataConfidence, UnwindView, ViewSection,
    },
    normalize::{normalize_exports, normalize_imports, normalize_symbols},
    ViewBuildError,
};

impl LoadedImage {
    pub fn analysis_view<'a>(&'a self, bytes: &'a [u8]) -> Result<BinaryView<'a>, ViewBuildError> {
        let ranges = self
            .segments
            .iter()
            .map(|segment| MappedRange {
                start: segment.vaddr,
                end: segment.vaddr + segment.mem_size,
                file_offset: segment.file_offset,
                file_size: segment.file_size,
                mem_size: segment.mem_size,
                permissions: segment.permissions.clone(),
                provenance: segment.name.clone(),
            })
            .collect::<Vec<_>>();
        if !ranges.iter().any(|range| range.permissions.contains('x')) {
            return Err(ViewBuildError::MissingExecutableMapping);
        }
        if self.entry == 0 {
            return Err(ViewBuildError::MissingAnalysisEntry);
        }

        let symbols = normalize_symbols(self.format, &self.symbols);
        let imports = normalize_imports(self.format, &self.imports);
        let exports = normalize_exports(self.format, &self.exports);
        let unwind = build_unwind_view(self);
        let has_unwind_ranges = unwind
            .as_ref()
            .is_some_and(|unwind| !unwind.function_ranges.is_empty());

        Ok(BinaryView {
            target: BinaryTarget {
                format: self.format,
                architecture: self.architecture,
                class: self.class,
                endian: self.endian,
            },
            entry: Some(self.entry),
            image_base: Some(self.image_base),
            bytes,
            ranges,
            sections: self
                .sections
                .iter()
                .map(|section| ViewSection {
                    name: section.name.clone(),
                    start: section.addr,
                    end: section.addr + section.size,
                    file_offset: section.offset,
                    permissions: section.permissions.clone(),
                    provenance: "section".to_string(),
                })
                .collect(),
            symbols,
            imports,
            exports,
            relocations: self.relocations.clone(),
            debug: None,
            unwind,
            capabilities: CapabilitySet {
                can_map_executable_bytes: true,
                can_translate_va: true,
                can_translate_rva: self.image_base != 0,
                has_named_sections: !self.sections.is_empty(),
                has_symbols: !self.symbols.is_empty(),
                has_imports: !self.imports.is_empty(),
                has_exports: !self.exports.is_empty(),
                has_relocations: !self.relocations.is_empty(),
                has_debug_lines: false,
                has_debug_function_ranges: false,
                has_unwind_ranges,
                supports_analysis_entry: true,
            },
            diagnostics: Vec::<LoaderDiagnostic>::new(),
        })
    }
}

fn build_unwind_view(image: &LoadedImage) -> Option<UnwindView> {
    match image.format {
        crate::ImageFormat::Elf => build_elf_unwind_view(image),
        crate::ImageFormat::Pe => build_pe_unwind_view(image),
    }
}

fn build_elf_unwind_view(image: &LoadedImage) -> Option<UnwindView> {
    let section = image.sections.iter().find(|section| section.name == ".eh_frame")?;
    let bytes = section_bytes(image, section)?;
    let mut function_ranges = Vec::new();
    let mut off = 0usize;
    while off + 16 <= bytes.len() {
        let range_start = u64::from_le_bytes(bytes[off..off + 8].try_into().ok()?);
        let range_size = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().ok()?);
        if range_start == 0 || range_size == 0 {
            break;
        }
        function_ranges.push(FunctionRange {
            start: range_start,
            end: range_start + range_size,
            name: None,
            source: "elf:eh_frame".to_string(),
            confidence: MetadataConfidence::Derived,
        });
        off += 16;
    }
    Some(UnwindView { function_ranges })
}

fn build_pe_unwind_view(image: &LoadedImage) -> Option<UnwindView> {
    let section = image.sections.iter().find(|section| section.name == ".pdata")?;
    let bytes = section_bytes(image, section)?;
    let mut function_ranges = Vec::new();
    let mut off = 0usize;
    while off + 12 <= bytes.len() {
        let begin_rva = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
        let end_rva = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().ok()?);
        if begin_rva == 0 || end_rva == 0 {
            break;
        }
        function_ranges.push(FunctionRange {
            start: image.image_base + u64::from(begin_rva),
            end: image.image_base + u64::from(end_rva),
            name: None,
            source: "pe:pdata".to_string(),
            confidence: MetadataConfidence::Derived,
        });
        off += 12;
    }
    Some(UnwindView { function_ranges })
}

fn section_bytes<'a>(image: &'a LoadedImage, section: &crate::Section) -> Option<&'a [u8]> {
    let start = section.offset as usize;
    let end = start.checked_add(section.size as usize)?;
    image.bytes.get(start..end).or_else(|| image.bytes.get(start..))
}
