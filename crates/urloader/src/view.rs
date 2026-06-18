use crate::{
    model::{
        BinaryTarget, BinaryView, CapabilitySet, LoadedImage, LoaderDiagnostic, MappedRange,
        ViewSection,
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
            unwind: None,
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
                has_unwind_ranges: false,
                supports_analysis_entry: true,
            },
            diagnostics: Vec::<LoaderDiagnostic>::new(),
        })
    }
}
