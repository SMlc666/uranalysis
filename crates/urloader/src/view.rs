use crate::{
    model::{
        BinaryTarget, BinaryView, CapabilitySet, LoadedImage, LoaderDiagnostic, MappedRange,
        MetadataConfidence, NormalizedExport, NormalizedImport, NormalizedSymbol, ViewSection,
    },
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

        let symbols = self
            .symbols
            .iter()
            .map(|symbol| NormalizedSymbol {
                name: symbol.name.clone(),
                addr: symbol.addr,
                size: symbol.size,
                kind: symbol.kind.clone(),
                source: "legacy:symbol".to_string(),
                confidence: MetadataConfidence::Exact,
            })
            .collect();
        let imports = self
            .imports
            .iter()
            .map(|import| NormalizedImport {
                library: import.library.clone(),
                name: Some(import.name.clone()),
                slot_addr: None,
                source: "legacy:import".to_string(),
                confidence: MetadataConfidence::Exact,
            })
            .collect();
        let exports = self
            .exports
            .iter()
            .map(|export| NormalizedExport {
                name: Some(export.name.clone()),
                addr: export.addr,
                source: "legacy:export".to_string(),
                confidence: MetadataConfidence::Exact,
            })
            .collect();

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
            relocations: Vec::new(),
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
                has_relocations: false,
                has_debug_lines: false,
                has_debug_function_ranges: false,
                has_unwind_ranges: false,
                supports_analysis_entry: true,
            },
            diagnostics: Vec::<LoaderDiagnostic>::new(),
        })
    }
}
