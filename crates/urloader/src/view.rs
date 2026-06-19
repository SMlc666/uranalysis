use crate::{
    model::{
        BinaryTarget, BinaryView, CapabilitySet, DebugView, FunctionRange, LineEntry,
        LoaderDiagnostic, MappedRange, MetadataConfidence, RawImage, UnwindView, ViewSection,
    },
    normalize::{normalize_exports, normalize_imports, normalize_symbols},
    ViewBuildError,
};
use gimli::{AttributeValue, ColumnType, Dwarf, EndianSlice, RunTimeEndian};

impl RawImage {
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
        let debug = build_debug_view(self, bytes);
        let has_debug_lines = debug
            .as_ref()
            .is_some_and(|debug| !debug.line_entries.is_empty());
        let has_debug_function_ranges = debug
            .as_ref()
            .is_some_and(|debug| !debug.function_ranges.is_empty());
        let unwind = build_unwind_view(self, bytes);
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
            debug,
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
                has_debug_lines,
                has_debug_function_ranges,
                has_unwind_ranges,
                supports_analysis_entry: true,
            },
            diagnostics: Vec::<LoaderDiagnostic>::new(),
        })
    }
}

fn build_debug_view(image: &RawImage, bytes: &[u8]) -> Option<DebugView> {
    if image.format != crate::ImageFormat::Elf {
        return None;
    }

    let endian = match image.endian {
        crate::Endian::Little => RunTimeEndian::Little,
        crate::Endian::Big => RunTimeEndian::Big,
    };

    let dwarf = Dwarf::load(
        |id| -> Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
            Ok(EndianSlice::new(
                section_bytes_by_name(image, bytes, id.name()).unwrap_or(&[]),
                endian,
            ))
        },
    )
    .ok()?;

    let mut line_entries = Vec::new();
    let mut function_ranges = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next().ok()? {
        let unit = dwarf.unit(header).ok()?;

        if let Some(program) = unit.line_program.clone() {
            let header = program.header().clone();
            let mut rows = program.rows();
            while let Some((_, row)) = rows.next_row().ok()? {
                let Some(file) = row.file(&header) else {
                    continue;
                };
                let file_name = dwarf_attr_string(&dwarf, &unit, file.path_name())?;
                line_entries.push(LineEntry {
                    addr: row.address(),
                    file: file_name,
                    line: row.line().map(|line| line.get()).unwrap_or(0),
                    column: match row.column() {
                        ColumnType::LeftEdge => 0,
                        ColumnType::Column(column) => column.get(),
                    },
                    confidence: MetadataConfidence::Exact,
                });
            }
        }

        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs().ok()? {
            if entry.tag() != gimli::constants::DW_TAG_subprogram {
                continue;
            }
            let low_pc = match entry
                .attr_value(gimli::constants::DW_AT_low_pc)
                .ok()
                .flatten()?
            {
                AttributeValue::Addr(addr) => addr,
                _ => continue,
            };
            let high_pc_attr = entry
                .attr_value(gimli::constants::DW_AT_high_pc)
                .ok()
                .flatten()?;
            let high_pc = match high_pc_attr {
                AttributeValue::Addr(addr) => addr,
                AttributeValue::Udata(size) => low_pc.checked_add(size)?,
                _ => continue,
            };
            let name = entry
                .attr_value(gimli::constants::DW_AT_linkage_name)
                .ok()
                .flatten()
                .or_else(|| {
                    entry
                        .attr_value(gimli::constants::DW_AT_name)
                        .ok()
                        .flatten()
                })
                .and_then(|value| dwarf_attr_string(&dwarf, &unit, value));

            function_ranges.push(FunctionRange {
                start: low_pc,
                end: high_pc,
                name,
                source: "dwarf:subprogram".to_string(),
                confidence: MetadataConfidence::Exact,
            });
        }
    }

    if line_entries.is_empty() && function_ranges.is_empty() {
        None
    } else {
        Some(DebugView {
            function_ranges,
            line_entries,
        })
    }
}

fn build_unwind_view(image: &RawImage, bytes: &[u8]) -> Option<UnwindView> {
    match image.format {
        crate::ImageFormat::Elf => build_elf_unwind_view(image, bytes),
        crate::ImageFormat::Pe => build_pe_unwind_view(image, bytes),
    }
}

fn build_elf_unwind_view(image: &RawImage, bytes: &[u8]) -> Option<UnwindView> {
    let section = image
        .sections
        .iter()
        .find(|section| section.name == ".eh_frame")?;
    let bytes = section_bytes(image, bytes, section)?;
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

fn build_pe_unwind_view(image: &RawImage, bytes: &[u8]) -> Option<UnwindView> {
    let section = image
        .sections
        .iter()
        .find(|section| section.name == ".pdata")?;
    let bytes = section_bytes(image, bytes, section)?;
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

fn section_bytes<'a>(
    image: &RawImage,
    bytes: &'a [u8],
    section: &crate::Section,
) -> Option<&'a [u8]> {
    let start = section.offset as usize;
    let end = start.checked_add(section.size as usize)?;
    let _ = image;
    bytes.get(start..end).or_else(|| bytes.get(start..))
}

fn section_bytes_by_name<'a>(image: &RawImage, bytes: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let section = image.sections.iter().find(|section| section.name == name)?;
    section_bytes(image, bytes, section)
}

fn dwarf_attr_string(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    value: AttributeValue<EndianSlice<'_, RunTimeEndian>>,
) -> Option<String> {
    let reader = dwarf.attr_string(unit, value).ok()?;
    Some(String::from_utf8_lossy(reader.slice()).into_owned())
}
