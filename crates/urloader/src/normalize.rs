use crate::{
    Export, ImageFormat, Import, MetadataConfidence, NormalizedExport, NormalizedImport,
    NormalizedRelocation, NormalizedSymbol, Symbol,
};

pub fn normalize_symbols(format: ImageFormat, symbols: &[Symbol]) -> Vec<NormalizedSymbol> {
    let source = match format {
        ImageFormat::Elf => "elf:symtab",
        ImageFormat::Pe => "pe:symbol",
    };
    symbols
        .iter()
        .map(|symbol| NormalizedSymbol {
            name: symbol.name.clone(),
            addr: symbol.addr,
            size: symbol.size,
            kind: symbol.kind.clone(),
            source: source.to_string(),
            confidence: MetadataConfidence::Exact,
        })
        .collect()
}

pub fn normalize_imports(format: ImageFormat, imports: &[Import]) -> Vec<NormalizedImport> {
    let source = match format {
        ImageFormat::Elf => "elf:import",
        ImageFormat::Pe => "pe:import",
    };
    imports
        .iter()
        .map(|import| NormalizedImport {
            library: import.library.clone(),
            name: Some(import.name.clone()),
            slot_addr: None,
            source: source.to_string(),
            confidence: MetadataConfidence::Exact,
        })
        .collect()
}

pub fn normalize_exports(format: ImageFormat, exports: &[Export]) -> Vec<NormalizedExport> {
    let source = match format {
        ImageFormat::Elf => "elf:export",
        ImageFormat::Pe => "pe:export",
    };
    exports
        .iter()
        .map(|export| NormalizedExport {
            name: Some(export.name.clone()),
            addr: export.addr,
            source: source.to_string(),
            confidence: MetadataConfidence::Exact,
        })
        .collect()
}

pub fn normalize_relocation(
    addr: u64,
    kind: impl Into<String>,
    target: Option<u64>,
    source: &'static str,
) -> NormalizedRelocation {
    NormalizedRelocation {
        addr,
        kind: kind.into(),
        target,
        source: source.to_string(),
        confidence: MetadataConfidence::Exact,
    }
}
