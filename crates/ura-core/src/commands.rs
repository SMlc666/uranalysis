use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::Path,
};

use crate::{
    analysis::{self, target::AnalysisTarget, AnalysisImage},
    model::{
        Diagnostic, Function, FunctionSource, Instruction, LoadProfile, ProjectInfo, Section,
        Segment, StringRef, Symbol, Xref,
    },
    project::Project,
    store::{ProjectFile, PROJECT_SCHEMA_VERSION},
    Result, UraError,
};

pub fn new_project(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
    new_project_with_options(input, output, None)
}

pub fn new_project_with_instruction_limit(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    max_instructions: usize,
) -> Result<()> {
    new_project_with_options(input, output, Some(max_instructions))
}

fn new_project_with_options(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    max_instructions: Option<usize>,
) -> Result<()> {
    let bytes = fs::read(input)?;
    let hash = stable_hash(&bytes);
    let loaded = urloader::load(&bytes).map_err(|err| UraError::Elf(err.to_string()))?;
    let project_file = build_project_file(&hash, &loaded, &[], max_instructions)?;
    Project::create(output, project_file)?;
    Ok(())
}

pub fn info(project_path: impl AsRef<Path>) -> Result<ProjectInfo> {
    Ok(Project::open(project_path)?.file().info.clone())
}

pub fn disasm(project_path: impl AsRef<Path>, addr: u64, count: usize) -> Result<Vec<Instruction>> {
    let project = Project::open(project_path)?;
    Ok(project
        .file()
        .instructions
        .iter()
        .filter(|insn| insn.addr >= addr)
        .take(count)
        .cloned()
        .collect())
}

pub fn strings(project_path: impl AsRef<Path>, filter: Option<&str>) -> Result<Vec<StringRef>> {
    let project = Project::open(project_path)?;
    let filter = filter.unwrap_or("");
    Ok(project
        .file()
        .strings
        .iter()
        .filter(|s| s.value.contains(filter))
        .cloned()
        .collect())
}

pub fn functions(project_path: impl AsRef<Path>) -> Result<Vec<Function>> {
    Ok(Project::open(project_path)?.file().functions.clone())
}

pub fn xrefs(project_path: impl AsRef<Path>, addr: u64) -> Result<Vec<Xref>> {
    let project = Project::open(project_path)?;
    Ok(project
        .file()
        .xrefs
        .iter()
        .filter(|xref| xref.to_addr == addr || xref.from_addr == addr)
        .cloned()
        .collect())
}

pub fn all_xrefs(project_path: impl AsRef<Path>) -> Result<Vec<Xref>> {
    Ok(Project::open(project_path)?.file().xrefs.clone())
}

pub fn rename(project_path: impl AsRef<Path>, addr: u64, name: &str) -> Result<()> {
    let mut project = Project::open(project_path)?;
    project.file_mut().renames.insert(addr, name.to_string());
    for function in &mut project.file_mut().functions {
        if function.addr == addr {
            function.name = name.to_string();
        }
    }
    project.save()
}

pub fn comment(project_path: impl AsRef<Path>, addr: u64, text: &str) -> Result<()> {
    let mut project = Project::open(project_path)?;
    project.file_mut().comments.insert(addr, text.to_string());
    project.save()
}

pub fn comments(project_path: impl AsRef<Path>, addr: u64) -> Result<Vec<String>> {
    let project = Project::open(project_path)?;
    Ok(project
        .file()
        .comments
        .get(&addr)
        .cloned()
        .into_iter()
        .collect())
}

pub fn diagnostics(project_path: impl AsRef<Path>) -> Result<Vec<Diagnostic>> {
    Ok(Project::open(project_path)?.file().diagnostics.clone())
}

pub fn make_function(project_path: impl AsRef<Path>, addr: u64) -> Result<()> {
    let mut project = Project::open(project_path)?;
    let existing_name = project
        .file()
        .functions
        .iter()
        .find(|func| func.addr == addr)
        .map(|func| func.name.clone())
        .unwrap_or_else(|| format!("sub_{addr:x}"));
    upsert_user_function(
        project.file_mut(),
        Function {
            addr,
            name: existing_name,
            start: addr,
            end: addr + 4,
            source: FunctionSource::User,
        },
    );
    project.save()
}

pub fn set_function_range(
    project_path: impl AsRef<Path>,
    function_addr: u64,
    start: u64,
    end: u64,
) -> Result<()> {
    let mut project = Project::open(project_path)?;
    let name = project
        .file()
        .functions
        .iter()
        .find(|func| func.addr == function_addr)
        .map(|func| func.name.clone())
        .unwrap_or_else(|| format!("sub_{function_addr:x}"));
    upsert_user_function(
        project.file_mut(),
        Function {
            addr: function_addr,
            name,
            start,
            end,
            source: FunctionSource::User,
        },
    );
    project.save()
}

pub fn reanalyze(project_path: impl AsRef<Path>) -> Result<()> {
    let project = Project::open(project_path)?;
    project.save()
}

fn build_project_file(
    source_hash: &str,
    loaded: &urloader::LoadedImage,
    user_functions: &[Function],
    max_instructions: Option<usize>,
) -> Result<ProjectFile> {
    let segments = convert_segments(&loaded.segments);
    let sections = convert_sections(&loaded.sections);
    let symbols = convert_symbols(&loaded.symbols);
    let target = AnalysisTarget::from_loaded(loaded)?;
    let analysis_image = AnalysisImage {
        target,
        entry: loaded.entry,
        bytes: &loaded.bytes,
        segments: &segments,
    };
    let analysis = analysis::run_initial_analysis_with_instruction_limit(
        &analysis_image,
        user_functions,
        max_instructions,
    )?;
    Ok(ProjectFile {
        info: ProjectInfo {
            schema_version: PROJECT_SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            source_hash: source_hash.to_string(),
            format: target.format,
            architecture: target.architecture,
            class: target.class,
            endian: target.endian,
            profile: convert_profile(loaded.profile),
        },
        segments,
        sections,
        symbols,
        instructions: analysis.instructions,
        functions: analysis.functions,
        xrefs: analysis.xrefs,
        strings: analysis.strings,
        comments: Default::default(),
        renames: Default::default(),
        diagnostics: analysis.diagnostics,
    })
}

fn convert_profile(profile: urloader::LoadProfile) -> LoadProfile {
    match profile {
        urloader::LoadProfile::SharedObject => LoadProfile::SharedObject,
        urloader::LoadProfile::Executable => LoadProfile::Executable,
        urloader::LoadProfile::Relocatable => LoadProfile::Relocatable,
        urloader::LoadProfile::KernelStyle => LoadProfile::KernelStyle,
        urloader::LoadProfile::StrippedLike | urloader::LoadProfile::Unknown => {
            LoadProfile::StrippedLike
        }
    }
}

fn convert_segments(segments: &[urloader::Segment]) -> Vec<Segment> {
    segments
        .iter()
        .map(|segment| Segment {
            id: segment.id,
            name: segment.name.clone(),
            vaddr: segment.vaddr,
            file_offset: segment.file_offset,
            file_size: segment.file_size,
            mem_size: segment.mem_size,
            permissions: segment.permissions.clone(),
        })
        .collect()
}

fn convert_sections(sections: &[urloader::Section]) -> Vec<Section> {
    sections
        .iter()
        .map(|section| Section {
            id: section.id,
            name: section.name.clone(),
            addr: section.addr,
            offset: section.offset,
            size: section.size,
            flags: section.flags,
        })
        .collect()
}

fn convert_symbols(symbols: &[urloader::Symbol]) -> Vec<Symbol> {
    symbols
        .iter()
        .map(|symbol| Symbol {
            id: symbol.id,
            name: symbol.name.clone(),
            addr: symbol.addr,
            size: symbol.size,
            kind: symbol.kind.clone(),
            is_import: symbol.is_import,
            is_export: symbol.is_export,
        })
        .collect()
}

fn upsert_user_function(project: &mut ProjectFile, function: Function) {
    project.functions.retain(|func| func.addr != function.addr);
    project.functions.push(function);
    project.functions.sort_by_key(|func| func.addr);
}

fn stable_hash(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
