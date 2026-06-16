use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::Path,
};

use crate::{
    analysis, db,
    elf_loader::LoadedElf,
    model::{Diagnostic, Function, FunctionSource, Instruction, ProjectInfo, StringRef, Xref},
    project::Project,
    Result,
};

pub fn new_project(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
    let bytes = fs::read(input)?;
    let hash = stable_hash(&bytes);
    let loaded = LoadedElf::parse(&bytes)?;
    let project = Project::create_empty(output, &hash)?;
    persist_loaded(&project, &loaded, &[])?;
    Ok(())
}

pub fn info(project_path: impl AsRef<Path>) -> Result<ProjectInfo> {
    let project = Project::open(project_path)?;
    db::project_info(project.conn())
}

pub fn disasm(project_path: impl AsRef<Path>, addr: u64, count: usize) -> Result<Vec<Instruction>> {
    let project = Project::open(project_path)?;
    db::query_disasm(project.conn(), addr, count)
}

pub fn strings(project_path: impl AsRef<Path>, filter: Option<&str>) -> Result<Vec<StringRef>> {
    let project = Project::open(project_path)?;
    db::query_strings(project.conn(), filter)
}

pub fn functions(project_path: impl AsRef<Path>) -> Result<Vec<Function>> {
    let project = Project::open(project_path)?;
    db::query_functions(project.conn())
}

pub fn xrefs(project_path: impl AsRef<Path>, addr: u64) -> Result<Vec<Xref>> {
    let project = Project::open(project_path)?;
    db::query_xrefs(project.conn(), addr)
}

pub fn rename(project_path: impl AsRef<Path>, addr: u64, name: &str) -> Result<()> {
    let project = Project::open(project_path)?;
    db::rename(project.conn(), addr, name)
}

pub fn comment(project_path: impl AsRef<Path>, addr: u64, text: &str) -> Result<()> {
    let project = Project::open(project_path)?;
    db::set_comment(project.conn(), addr, text)
}

pub fn comments(project_path: impl AsRef<Path>, addr: u64) -> Result<Vec<String>> {
    let project = Project::open(project_path)?;
    db::query_comments(project.conn(), addr)
}

pub fn diagnostics(project_path: impl AsRef<Path>) -> Result<Vec<Diagnostic>> {
    let project = Project::open(project_path)?;
    db::query_diagnostics(project.conn())
}

pub fn make_function(project_path: impl AsRef<Path>, addr: u64) -> Result<()> {
    let project = Project::open(project_path)?;
    let existing_name = db::query_functions(project.conn())?
        .into_iter()
        .find(|func| func.addr == addr)
        .map(|func| func.name)
        .unwrap_or_else(|| format!("sub_{addr:x}"));
    db::upsert_user_function(
        project.conn(),
        &Function {
            addr,
            name: existing_name,
            start: addr,
            end: addr + 4,
            source: FunctionSource::User,
        },
    )
}

pub fn set_function_range(
    project_path: impl AsRef<Path>,
    function_addr: u64,
    start: u64,
    end: u64,
) -> Result<()> {
    let project = Project::open(project_path)?;
    let name = db::query_functions(project.conn())?
        .into_iter()
        .find(|func| func.addr == function_addr)
        .map(|func| func.name)
        .unwrap_or_else(|| format!("sub_{function_addr:x}"));
    db::upsert_user_function(
        project.conn(),
        &Function {
            addr: function_addr,
            name,
            start,
            end,
            source: FunctionSource::User,
        },
    )
}

pub fn reanalyze(project_path: impl AsRef<Path>) -> Result<()> {
    let project_path = project_path.as_ref();
    let project = Project::open(project_path)?;
    let user_functions = db::query_functions(project.conn())?
        .into_iter()
        .filter(|func| func.source == FunctionSource::User)
        .collect::<Vec<_>>();
    db::insert_functions(project.conn(), &user_functions)?;
    Ok(())
}

fn persist_loaded(
    project: &Project,
    loaded: &LoadedElf,
    user_functions: &[Function],
) -> Result<()> {
    db::set_metadata(project.conn(), "profile", &format!("{:?}", loaded.profile))?;
    db::insert_segments(project.conn(), &loaded.segments)?;
    db::insert_sections(project.conn(), &loaded.sections)?;
    db::insert_symbols(project.conn(), &loaded.symbols)?;
    let analysis = analysis::run_initial_analysis(loaded, user_functions)?;
    db::insert_instructions(project.conn(), &analysis.instructions)?;
    db::insert_strings(project.conn(), &analysis.strings)?;
    db::insert_functions(project.conn(), &analysis.functions)?;
    db::insert_xrefs(project.conn(), &analysis.xrefs)?;
    db::insert_diagnostics(project.conn(), &analysis.diagnostics)?;
    Ok(())
}

fn stable_hash(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
