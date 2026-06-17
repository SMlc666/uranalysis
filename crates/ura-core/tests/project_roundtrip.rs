mod fixtures;

use tempfile::tempdir;
use ura_core::{commands, model::LoadProfile, project::Project, Result};

#[test]
fn creates_and_reopens_empty_project() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("sample.ura");

    let project = Project::create_empty(&path, "hash-for-test")?;
    assert_eq!(project.source_hash()?, "hash-for-test");
    drop(project);

    let reopened = Project::open(&path)?;
    assert_eq!(reopened.source_hash()?, "hash-for-test");
    assert_eq!(reopened.schema_version()?, 1);
    Ok(())
}

#[test]
fn creates_project_from_elf_and_persists_metadata() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project_path = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project_path)?;
    let info = commands::info(&project_path)?;

    assert_eq!(info.profile, LoadProfile::Executable);
    assert_eq!(info.architecture, ura_core::model::Architecture::Aarch64);
    Ok(())
}
