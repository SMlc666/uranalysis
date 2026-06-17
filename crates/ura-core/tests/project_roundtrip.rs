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
    assert_eq!(reopened.schema_version()?, 2);
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

#[test]
fn project_schema_v2_records_decode_metadata() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    let info = commands::info(&project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;

    assert_eq!(info.schema_version, 2);
    assert_eq!(disasm[0].text, "ret");
    assert_eq!(disasm[0].kind, "Return");
    assert_eq!(disasm[0].flow, "Return");
    assert_eq!(disasm[0].decode_status, "Complete");
    assert_eq!(disasm[0].decoder, "urdisassembly/aarch64");
    assert_eq!(disasm[0].decoder_version, env!("CARGO_PKG_VERSION"));
    Ok(())
}

#[test]
fn binary_project_rejects_old_sqlite_header() -> Result<()> {
    let dir = tempdir()?;
    let project = dir.path().join("old.ura");
    std::fs::write(&project, b"SQLite format 3\0")?;

    let err = commands::info(&project).unwrap_err().to_string();

    assert!(err.contains("invalid project magic"), "{err}");
    Ok(())
}
