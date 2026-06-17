mod fixtures;

use tempfile::tempdir;
use ura_core::{commands, Result};

#[test]
fn project_file_uses_ura_binary_magic_not_sqlite_header() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    let bytes = std::fs::read(&project)?;

    assert!(bytes.starts_with(b"URA0"));
    assert!(!bytes.starts_with(b"SQLite format 3\0"));
    Ok(())
}

#[test]
fn project_file_persists_user_truth_after_reopen() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    commands::make_function(&project, 0x400080)?;
    commands::rename(&project, 0x400080, "manual_ret")?;
    commands::comment(&project, 0x400080, "manual function")?;
    commands::set_function_range(&project, 0x400080, 0x400080, 0x400084)?;

    let funcs = commands::functions(&project)?;
    let comments = commands::comments(&project, 0x400080)?;

    assert!(funcs.iter().any(|func| {
        func.addr == 0x400080
            && func.name == "manual_ret"
            && func.start == 0x400080
            && func.end == 0x400084
    }));
    assert_eq!(comments, vec!["manual function".to_string()]);
    Ok(())
}

#[test]
fn project_file_rejects_malformed_binary_headers() -> Result<()> {
    let dir = tempdir()?;
    let project = dir.path().join("bad.ura");

    std::fs::write(&project, b"SQLite format 3\0")?;
    let err = commands::info(&project).unwrap_err().to_string();
    assert!(err.contains("invalid project magic"), "{err}");

    std::fs::write(&project, b"URA")?;
    let err = commands::info(&project).unwrap_err().to_string();
    assert!(err.contains("truncated project header"), "{err}");

    let mut unsupported_version = Vec::new();
    unsupported_version.extend_from_slice(b"URA0");
    unsupported_version.extend_from_slice(&2u32.to_le_bytes());
    unsupported_version.extend_from_slice(&0u64.to_le_bytes());
    std::fs::write(&project, unsupported_version)?;
    let err = commands::info(&project).unwrap_err().to_string();
    assert!(
        err.contains("unsupported project container version"),
        "{err}"
    );

    let mut mismatched_length = Vec::new();
    mismatched_length.extend_from_slice(b"URA0");
    mismatched_length.extend_from_slice(&1u32.to_le_bytes());
    mismatched_length.extend_from_slice(&4u64.to_le_bytes());
    std::fs::write(&project, mismatched_length)?;
    let err = commands::info(&project).unwrap_err().to_string();
    assert!(err.contains("project payload length mismatch"), "{err}");

    Ok(())
}
