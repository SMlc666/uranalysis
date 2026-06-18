mod fixtures;

use ura_core::{commands, model::LoadProfile, Result};

#[test]
fn commands_load_minimal_aarch64_executable_through_urloader() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    let info = commands::info(&project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;

    assert_eq!(info.profile, LoadProfile::Executable);
    assert_eq!(disasm[0].text, "ret");
    Ok(())
}

#[test]
fn commands_load_minimal_x86_64_executable_through_urloader() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("sample-x86_64.elf");
    let project = dir.path().join("sample-x86_64.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
    bytes[0x80] = 0xc3;
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let info = commands::info(&project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;

    assert_eq!(info.format, ura_core::model::BinaryFormat::Elf);
    assert_eq!(info.architecture, ura_core::model::Architecture::X86_64);
    assert_eq!(disasm[0].mnemonic, "ret");
    Ok(())
}

#[test]
fn new_project_with_instruction_limit_bounds_initial_analysis() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project_with_instruction_limit(&input, &project, 3)?;
    let disasm = commands::disasm(&project, 0, usize::MAX)?;

    assert_eq!(disasm.len(), 3);
    Ok(())
}

#[test]
fn new_project_with_instruction_limit_still_analyzes_entry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project_with_instruction_limit(&input, &project, 3)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;
    let blocks = commands::basic_blocks(&project)?;

    assert_eq!(disasm[0].addr, 0x400080);
    assert_eq!(disasm[0].mnemonic, "ret");
    assert!(blocks.iter().any(|block| block.start == 0x400080));
    Ok(())
}

#[test]
fn new_project_with_instruction_limit_keeps_report_when_cfg_has_decode_gap() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0xffffffffu32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project_with_instruction_limit(&input, &project, 3)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;
    let diagnostics = commands::diagnostics(&project)?;

    assert_eq!(disasm[0].addr, 0x400080);
    assert_eq!(
        disasm[0].decode_status,
        ura_core::model::DecodeStatus::Unknown
    );
    assert!(diagnostics.iter().any(|diag| {
        diag.severity == "error" && diag.message.contains("CFG decode gap at 0x400080")
    }));
    Ok(())
}
