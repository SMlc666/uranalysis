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
