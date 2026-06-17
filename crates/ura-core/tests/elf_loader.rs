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
