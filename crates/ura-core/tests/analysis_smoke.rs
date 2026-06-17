mod fixtures;

use tempfile::tempdir;
use ura_core::{commands, Result};

#[test]
fn new_project_records_disassembly_and_strings() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x200..0x20c].copy_from_slice(b"hello-ura\0\0\0");
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;
    let strings = commands::strings(&project, Some("hello"))?;

    assert_eq!(disasm[0].addr, 0x400080);
    assert_eq!(disasm[0].mnemonic, "ret");
    assert_eq!(strings[0].value, "hello-ura");
    Ok(())
}

#[test]
fn user_edits_persist_across_reanalysis() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    commands::make_function(&project, 0x400080)?;
    commands::rename(&project, 0x400080, "manual_ret")?;
    commands::comment(&project, 0x400080, "manual function")?;
    commands::set_function_range(&project, 0x400080, 0x400080, 0x400084)?;
    commands::reanalyze(&project)?;

    let funcs = commands::functions(&project)?;
    let comments = commands::comments(&project, 0x400080)?;

    assert!(funcs
        .iter()
        .any(|func| func.addr == 0x400080 && func.name == "manual_ret"));
    assert_eq!(comments, vec!["manual function".to_string()]);
    Ok(())
}
