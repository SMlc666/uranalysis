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

#[test]
fn branch_and_call_xrefs_use_decoder_flow() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x94000002u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0x14000003u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x90..0x94].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let xrefs_to_88 = commands::xrefs(&project, 0x400088)?;
    let xrefs_to_90 = commands::xrefs(&project, 0x400090)?;

    assert!(xrefs_to_88.iter().any(|xref| xref.from_addr == 0x400080));
    assert!(xrefs_to_90.iter().any(|xref| xref.from_addr == 0x400084));
    Ok(())
}

#[test]
fn unknown_instruction_is_recorded_and_diagnosed() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0xffffffffu32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let disasm = commands::disasm(&project, 0x400080, 1)?;
    let diagnostics = commands::diagnostics(&project)?;

    assert_eq!(disasm[0].text, ".word 0xffffffff");
    assert_eq!(disasm[0].decode_status, "Unknown");
    assert!(diagnostics
        .iter()
        .any(|diag| diag.addr == Some(0x400080) && diag.message.contains("unknown instruction")));
    Ok(())
}

#[test]
fn pe_input_is_rejected_before_analysis() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.exe");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_pe32_plus_x86_64())?;

    let err = commands::new_project(&input, &project)
        .unwrap_err()
        .to_string();

    assert!(err.contains("unsupported analysis target"), "{err}");
    Ok(())
}
