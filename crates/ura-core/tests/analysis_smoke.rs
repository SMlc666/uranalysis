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
fn new_project_records_basic_blocks_and_cfg_edges() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    let blocks = commands::basic_blocks(&project)?;
    let edges = commands::cfg_edges(&project)?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].start, 0x400080);
    assert_eq!(blocks[0].end, 0x400084);
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, ura_core::model::CfgEdgeKind::Return);
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
fn set_function_range_refreshes_only_the_graph_window() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    commands::set_function_range(&project, 0x400080, 0x400080, 0x400084)?;

    let funcs = commands::functions(&project)?;
    assert!(funcs.iter().any(|func| {
        func.addr == 0x400080
            && func.start == 0x400080
            && func.end == 0x400084
            && func.source == ura_core::model::FunctionSource::User
    }));
    Ok(())
}

#[test]
fn invalid_user_function_root_is_retained_and_diagnosed() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_elf64_aarch64_executable())?;

    commands::new_project(&input, &project)?;
    commands::make_function(&project, 0x500000)?;

    let funcs = commands::functions(&project)?;
    let diagnostics = commands::diagnostics(&project)?;

    assert!(funcs.iter().any(|func| {
        func.addr == 0x500000 && func.source == ura_core::model::FunctionSource::User
    }));
    assert!(diagnostics.iter().any(|diag| {
        diag.addr == Some(0x500000)
            && diag
                .message
                .contains("manual function root is not in disassembly")
    }));
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
fn call_xrefs_are_derived_from_cfg_edges() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x94000002u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let xrefs = commands::xrefs(&project, 0x400088)?;

    assert!(xrefs.iter().any(|xref| {
        xref.from_addr == 0x400080
            && xref.to_addr == 0x400088
            && xref.kind == ura_core::model::XrefKind::Call
    }));
    Ok(())
}

#[test]
fn function_discovery_uses_call_targets_without_merging_callee_body() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x94000002u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let funcs = commands::functions(&project)?;

    let entry = funcs
        .iter()
        .find(|func| func.addr == 0x400080)
        .expect("entry function should exist");
    let callee = funcs
        .iter()
        .find(|func| func.addr == 0x400088)
        .expect("call target function should exist");

    assert_eq!(entry.start, 0x400080);
    assert_eq!(entry.end, 0x400088);
    assert_eq!(callee.start, 0x400088);
    assert_eq!(callee.end, 0x40008c);
    Ok(())
}

#[test]
fn conditional_branch_target_stays_in_entry_function() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x54000040u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project)?;
    let funcs = commands::functions(&project)?;

    assert!(funcs.iter().any(|func| {
        func.addr == 0x400080 && func.start == 0x400080 && func.end == 0x40008c
    }));
    assert!(!funcs.iter().any(|func| func.addr == 0x400088));
    Ok(())
}

#[test]
fn unknown_entry_instruction_fails_cfg_import() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0xffffffffu32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    let err = commands::new_project(&input, &project)
        .unwrap_err()
        .to_string();

    assert!(err.contains("CFG decode gap"), "{err}");
    assert!(err.contains("0x400080"), "{err}");
    Ok(())
}

#[test]
fn pe_x86_64_input_creates_project_and_records_target() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.exe");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, fixtures::minimal_pe32_plus_x86_64())?;

    commands::new_project(&input, &project)?;
    let info = commands::info(&project)?;

    assert_eq!(info.format, ura_core::model::BinaryFormat::Pe);
    assert_eq!(info.architecture, ura_core::model::Architecture::X86_64);
    assert_eq!(info.class, ura_core::model::ImageClass::Bits64);
    assert_eq!(info.endian, ura_core::model::Endian::Little);
    Ok(())
}
