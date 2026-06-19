mod fixtures;

use ura_core::{
    analysis,
    model::{DecodeStatus, UserFacts},
    Result, UraError,
};

fn load_image(bytes: &[u8]) -> Result<urloader::RawImage> {
    urloader::load(bytes).map_err(|err| UraError::Analysis(err.to_string()))
}

#[test]
fn commands_load_minimal_aarch64_executable_through_urloader() -> Result<()> {
    let bytes = fixtures::minimal_elf64_aarch64_executable();
    let raw = load_image(&bytes)?;
    let view = raw
        .analysis_view(&bytes)
        .map_err(|err| UraError::Analysis(err.to_string()))?;
    let target = ura_core::analysis::target::AnalysisTarget::from_view(&view)?;
    let state = analysis::build_state_from_view(&view, &UserFacts::default())?;
    let entry = state
        .instructions
        .iter()
        .find(|insn| insn.addr == raw.entry)
        .expect("entry instruction should exist");

    assert_eq!(target.format, ura_core::model::BinaryFormat::Elf);
    assert_eq!(raw.profile, urloader::LoadProfile::Executable);
    assert_eq!(entry.text, "ret");
    Ok(())
}

#[test]
fn commands_load_minimal_x86_64_executable_through_urloader() -> Result<()> {
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
    bytes[0x80] = 0xc3;

    let raw = load_image(&bytes)?;
    let view = raw
        .analysis_view(&bytes)
        .map_err(|err| UraError::Analysis(err.to_string()))?;
    let target = ura_core::analysis::target::AnalysisTarget::from_view(&view)?;
    let state = analysis::build_state_from_view(&view, &UserFacts::default())?;
    let entry = state
        .instructions
        .iter()
        .find(|insn| insn.addr == raw.entry)
        .expect("entry instruction should exist");

    assert_eq!(target.format, ura_core::model::BinaryFormat::Elf);
    assert_eq!(target.architecture, ura_core::model::Architecture::X86_64);
    assert_eq!(entry.mnemonic, "ret");
    Ok(())
}

#[test]
fn new_project_with_instruction_limit_bounds_initial_analysis() -> Result<()> {
    let bytes = fixtures::minimal_elf64_aarch64_executable();
    let raw = load_image(&bytes)?;
    let view = raw
        .analysis_view(&bytes)
        .map_err(|err| UraError::Analysis(err.to_string()))?;
    let state = analysis::build_state_from_view_with_instruction_limit(
        &view,
        &UserFacts::default(),
        Some(3),
    )?;

    assert_eq!(state.instructions.len(), 3);
    Ok(())
}

#[test]
fn new_project_with_instruction_limit_still_analyzes_entry() -> Result<()> {
    let bytes = fixtures::minimal_elf64_aarch64_executable();
    let raw = load_image(&bytes)?;
    let view = raw
        .analysis_view(&bytes)
        .map_err(|err| UraError::Analysis(err.to_string()))?;
    let state = analysis::build_state_from_view_with_instruction_limit(
        &view,
        &UserFacts::default(),
        Some(3),
    )?;
    let entry = state
        .instructions
        .iter()
        .find(|insn| insn.addr == raw.entry)
        .expect("entry instruction should exist");

    assert_eq!(entry.mnemonic, "ret");
    assert!(state
        .basic_blocks
        .iter()
        .any(|block| block.start == 0x400080));
    Ok(())
}

#[test]
fn new_project_with_instruction_limit_keeps_report_when_cfg_has_decode_gap() -> Result<()> {
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0xffffffffu32.to_le_bytes());

    let raw = load_image(&bytes)?;
    let view = raw
        .analysis_view(&bytes)
        .map_err(|err| UraError::Analysis(err.to_string()))?;
    let state = analysis::build_state_from_view_with_instruction_limit(
        &view,
        &UserFacts::default(),
        Some(3),
    )?;
    let entry = state
        .instructions
        .iter()
        .find(|insn| insn.addr == raw.entry)
        .expect("entry instruction should exist");

    assert_eq!(entry.decode_status, DecodeStatus::Unknown);
    assert!(state.diagnostics.iter().any(|diag| {
        diag.severity == "error" && diag.message.contains("CFG decode gap at 0x400080")
    }));
    Ok(())
}
