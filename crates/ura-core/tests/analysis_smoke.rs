mod fixtures;

use ura_core::{
    analysis::{
        self,
        session::{AnalysisInputs, AnalysisSession},
    },
    model::{
        Architecture, BinaryFormat, Endian, FunctionSource, ImageClass, UserFacts, XrefKind,
    },
    Result, UraError,
};

fn load_image(bytes: &[u8]) -> Result<urloader::LoadedImage> {
    urloader::load(bytes).map_err(|err| UraError::Analysis(err.to_string()))
}

fn build_session(bytes: &[u8]) -> Result<AnalysisSession> {
    let loaded = load_image(bytes)?;
    let mut session = AnalysisSession::new(AnalysisInputs::from_loaded(&loaded));
    session.refresh()?;
    Ok(session)
}

#[test]
fn new_project_records_disassembly_and_strings() -> Result<()> {
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x200..0x20c].copy_from_slice(b"hello-ura\0\0\0");

    let session = build_session(&bytes)?;
    let entry = session
        .state
        .instructions
        .iter()
        .find(|insn| insn.addr == 0x400080)
        .expect("entry instruction should exist");

    assert_eq!(entry.mnemonic, "ret");
    assert_eq!(session.state.strings[0].value, "hello-ura");
    Ok(())
}

#[test]
fn new_project_records_basic_blocks_and_cfg_edges() -> Result<()> {
    let session = build_session(&fixtures::minimal_elf64_aarch64_executable())?;

    assert_eq!(session.state.basic_blocks.len(), 1);
    assert_eq!(session.state.basic_blocks[0].start, 0x400080);
    assert_eq!(session.state.basic_blocks[0].end, 0x400084);
    assert_eq!(session.state.cfg_edges.len(), 1);
    assert_eq!(session.state.cfg_edges[0].kind, ura_core::model::CfgEdgeKind::Return);
    Ok(())
}

#[test]
fn session_reanalysis_preserves_user_truth() -> Result<()> {
    let loaded = load_image(&fixtures::minimal_elf64_aarch64_executable())?;
    let mut session = AnalysisSession::new(AnalysisInputs::from_loaded(&loaded));

    session.refresh()?;
    session.rename(0x400080, "manual_ret")?;
    session.comment(0x400080, "manual function")?;
    session.update_manual_function_range(0x400080, 0x400080, 0x400084)?;
    session.refresh()?;

    assert!(session
        .state
        .functions
        .iter()
        .any(|func| func.addr == 0x400080 && func.name == "manual_ret"));
    assert_eq!(
        session.inputs.user_facts.comments.get(&0x400080),
        Some(&"manual function".to_string())
    );
    Ok(())
}

#[test]
fn set_function_range_refreshes_only_the_graph_window() -> Result<()> {
    let loaded = load_image(&fixtures::minimal_elf64_aarch64_executable())?;
    let mut session = AnalysisSession::new(AnalysisInputs::from_loaded(&loaded));

    session.refresh()?;
    session.update_manual_function_range(0x400080, 0x400080, 0x400084)?;
    session.refresh()?;

    assert!(session.state.functions.iter().any(|func| {
        func.addr == 0x400080
            && func.start == 0x400080
            && func.end == 0x400084
            && func.source == FunctionSource::User
    }));
    Ok(())
}

#[test]
fn invalid_user_function_root_is_retained_and_diagnosed() -> Result<()> {
    let loaded = load_image(&fixtures::minimal_elf64_aarch64_executable())?;
    let mut session = AnalysisSession::new(AnalysisInputs::from_loaded(&loaded));

    session.refresh()?;
    session.update_manual_function_range(0x500000, 0x500000, 0x500004)?;
    session.refresh()?;

    assert!(session.state.functions.iter().any(|func| {
        func.addr == 0x500000 && func.source == FunctionSource::User
    }));
    assert!(session.state.diagnostics.iter().any(|diag| {
        diag.addr == Some(0x500000)
            && diag
                .message
                .contains("manual function root is not in disassembly")
    }));
    Ok(())
}

#[test]
fn branch_and_call_xrefs_use_decoder_flow() -> Result<()> {
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x94000002u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0x14000003u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x90..0x94].copy_from_slice(&0xd65f03c0u32.to_le_bytes());

    let session = build_session(&bytes)?;
    assert!(session.state.xrefs.iter().any(|xref| xref.from_addr == 0x400080 && xref.to_addr == 0x400088));
    assert!(session.state.xrefs.iter().any(|xref| xref.from_addr == 0x400084 && xref.to_addr == 0x400090));
    Ok(())
}

#[test]
fn call_xrefs_are_derived_from_cfg_edges() -> Result<()> {
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x94000002u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());

    let session = build_session(&bytes)?;

    assert!(session.state.xrefs.iter().any(|xref| {
        xref.from_addr == 0x400080 && xref.to_addr == 0x400088 && xref.kind == XrefKind::Call
    }));
    Ok(())
}

#[test]
fn function_discovery_uses_call_targets_without_merging_callee_body() -> Result<()> {
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x94000002u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());

    let session = build_session(&bytes)?;

    let entry = session
        .state
        .functions
        .iter()
        .find(|func| func.addr == 0x400080)
        .expect("entry function should exist");
    let callee = session
        .state
        .functions
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
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0x54000040u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes[0x88..0x8c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());

    let session = build_session(&bytes)?;

    assert!(session
        .state
        .functions
        .iter()
        .any(|func| { func.addr == 0x400080 && func.start == 0x400080 && func.end == 0x40008c }));
    assert!(!session.state.functions.iter().any(|func| func.addr == 0x400088));
    Ok(())
}

#[test]
fn unknown_entry_instruction_fails_cfg_import() {
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x80..0x84].copy_from_slice(&0xffffffffu32.to_le_bytes());

    let loaded = load_image(&bytes).expect("fixture should load");
    let mut session = AnalysisSession::new(AnalysisInputs::from_loaded(&loaded));
    let err = match session.refresh() {
        Ok(summary) => panic!("expected refresh failure, got {:?}", summary.ran("cfg")),
        Err(err) => err.to_string(),
    };

    assert!(err.contains("CFG decode gap"), "{err}");
    assert!(err.contains("0x400080"), "{err}");
}

#[test]
fn pe_x86_64_input_creates_project_and_records_target() -> Result<()> {
    let loaded = load_image(&fixtures::minimal_pe32_plus_x86_64())?;
    let target = ura_core::analysis::target::AnalysisTarget::from_loaded(&loaded)?;
    let state = analysis::build_state_from_loaded(&loaded, &UserFacts::default())?;

    assert_eq!(target.format, BinaryFormat::Pe);
    assert_eq!(target.architecture, Architecture::X86_64);
    assert_eq!(target.class, ImageClass::Bits64);
    assert_eq!(target.endian, Endian::Little);
    assert!(!state.instructions.is_empty());
    Ok(())
}
