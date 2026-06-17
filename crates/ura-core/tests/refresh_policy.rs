mod fixtures;

use tempfile::tempdir;
use ura_core::{
    analysis::refresh::{refresh_policy, AnalysisWindow, ProjectEvent, RefreshPlan, RefreshReason},
    commands,
    project::Project,
    Result,
};

#[test]
fn new_project_uses_full_import() {
    assert_eq!(
        refresh_policy(ProjectEvent::SourceCreated),
        RefreshPlan::FullImport
    );
}

#[test]
fn source_replacement_uses_full_import() {
    assert_eq!(
        refresh_policy(ProjectEvent::SourceReplaced),
        RefreshPlan::FullImport
    );
}

#[test]
fn manual_function_added_uses_graph_window() {
    assert_eq!(
        refresh_policy(ProjectEvent::ManualFunctionAdded { addr: 0x400080 }),
        RefreshPlan::GraphWindow(AnalysisWindow {
            start: 0x400080,
            end: 0x400084,
            reason: RefreshReason::ManualFunctionAdded { addr: 0x400080 },
        })
    );
}

#[test]
fn manual_range_change_uses_exact_graph_window() {
    assert_eq!(
        refresh_policy(ProjectEvent::ManualFunctionRangeChanged {
            addr: 0x400080,
            start: 0x400080,
            end: 0x400090,
        }),
        RefreshPlan::GraphWindow(AnalysisWindow {
            start: 0x400080,
            end: 0x400090,
            reason: RefreshReason::ManualFunctionRangeChanged {
                addr: 0x400080,
                start: 0x400080,
                end: 0x400090,
            },
        })
    );
}

#[test]
fn rename_comment_and_queries_do_not_refresh() {
    assert_eq!(
        refresh_policy(ProjectEvent::RenameChanged { addr: 0x400080 }),
        RefreshPlan::None
    );
    assert_eq!(
        refresh_policy(ProjectEvent::CommentChanged { addr: 0x400080 }),
        RefreshPlan::None
    );
    assert_eq!(refresh_policy(ProjectEvent::Query), RefreshPlan::None);
}

#[test]
fn make_function_refreshes_graph_without_rebuilding_disassembly() -> Result<()> {
    let dir = tempdir()?;
    let input = dir.path().join("sample.elf");
    let project_path = dir.path().join("sample.ura");
    let mut bytes = fixtures::minimal_elf64_aarch64_executable();
    bytes[0x84..0x88].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    std::fs::write(&input, bytes)?;

    commands::new_project(&input, &project_path)?;
    {
        let mut project = Project::open(&project_path)?;
        let second = project
            .file_mut()
            .instructions
            .iter_mut()
            .find(|insn| insn.addr == 0x400084)
            .expect("second decoded instruction should exist");
        second.text = "ret /* preserved */".to_string();
        project.save()?;
    }

    commands::make_function(&project_path, 0x400084)?;
    let disasm = commands::disasm(&project_path, 0x400084, 1)?;
    let funcs = commands::functions(&project_path)?;
    let blocks = commands::basic_blocks(&project_path)?;

    assert_eq!(disasm[0].text, "ret /* preserved */");
    assert!(funcs.iter().any(|func| {
        func.addr == 0x400084 && func.source == ura_core::model::FunctionSource::User
    }));
    assert!(blocks.iter().any(|block| block.start == 0x400084));
    Ok(())
}
