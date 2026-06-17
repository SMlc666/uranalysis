use ura_core::analysis::refresh::{
    refresh_policy, AnalysisWindow, ProjectEvent, RefreshPlan, RefreshReason,
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
