mod fixtures;

use ura_core::analysis::{
    invalidation::DirtyInputs,
    session::{AnalysisInputs, AnalysisSession},
};

#[test]
fn refresh_plan_marks_cfg_and_downstream_passes_dirty_for_manual_function_range() {
    let loaded = fixtures::load_minimal_aarch64_image();
    let mut session = AnalysisSession::new(AnalysisInputs::from_loaded(&loaded));

    session.mark_dirty(DirtyInputs::manual_function_ranges());
    let plan = session.refresh_plan().expect("plan should build");

    assert_eq!(
        plan.pass_ids(),
        vec!["cfg", "functions", "xrefs", "diagnostics"]
    );
}

#[test]
fn refresh_rebuilds_functions_after_manual_range_change() {
    let loaded = fixtures::load_minimal_aarch64_image();
    let mut session = AnalysisSession::new(AnalysisInputs::from_loaded(&loaded));

    session.refresh().expect("initial refresh");
    session
        .update_manual_function_range(0x400080, 0x400080, 0x400084)
        .expect("manual range update");
    let summary = session.refresh().expect("second refresh");

    assert!(summary.ran("cfg"));
    assert!(summary.ran("functions"));
    assert!(session
        .state
        .functions
        .iter()
        .any(|func| func.addr == 0x400080 && func.start == 0x400080 && func.end == 0x400084));
}
