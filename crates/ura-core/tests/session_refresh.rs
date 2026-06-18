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
