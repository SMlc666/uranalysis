use crate::{
    analysis::{invalidation::DirtyInputs, pass::PASS_SPECS},
    model::PassId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshPlan {
    pass_ids: Vec<PassId>,
}

impl RefreshPlan {
    pub fn pass_ids(&self) -> Vec<&'static str> {
        self.pass_ids.iter().map(|id| id.as_str()).collect()
    }
}

pub fn build_refresh_plan(dirty: DirtyInputs) -> RefreshPlan {
    let mut pass_ids = Vec::new();
    for spec in PASS_SPECS {
        let include = dirty.source_bytes
            || dirty.target_metadata
            || matches!(
                spec.id,
                PassId::Cfg | PassId::Functions | PassId::Xrefs | PassId::Diagnostics
            ) && (dirty.manual_function_roots || dirty.manual_function_ranges)
            || matches!(spec.id, PassId::Functions | PassId::Diagnostics) && dirty.renames
            || matches!(spec.id, PassId::Diagnostics) && dirty.comments;
        if include {
            pass_ids.push(spec.id);
        }
    }
    RefreshPlan { pass_ids }
}
