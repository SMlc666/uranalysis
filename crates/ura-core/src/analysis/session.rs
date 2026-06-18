use urloader::LoadedImage;

use crate::{
    analysis::{
        invalidation::DirtyInputs,
        scheduler::{build_refresh_plan, RefreshPlan},
    },
    model::{AnalysisState, UserFacts},
    Result,
};

#[derive(Debug, Clone)]
pub struct AnalysisInputs {
    pub loaded: LoadedImage,
    pub user_facts: UserFacts,
}

impl AnalysisInputs {
    pub fn from_loaded(loaded: &LoadedImage) -> Self {
        Self {
            loaded: loaded.clone(),
            user_facts: UserFacts::default(),
        }
    }
}

pub struct AnalysisSession {
    pub inputs: AnalysisInputs,
    pub state: AnalysisState,
    dirty: DirtyInputs,
}

impl AnalysisSession {
    pub fn new(inputs: AnalysisInputs) -> Self {
        Self {
            inputs,
            state: AnalysisState::default(),
            dirty: DirtyInputs::default(),
        }
    }

    pub fn mark_dirty(&mut self, dirty: DirtyInputs) {
        self.dirty = dirty;
    }

    pub fn refresh_plan(&self) -> Result<RefreshPlan> {
        Ok(build_refresh_plan(self.dirty))
    }
}
