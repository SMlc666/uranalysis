use urloader::LoadedImage;

use crate::{
    analysis::{
        build_state_from_loaded,
        invalidation::DirtyInputs,
        scheduler::{build_refresh_plan, RefreshPlan},
    },
    model::{AnalysisState, PassId, UserFacts},
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

pub struct RefreshSummary {
    ran: Vec<PassId>,
}

impl RefreshSummary {
    pub fn ran(&self, name: &str) -> bool {
        self.ran.iter().any(|id| id.as_str() == name)
    }
}

impl AnalysisSession {
    pub fn new(inputs: AnalysisInputs) -> Self {
        Self {
            inputs,
            state: AnalysisState::default(),
            dirty: DirtyInputs {
                source_bytes: true,
                ..DirtyInputs::default()
            },
        }
    }

    pub fn from_parts(inputs: AnalysisInputs, state: AnalysisState, stale: bool) -> Self {
        let mut session = Self::new(inputs);
        session.state = state;
        if !stale {
            session.dirty = DirtyInputs::default();
        }
        session
    }

    pub fn mark_dirty(&mut self, dirty: DirtyInputs) {
        self.dirty = dirty;
    }

    pub fn refresh_plan(&self) -> Result<RefreshPlan> {
        Ok(build_refresh_plan(self.dirty))
    }

    pub fn refresh(&mut self) -> Result<RefreshSummary> {
        let plan = build_refresh_plan(self.dirty);
        let ran = if plan.pass_ids().is_empty() {
            Vec::new()
        } else {
            self.state = build_state_from_loaded(&self.inputs.loaded, &self.inputs.user_facts)?;
            plan.clone_ids()
        };
        self.dirty = DirtyInputs::default();
        Ok(RefreshSummary { ran })
    }

    pub fn rename(&mut self, addr: u64, name: &str) -> Result<()> {
        self.inputs.user_facts.renames.insert(addr, name.to_string());
        self.dirty.renames = true;
        Ok(())
    }

    pub fn comment(&mut self, addr: u64, text: &str) -> Result<()> {
        self.inputs.user_facts.comments.insert(addr, text.to_string());
        self.dirty.comments = true;
        Ok(())
    }

    pub fn update_manual_function_range(&mut self, addr: u64, start: u64, end: u64) -> Result<()> {
        self.inputs.user_facts.manual_function_roots.insert(addr);
        self.inputs
            .user_facts
            .manual_function_ranges
            .insert(addr, (start, end));
        self.dirty.manual_function_ranges = true;
        Ok(())
    }
}
