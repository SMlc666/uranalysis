#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectEvent {
    SourceCreated,
    SourceReplaced,
    ManualFunctionAdded { addr: u64 },
    ManualFunctionRangeChanged { addr: u64, start: u64, end: u64 },
    RenameChanged { addr: u64 },
    CommentChanged { addr: u64 },
    Query,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshReason {
    ManualFunctionAdded { addr: u64 },
    ManualFunctionRangeChanged { addr: u64, start: u64, end: u64 },
    SourceBytesChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisWindow {
    pub start: u64,
    pub end: u64,
    pub reason: RefreshReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshPlan {
    None,
    GraphWindow(AnalysisWindow),
    DecodeWindow(AnalysisWindow),
    FullImport,
}

pub fn refresh_policy(event: ProjectEvent) -> RefreshPlan {
    match event {
        ProjectEvent::SourceCreated | ProjectEvent::SourceReplaced => RefreshPlan::FullImport,
        ProjectEvent::ManualFunctionAdded { addr } => RefreshPlan::GraphWindow(AnalysisWindow {
            start: addr,
            end: addr.saturating_add(4),
            reason: RefreshReason::ManualFunctionAdded { addr },
        }),
        ProjectEvent::ManualFunctionRangeChanged { addr, start, end } => {
            RefreshPlan::GraphWindow(AnalysisWindow {
                start,
                end,
                reason: RefreshReason::ManualFunctionRangeChanged { addr, start, end },
            })
        }
        ProjectEvent::RenameChanged { .. }
        | ProjectEvent::CommentChanged { .. }
        | ProjectEvent::Query => RefreshPlan::None,
    }
}
