#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirtyInputs {
    pub source_bytes: bool,
    pub target_metadata: bool,
    pub renames: bool,
    pub comments: bool,
    pub manual_function_roots: bool,
    pub manual_function_ranges: bool,
}

impl DirtyInputs {
    pub fn manual_function_ranges() -> Self {
        Self {
            manual_function_ranges: true,
            ..Self::default()
        }
    }
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
