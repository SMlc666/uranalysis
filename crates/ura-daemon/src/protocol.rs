use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    OpenProject {
        id: u64,
        path: String,
    },
    CloseProject {
        id: u64,
        session_id: u64,
    },
    GetInfo {
        id: u64,
        session_id: u64,
    },
    ListFunctions {
        id: u64,
        session_id: u64,
    },
    GetDisassembly {
        id: u64,
        session_id: u64,
        addr: u64,
        count: usize,
    },
    ListXrefs {
        id: u64,
        session_id: u64,
        addr: u64,
    },
    RenameSymbol {
        id: u64,
        session_id: u64,
        addr: u64,
        name: String,
    },
    SetComment {
        id: u64,
        session_id: u64,
        addr: u64,
        text: String,
    },
    MakeFunction {
        id: u64,
        session_id: u64,
        addr: u64,
    },
    SetFunctionRange {
        id: u64,
        session_id: u64,
        function_addr: u64,
        start: u64,
        end: u64,
    },
    Reanalyze {
        id: u64,
        session_id: u64,
    },
}

#[derive(Debug, Serialize)]
pub struct Response<T: Serialize> {
    pub id: u64,
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<String>,
}

impl<T: Serialize> Response<T> {
    pub fn ok(id: u64, result: T) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, error: impl ToString) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(error.to_string()),
        }
    }
}
