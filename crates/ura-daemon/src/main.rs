mod protocol;

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use protocol::{Request, Response};

struct SessionProject {
    stored: urastore::StoredProject,
    session: ura_core::analysis::session::AnalysisSession,
}

fn main() -> Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7878".to_string());
    let listener = TcpListener::bind(&addr)?;
    println!("ura-daemon listening on {addr}");
    for stream in listener.incoming() {
        handle_client(stream?)?;
    }
    Ok(())
}

fn handle_client(stream: TcpStream) -> Result<()> {
    let mut writer = stream.try_clone()?;
    let reader = BufReader::new(stream);
    let mut sessions: HashMap<u64, PathBuf> = HashMap::new();
    let mut next_session = 1u64;
    for line in reader.lines() {
        let line = line?;
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle_request(request, &mut sessions, &mut next_session),
            Err(err) => serde_json::to_string(&Response::<serde_json::Value>::err(0, err))?,
        };
        writeln!(writer, "{response}")?;
    }
    Ok(())
}

fn load_session_project(path: &Path) -> Result<SessionProject> {
    let stored = urastore::load_project(path)?;
    let loaded =
        urloader::load(&stored.source.source_bytes).map_err(|err| anyhow!(err.to_string()))?;
    let session = ura_core::analysis::session::AnalysisSession::from_parts(
        ura_core::analysis::session::AnalysisInputs {
            source_bytes: stored.source.source_bytes.clone(),
            raw: loaded,
            user_facts: stored.user_truth.facts.clone(),
        },
        stored.cache.state.clone(),
        stored
            .cache_metadata
            .is_stale_for(&stored.source, &stored.user_truth),
    );
    Ok(SessionProject { stored, session })
}

fn save_session_project(path: &Path, project: &mut SessionProject) -> Result<()> {
    if project.stored.user_truth.facts != project.session.inputs.user_facts {
        project.stored.user_truth.revision += 1;
    }
    project.stored.user_truth.facts = project.session.inputs.user_facts.clone();
    project.stored.cache.state = project.session.state.clone();
    project.stored.cache_metadata = urastore::CacheMetadata::fresh(
        env!("CARGO_PKG_VERSION"),
        "kernel-v1",
        &project.stored.source.source_hash,
        project.stored.user_truth.revision,
    );
    urastore::save_project(path, &project.stored)?;
    Ok(())
}

fn handle_request(
    request: Request,
    sessions: &mut HashMap<u64, PathBuf>,
    next_session: &mut u64,
) -> String {
    match request {
        Request::OpenProject { id, path } => {
            let session_id = *next_session;
            *next_session += 1;
            sessions.insert(session_id, PathBuf::from(path));
            serde_json::to_string(&Response::ok(
                id,
                serde_json::json!({ "session_id": session_id }),
            ))
            .unwrap()
        }
        Request::CloseProject { id, session_id } => {
            sessions.remove(&session_id);
            serde_json::to_string(&Response::ok(id, serde_json::json!({ "closed": true }))).unwrap()
        }
        Request::GetInfo { id, session_id } => with_project(id, session_id, sessions, |path| {
            let project = load_session_project(path)?;
            Ok(serde_json::json!({
                "format": project.stored.source.format,
                "architecture": project.stored.source.architecture,
                "profile": project.stored.source.profile,
                "entry": project.stored.source.entry,
            }))
        }),
        Request::ListFunctions { id, session_id } => {
            with_project(id, session_id, sessions, |path| {
                let project = load_session_project(path)?;
                serde_json::to_value(project.session.state.functions).map_err(anyhow::Error::from)
            })
        }
        Request::GetDisassembly {
            id,
            session_id,
            addr,
            count,
        } => with_project(id, session_id, sessions, |path| {
            let project = load_session_project(path)?;
            let rows = project
                .session
                .state
                .instructions
                .iter()
                .filter(|insn| insn.addr >= addr)
                .take(count)
                .cloned()
                .collect::<Vec<_>>();
            serde_json::to_value(rows).map_err(anyhow::Error::from)
        }),
        Request::ListXrefs {
            id,
            session_id,
            addr,
        } => with_project(id, session_id, sessions, |path| {
            let project = load_session_project(path)?;
            let rows = project
                .session
                .state
                .xrefs
                .iter()
                .filter(|xref| xref.to_addr == addr || xref.from_addr == addr)
                .cloned()
                .collect::<Vec<_>>();
            serde_json::to_value(rows).map_err(anyhow::Error::from)
        }),
        Request::RenameSymbol {
            id,
            session_id,
            addr,
            name,
        } => with_project(id, session_id, sessions, |path| {
            let mut project = load_session_project(path)?;
            project.session.rename(addr, &name)?;
            project.session.refresh()?;
            save_session_project(path, &mut project)?;
            Ok(serde_json::json!({ "renamed": true }))
        }),
        Request::SetComment {
            id,
            session_id,
            addr,
            text,
        } => with_project(id, session_id, sessions, |path| {
            let mut project = load_session_project(path)?;
            project.session.comment(addr, &text)?;
            project.session.refresh()?;
            save_session_project(path, &mut project)?;
            Ok(serde_json::json!({ "commented": true }))
        }),
        Request::MakeFunction {
            id,
            session_id,
            addr,
        } => with_project(id, session_id, sessions, |path| {
            let mut project = load_session_project(path)?;
            project
                .session
                .update_manual_function_range(addr, addr, addr + 4)?;
            project.session.refresh()?;
            save_session_project(path, &mut project)?;
            Ok(serde_json::json!({ "made_function": true }))
        }),
        Request::SetFunctionRange {
            id,
            session_id,
            function_addr,
            start,
            end,
        } => with_project(id, session_id, sessions, |path| {
            let mut project = load_session_project(path)?;
            project
                .session
                .update_manual_function_range(function_addr, start, end)?;
            project.session.refresh()?;
            save_session_project(path, &mut project)?;
            Ok(serde_json::json!({ "range_set": true }))
        }),
        Request::Reanalyze { id, session_id } => with_project(id, session_id, sessions, |path| {
            let mut project = load_session_project(path)?;
            project
                .session
                .mark_dirty(ura_core::analysis::invalidation::DirtyInputs {
                    source_bytes: true,
                    ..Default::default()
                });
            project.session.refresh()?;
            save_session_project(path, &mut project)?;
            Ok(serde_json::json!({ "reanalyzed": true }))
        }),
    }
}

fn with_project<F>(id: u64, session_id: u64, sessions: &HashMap<u64, PathBuf>, f: F) -> String
where
    F: FnOnce(&Path) -> Result<serde_json::Value>,
{
    let Some(path) = sessions.get(&session_id) else {
        return serde_json::to_string(&Response::<serde_json::Value>::err(id, "unknown session"))
            .unwrap();
    };
    match f(path) {
        Ok(value) => serde_json::to_string(&Response::ok(id, value)).unwrap(),
        Err(err) => serde_json::to_string(&Response::<serde_json::Value>::err(id, err)).unwrap(),
    }
}
