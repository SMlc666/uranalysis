mod protocol;

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
};

use anyhow::Result;
use protocol::{Request, Response};

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
            serde_json::to_value(ura_core::commands::info(path)?).map_err(anyhow::Error::from)
        }),
        Request::ListFunctions { id, session_id } => {
            with_project(id, session_id, sessions, |path| {
                serde_json::to_value(ura_core::commands::functions(path)?)
                    .map_err(anyhow::Error::from)
            })
        }
        Request::GetDisassembly {
            id,
            session_id,
            addr,
            count,
        } => with_project(id, session_id, sessions, |path| {
            serde_json::to_value(ura_core::commands::disasm(path, addr, count)?)
                .map_err(anyhow::Error::from)
        }),
        Request::ListXrefs {
            id,
            session_id,
            addr,
        } => with_project(id, session_id, sessions, |path| {
            serde_json::to_value(ura_core::commands::xrefs(path, addr)?)
                .map_err(anyhow::Error::from)
        }),
        Request::RenameSymbol {
            id,
            session_id,
            addr,
            name,
        } => with_project(id, session_id, sessions, |path| {
            ura_core::commands::rename(path, addr, &name)?;
            Ok(serde_json::json!({ "renamed": true }))
        }),
        Request::SetComment {
            id,
            session_id,
            addr,
            text,
        } => with_project(id, session_id, sessions, |path| {
            ura_core::commands::comment(path, addr, &text)?;
            Ok(serde_json::json!({ "commented": true }))
        }),
        Request::MakeFunction {
            id,
            session_id,
            addr,
        } => with_project(id, session_id, sessions, |path| {
            ura_core::commands::make_function(path, addr)?;
            Ok(serde_json::json!({ "made_function": true }))
        }),
        Request::SetFunctionRange {
            id,
            session_id,
            function_addr,
            start,
            end,
        } => with_project(id, session_id, sessions, |path| {
            ura_core::commands::set_function_range(path, function_addr, start, end)?;
            Ok(serde_json::json!({ "range_set": true }))
        }),
        Request::Reanalyze { id, session_id } => with_project(id, session_id, sessions, |path| {
            ura_core::commands::reanalyze(path)?;
            Ok(serde_json::json!({ "reanalyzed": true }))
        }),
    }
}

fn with_project<F>(id: u64, session_id: u64, sessions: &HashMap<u64, PathBuf>, f: F) -> String
where
    F: FnOnce(&PathBuf) -> Result<serde_json::Value>,
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
