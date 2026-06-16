use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::tempdir;

fn minimal_elf64_aarch64_executable() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x1000];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&183u16.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&0x400080u64.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    bytes[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let ph = 0x40usize;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    bytes
}

#[test]
fn daemon_opens_project_and_writes_comment() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.elf");
    let project = dir.path().join("sample.ura");
    std::fs::write(&input, minimal_elf64_aarch64_executable()).unwrap();
    ura_core::commands::new_project(&input, &project).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = spawn_daemon(&addr);
    let mut stream = connect_with_retry(&addr);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    send(
        &mut stream,
        serde_json::json!({
            "method": "open_project",
            "id": 1,
            "path": project.to_string_lossy()
        }),
    );
    let response = recv(&mut reader);
    assert_eq!(response["ok"], true);
    let session_id = response["result"]["session_id"].as_u64().unwrap();

    send(
        &mut stream,
        serde_json::json!({
            "method": "get_info",
            "id": 2,
            "session_id": session_id
        }),
    );
    let response = recv(&mut reader);
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["architecture"], "Aarch64");

    send(
        &mut stream,
        serde_json::json!({
            "method": "set_comment",
            "id": 3,
            "session_id": session_id,
            "addr": 0x400080u64,
            "text": "daemon comment"
        }),
    );
    let response = recv(&mut reader);
    assert_eq!(response["ok"], true);
    assert_eq!(
        ura_core::commands::comments(&project, 0x400080).unwrap(),
        vec!["daemon comment".to_string()]
    );

    child.kill().unwrap();
    let _ = child.wait();
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn_daemon(addr: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ura-daemon"))
        .arg(addr)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn connect_with_retry(addr: &str) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) => panic!("daemon did not accept connections: {err}"),
        }
    }
}

fn send(stream: &mut TcpStream, value: serde_json::Value) {
    writeln!(stream, "{value}").unwrap();
}

fn recv(reader: &mut BufReader<TcpStream>) -> serde_json::Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}
