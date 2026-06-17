use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

use crate::{
    model::{
        Architecture, BinaryFormat, Diagnostic, Function, FunctionSource, Instruction, LoadProfile,
        ProjectInfo, Section, Segment, StringRef, Symbol, Xref, XrefKind,
    },
    Result, UraError,
};

pub const SCHEMA_VERSION: i64 = 2;

pub fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(conn)
}

pub fn initialize(conn: &Connection, source_hash: &str) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS segments (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            vaddr INTEGER NOT NULL,
            file_offset INTEGER NOT NULL,
            file_size INTEGER NOT NULL,
            mem_size INTEGER NOT NULL,
            permissions TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sections (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            addr INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            size INTEGER NOT NULL,
            flags INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS symbols (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            addr INTEGER NOT NULL,
            size INTEGER NOT NULL,
            kind TEXT NOT NULL,
            is_import INTEGER NOT NULL,
            is_export INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS instructions (
            addr INTEGER PRIMARY KEY,
            size INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            mnemonic TEXT NOT NULL,
            operands TEXT NOT NULL,
            text TEXT NOT NULL,
            kind TEXT NOT NULL,
            flow TEXT NOT NULL,
            fallthrough INTEGER,
            branch_target INTEGER,
            decode_status TEXT NOT NULL,
            decoder TEXT NOT NULL,
            decoder_version TEXT NOT NULL,
            function_addr INTEGER
        );
        CREATE TABLE IF NOT EXISTS functions (
            addr INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            start INTEGER NOT NULL,
            end INTEGER NOT NULL,
            source TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS basic_blocks (
            id INTEGER PRIMARY KEY,
            function_addr INTEGER NOT NULL,
            start INTEGER NOT NULL,
            end INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS xrefs (
            from_addr INTEGER NOT NULL,
            to_addr INTEGER NOT NULL,
            kind TEXT NOT NULL,
            PRIMARY KEY (from_addr, to_addr, kind)
        );
        CREATE TABLE IF NOT EXISTS strings (
            addr INTEGER PRIMARY KEY,
            value TEXT NOT NULL,
            encoding TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS comments (
            addr INTEGER PRIMARY KEY,
            text TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS renames (
            addr INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS diagnostics (
            id INTEGER PRIMARY KEY,
            addr INTEGER,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        );
        ",
    )?;
    set_metadata(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
    set_metadata(conn, "engine_version", env!("CARGO_PKG_VERSION"))?;
    set_metadata(conn, "source_hash", source_hash)?;
    Ok(())
}

pub fn migrate(conn: &Connection) -> Result<()> {
    let Some(version) = get_metadata(conn, "schema_version")? else {
        return Err(UraError::NotFound("schema_version metadata".to_string()));
    };
    let version = version
        .parse::<i64>()
        .map_err(|err| UraError::Unsupported(format!("invalid schema_version: {err}")))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version != 1 {
        return Err(UraError::Unsupported(format!(
            "schema version {version}, expected {SCHEMA_VERSION}"
        )));
    }

    conn.execute("DROP TABLE IF EXISTS instructions", [])?;
    conn.execute(
        "CREATE TABLE instructions (
            addr INTEGER PRIMARY KEY,
            size INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            mnemonic TEXT NOT NULL,
            operands TEXT NOT NULL,
            text TEXT NOT NULL,
            kind TEXT NOT NULL,
            flow TEXT NOT NULL,
            fallthrough INTEGER,
            branch_target INTEGER,
            decode_status TEXT NOT NULL,
            decoder TEXT NOT NULL,
            decoder_version TEXT NOT NULL,
            function_addr INTEGER
        )",
        [],
    )?;
    set_metadata(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
    Ok(())
}

pub fn set_metadata(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO metadata(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn get_metadata(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?)
}

pub fn insert_segments(conn: &Connection, segments: &[Segment]) -> Result<()> {
    conn.execute("DELETE FROM segments", [])?;
    for segment in segments {
        conn.execute(
            "INSERT INTO segments(id, name, vaddr, file_offset, file_size, mem_size, permissions)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                segment.id,
                segment.name,
                to_i64(segment.vaddr)?,
                to_i64(segment.file_offset)?,
                to_i64(segment.file_size)?,
                to_i64(segment.mem_size)?,
                segment.permissions
            ],
        )?;
    }
    Ok(())
}

pub fn insert_sections(conn: &Connection, sections: &[Section]) -> Result<()> {
    conn.execute("DELETE FROM sections", [])?;
    for section in sections {
        conn.execute(
            "INSERT INTO sections(id, name, addr, offset, size, flags)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                section.id,
                section.name,
                to_i64(section.addr)?,
                to_i64(section.offset)?,
                to_i64(section.size)?,
                to_i64(section.flags)?
            ],
        )?;
    }
    Ok(())
}

pub fn insert_symbols(conn: &Connection, symbols: &[Symbol]) -> Result<()> {
    conn.execute("DELETE FROM symbols", [])?;
    for symbol in symbols {
        conn.execute(
            "INSERT INTO symbols(id, name, addr, size, kind, is_import, is_export)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                symbol.id,
                symbol.name,
                to_i64(symbol.addr)?,
                to_i64(symbol.size)?,
                symbol.kind,
                symbol.is_import as i64,
                symbol.is_export as i64
            ],
        )?;
    }
    Ok(())
}

pub fn insert_instructions(conn: &Connection, instructions: &[Instruction]) -> Result<()> {
    conn.execute("DELETE FROM instructions", [])?;
    for insn in instructions {
        conn.execute(
            "INSERT INTO instructions(addr, size, bytes, mnemonic, operands, text, kind, flow, fallthrough, branch_target, decode_status, decoder, decoder_version, function_addr)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                to_i64(insn.addr)?,
                i64::from(insn.size),
                insn.bytes,
                insn.mnemonic,
                insn.operands,
                insn.text,
                insn.kind,
                insn.flow,
                optional_to_i64(insn.fallthrough)?,
                optional_to_i64(insn.branch_target)?,
                insn.decode_status,
                insn.decoder,
                insn.decoder_version,
                optional_to_i64(insn.function_addr)?
            ],
        )?;
    }
    Ok(())
}

pub fn insert_strings(conn: &Connection, strings: &[StringRef]) -> Result<()> {
    conn.execute("DELETE FROM strings", [])?;
    for s in strings {
        conn.execute(
            "INSERT INTO strings(addr, value, encoding) VALUES(?1, ?2, ?3)",
            params![to_i64(s.addr)?, s.value, s.encoding],
        )?;
    }
    Ok(())
}

pub fn insert_functions(conn: &Connection, functions: &[Function]) -> Result<()> {
    conn.execute("DELETE FROM functions WHERE source != 'User'", [])?;
    for function in functions {
        conn.execute(
            "INSERT INTO functions(addr, name, start, end, source)
             VALUES(?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(addr) DO UPDATE SET
                name = excluded.name,
                start = excluded.start,
                end = excluded.end,
                source = excluded.source",
            params![
                to_i64(function.addr)?,
                function.name,
                to_i64(function.start)?,
                to_i64(function.end)?,
                format!("{:?}", function.source)
            ],
        )?;
    }
    Ok(())
}

pub fn insert_xrefs(conn: &Connection, xrefs: &[Xref]) -> Result<()> {
    conn.execute("DELETE FROM xrefs", [])?;
    for xref in xrefs {
        conn.execute(
            "INSERT OR IGNORE INTO xrefs(from_addr, to_addr, kind) VALUES(?1, ?2, ?3)",
            params![
                to_i64(xref.from_addr)?,
                to_i64(xref.to_addr)?,
                format!("{:?}", xref.kind)
            ],
        )?;
    }
    Ok(())
}

pub fn insert_diagnostics(conn: &Connection, diagnostics: &[Diagnostic]) -> Result<()> {
    conn.execute("DELETE FROM diagnostics", [])?;
    for diagnostic in diagnostics {
        conn.execute(
            "INSERT INTO diagnostics(addr, severity, message) VALUES(?1, ?2, ?3)",
            params![
                optional_to_i64(diagnostic.addr)?,
                diagnostic.severity,
                diagnostic.message
            ],
        )?;
    }
    Ok(())
}

pub fn project_info(conn: &Connection) -> Result<ProjectInfo> {
    let schema_version = get_metadata(conn, "schema_version")?
        .unwrap_or_else(|| "1".to_string())
        .parse::<i64>()
        .map_err(|err| UraError::Unsupported(format!("invalid schema_version: {err}")))?;
    let engine_version = get_metadata(conn, "engine_version")?.unwrap_or_default();
    let source_hash = get_metadata(conn, "source_hash")?.unwrap_or_default();
    let profile = parse_load_profile(
        get_metadata(conn, "profile")?
            .unwrap_or_else(|| "Executable".to_string())
            .as_str(),
    );
    Ok(ProjectInfo {
        schema_version,
        engine_version,
        source_hash,
        format: BinaryFormat::Elf64,
        architecture: Architecture::Aarch64,
        profile,
    })
}

pub fn query_disasm(conn: &Connection, addr: u64, count: usize) -> Result<Vec<Instruction>> {
    let mut stmt = conn.prepare(
        "SELECT addr, size, bytes, mnemonic, operands, text, kind, flow, fallthrough, branch_target, decode_status, decoder, decoder_version, function_addr
         FROM instructions WHERE addr >= ?1 ORDER BY addr LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![to_i64(addr)?, count as i64], |row| {
        Ok(Instruction {
            addr: from_i64(row.get(0)?),
            size: row.get::<_, i64>(1)? as u8,
            bytes: row.get(2)?,
            mnemonic: row.get(3)?,
            operands: row.get(4)?,
            text: row.get(5)?,
            kind: row.get(6)?,
            flow: row.get(7)?,
            fallthrough: row.get::<_, Option<i64>>(8)?.map(from_i64),
            branch_target: row.get::<_, Option<i64>>(9)?.map(from_i64),
            decode_status: row.get(10)?,
            decoder: row.get(11)?,
            decoder_version: row.get(12)?,
            function_addr: row.get::<_, Option<i64>>(13)?.map(from_i64),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn query_strings(conn: &Connection, filter: Option<&str>) -> Result<Vec<StringRef>> {
    let pattern = format!("%{}%", filter.unwrap_or(""));
    let mut stmt = conn
        .prepare("SELECT addr, value, encoding FROM strings WHERE value LIKE ?1 ORDER BY addr")?;
    let rows = stmt.query_map(params![pattern], |row| {
        Ok(StringRef {
            addr: from_i64(row.get(0)?),
            value: row.get(1)?,
            encoding: row.get(2)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn query_functions(conn: &Connection) -> Result<Vec<Function>> {
    let mut stmt =
        conn.prepare("SELECT addr, name, start, end, source FROM functions ORDER BY addr")?;
    let rows = stmt.query_map([], |row| {
        let source: String = row.get(4)?;
        Ok(Function {
            addr: from_i64(row.get(0)?),
            name: row.get(1)?,
            start: from_i64(row.get(2)?),
            end: from_i64(row.get(3)?),
            source: parse_function_source(&source),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn query_xrefs(conn: &Connection, addr: u64) -> Result<Vec<Xref>> {
    let mut stmt = conn.prepare(
        "SELECT from_addr, to_addr, kind FROM xrefs
         WHERE to_addr = ?1 OR from_addr = ?1 ORDER BY from_addr, to_addr",
    )?;
    let rows = stmt.query_map(params![to_i64(addr)?], |row| {
        let kind: String = row.get(2)?;
        Ok(Xref {
            from_addr: from_i64(row.get(0)?),
            to_addr: from_i64(row.get(1)?),
            kind: parse_xref_kind(&kind),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn rename(conn: &Connection, addr: u64, name: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO renames(addr, name) VALUES(?1, ?2)
         ON CONFLICT(addr) DO UPDATE SET name = excluded.name",
        params![to_i64(addr)?, name],
    )?;
    conn.execute(
        "UPDATE functions SET name = ?2 WHERE addr = ?1",
        params![to_i64(addr)?, name],
    )?;
    Ok(())
}

pub fn set_comment(conn: &Connection, addr: u64, text: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO comments(addr, text) VALUES(?1, ?2)
         ON CONFLICT(addr) DO UPDATE SET text = excluded.text",
        params![to_i64(addr)?, text],
    )?;
    Ok(())
}

pub fn query_comments(conn: &Connection, addr: u64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT text FROM comments WHERE addr = ?1")?;
    let rows = stmt.query_map(params![to_i64(addr)?], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn upsert_user_function(conn: &Connection, function: &Function) -> Result<()> {
    conn.execute(
        "INSERT INTO functions(addr, name, start, end, source)
         VALUES(?1, ?2, ?3, ?4, 'User')
         ON CONFLICT(addr) DO UPDATE SET
            name = excluded.name,
            start = excluded.start,
            end = excluded.end,
            source = 'User'",
        params![
            to_i64(function.addr)?,
            function.name,
            to_i64(function.start)?,
            to_i64(function.end)?
        ],
    )?;
    Ok(())
}

pub fn query_diagnostics(conn: &Connection) -> Result<Vec<Diagnostic>> {
    let mut stmt = conn.prepare("SELECT addr, severity, message FROM diagnostics ORDER BY id")?;
    let rows = stmt.query_map([], |row| {
        Ok(Diagnostic {
            addr: row.get::<_, Option<i64>>(0)?.map(from_i64),
            severity: row.get(1)?,
            message: row.get(2)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn parse_load_profile(profile: &str) -> LoadProfile {
    match profile {
        "SharedObject" => LoadProfile::SharedObject,
        "Relocatable" => LoadProfile::Relocatable,
        "KernelStyle" => LoadProfile::KernelStyle,
        "StrippedLike" => LoadProfile::StrippedLike,
        _ => LoadProfile::Executable,
    }
}

fn parse_function_source(source: &str) -> FunctionSource {
    match source {
        "Entry" => FunctionSource::Entry,
        "BranchTarget" => FunctionSource::BranchTarget,
        "User" => FunctionSource::User,
        _ => FunctionSource::Symbol,
    }
}

fn parse_xref_kind(kind: &str) -> XrefKind {
    match kind {
        "Call" => XrefKind::Call,
        "Data" => XrefKind::Data,
        "String" => XrefKind::String,
        _ => XrefKind::Code,
    }
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| UraError::Unsupported(format!("value does not fit SQLite INTEGER: {value}")))
}

fn optional_to_i64(value: Option<u64>) -> Result<Option<i64>> {
    value.map(to_i64).transpose()
}

fn from_i64(value: i64) -> u64 {
    value as u64
}
