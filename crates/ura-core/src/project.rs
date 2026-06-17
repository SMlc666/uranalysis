use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::{db, Result, UraError};

pub struct Project {
    path: PathBuf,
    conn: Connection,
}

impl Project {
    pub fn create_empty(path: impl AsRef<Path>, source_hash: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = db::open_connection(&path)?;
        db::initialize(&conn, source_hash)?;
        Ok(Self { path, conn })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = db::open_connection(&path)?;
        db::migrate(&conn)?;
        Ok(Self { path, conn })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn source_hash(&self) -> Result<String> {
        db::get_metadata(&self.conn, "source_hash")?
            .ok_or_else(|| UraError::NotFound("source_hash metadata".to_string()))
    }

    pub fn schema_version(&self) -> Result<i64> {
        let value = db::get_metadata(&self.conn, "schema_version")?
            .ok_or_else(|| UraError::NotFound("schema_version metadata".to_string()))?;
        value
            .parse::<i64>()
            .map_err(|err| UraError::Unsupported(format!("invalid schema_version: {err}")))
    }
}
