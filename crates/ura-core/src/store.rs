use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    model::{
        Architecture, BasicBlock, BinaryFormat, CfgEdge, Diagnostic, Endian, Function, ImageClass,
        Instruction, LoadProfile, ProjectInfo, Section, Segment, StringRef, Symbol, Xref,
    },
    Result, UraError,
};

pub const PROJECT_MAGIC: [u8; 4] = *b"URA0";
pub const PROJECT_CONTAINER_VERSION: u32 = 1;
pub const PROJECT_SCHEMA_VERSION: i64 = 4;

const HEADER_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectFile {
    pub info: ProjectInfo,
    pub source_bytes: Vec<u8>,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub instructions: Vec<Instruction>,
    pub basic_blocks: Vec<BasicBlock>,
    pub cfg_edges: Vec<CfgEdge>,
    pub functions: Vec<Function>,
    pub xrefs: Vec<Xref>,
    pub strings: Vec<StringRef>,
    pub comments: BTreeMap<u64, String>,
    pub renames: BTreeMap<u64, String>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ProjectFile {
    pub fn empty(source_hash: impl Into<String>) -> Self {
        Self {
            info: ProjectInfo {
                schema_version: PROJECT_SCHEMA_VERSION,
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                source_hash: source_hash.into(),
                format: BinaryFormat::Elf,
                architecture: Architecture::Aarch64,
                class: ImageClass::Bits64,
                endian: Endian::Little,
                profile: LoadProfile::StrippedLike,
            },
            source_bytes: Vec::new(),
            segments: Vec::new(),
            sections: Vec::new(),
            symbols: Vec::new(),
            instructions: Vec::new(),
            basic_blocks: Vec::new(),
            cfg_edges: Vec::new(),
            functions: Vec::new(),
            xrefs: Vec::new(),
            strings: Vec::new(),
            comments: BTreeMap::new(),
            renames: BTreeMap::new(),
            diagnostics: Vec::new(),
        }
    }
}

pub trait ProjectStore {
    fn load(&self, path: &Path) -> Result<ProjectFile>;
    fn save(&self, path: &Path, project: &ProjectFile) -> Result<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BinaryProjectStore;

impl ProjectStore for BinaryProjectStore {
    fn load(&self, path: &Path) -> Result<ProjectFile> {
        let bytes = fs::read(path)?;
        decode_project_file(&bytes)
    }

    fn save(&self, path: &Path, project: &ProjectFile) -> Result<()> {
        let bytes = encode_project_file(project)?;
        let tmp_path = temporary_path(path);
        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

fn encode_project_file(project: &ProjectFile) -> Result<Vec<u8>> {
    let payload = bincode::serialize(project)
        .map_err(|err| UraError::ProjectFormat(format!("encode project payload: {err}")))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&PROJECT_MAGIC);
    out.extend_from_slice(&PROJECT_CONTAINER_VERSION.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

fn decode_project_file(bytes: &[u8]) -> Result<ProjectFile> {
    if bytes.len() < HEADER_LEN {
        return Err(UraError::ProjectFormat(
            "truncated project header".to_string(),
        ));
    }
    if bytes[0..4] != PROJECT_MAGIC {
        return Err(UraError::ProjectFormat("invalid project magic".to_string()));
    }

    let version = u32::from_le_bytes(bytes[4..8].try_into().expect("header length checked"));
    if version != PROJECT_CONTAINER_VERSION {
        return Err(UraError::ProjectFormat(format!(
            "unsupported project container version {version}"
        )));
    }

    let payload_len = u64::from_le_bytes(bytes[8..16].try_into().expect("header length checked"));
    let actual_len = bytes.len() - HEADER_LEN;
    if payload_len as usize != actual_len {
        return Err(UraError::ProjectFormat(format!(
            "project payload length mismatch: header={payload_len} actual={actual_len}"
        )));
    }

    bincode::deserialize(&bytes[HEADER_LEN..])
        .map_err(|err| UraError::ProjectFormat(format!("decode project payload: {err}")))
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}
