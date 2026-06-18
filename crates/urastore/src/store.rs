use std::{fs, path::Path};

use crate::{
    error::{Result, StoreError},
    model::StoredProject,
};

const MAGIC: &[u8; 4] = b"URS1";

pub fn save_project(path: &Path, project: &StoredProject) -> Result<()> {
    let mut out = Vec::from(*MAGIC);
    let payload = bincode::serialize(project).map_err(|err| StoreError::Encode(err.to_string()))?;
    out.extend_from_slice(&payload);
    fs::write(path, out)?;
    Ok(())
}

pub fn load_project(path: &Path) -> Result<StoredProject> {
    let bytes = fs::read(path)?;
    if bytes.get(0..4) != Some(MAGIC.as_slice()) {
        return Err(StoreError::UnsupportedFormat(
            "expected URS1 container".to_string(),
        ));
    }
    bincode::deserialize(&bytes[4..]).map_err(|err| StoreError::Decode(err.to_string()))
}
