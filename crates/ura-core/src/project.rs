use std::path::{Path, PathBuf};

use crate::{
    store::{BinaryProjectStore, ProjectFile, ProjectStore},
    Result, UraError,
};

pub struct Project {
    path: PathBuf,
    file: ProjectFile,
}

impl Project {
    pub fn create_empty(path: impl AsRef<Path>, source_hash: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = ProjectFile::empty(source_hash);
        BinaryProjectStore.save(&path, &file)?;
        Ok(Self { path, file })
    }

    pub fn create(path: impl AsRef<Path>, file: ProjectFile) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        BinaryProjectStore.save(&path, &file)?;
        Ok(Self { path, file })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = BinaryProjectStore.load(&path)?;
        Ok(Self { path, file })
    }

    pub fn save(&self) -> Result<()> {
        BinaryProjectStore.save(&self.path, &self.file)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut ProjectFile {
        &mut self.file
    }

    pub fn source_hash(&self) -> Result<String> {
        Ok(self.file.info.source_hash.clone())
    }

    pub fn schema_version(&self) -> Result<i64> {
        if self.file.info.schema_version <= 0 {
            return Err(UraError::ProjectFormat(format!(
                "invalid schema_version: {}",
                self.file.info.schema_version
            )));
        }
        Ok(self.file.info.schema_version)
    }
}
