use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

pub mod shell;

pub struct SessionProject {
    pub path: PathBuf,
    pub stored: urastore::StoredProject,
    pub session: ura_core::analysis::session::AnalysisSession,
}

impl SessionProject {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let stored = urastore::load_project(&path)?;
        let loaded =
            urloader::load(&stored.source.source_bytes).map_err(|err| anyhow!(err.to_string()))?;
        let session = ura_core::analysis::session::AnalysisSession::from_parts(
            ura_core::analysis::session::AnalysisInputs {
                loaded,
                user_facts: stored.user_truth.facts.clone(),
            },
            stored.cache.state.clone(),
            stored
                .cache_metadata
                .is_stale_for(&stored.source, &stored.user_truth),
        );
        Ok(Self {
            path,
            stored,
            session,
        })
    }

    pub fn create(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<Self> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let path = output.as_ref().to_path_buf();
        let source_bytes = std::fs::read(input)?;
        let loaded = urloader::load(&source_bytes).map_err(|err| anyhow!(err.to_string()))?;
        let mut hasher = DefaultHasher::new();
        source_bytes.hash(&mut hasher);
        let source_hash = format!("{:016x}", hasher.finish());
        let stored = urastore::StoredProject {
            source: urastore::ProjectSource {
                source_bytes,
                source_hash: source_hash.clone(),
                format: format!("{:?}", loaded.format),
                architecture: format!("{:?}", loaded.architecture),
                profile: format!("{:?}", loaded.profile),
                entry: loaded.entry,
            },
            user_truth: urastore::UserTruth::default(),
            cache: urastore::AnalysisCache::default(),
            cache_metadata: urastore::CacheMetadata::fresh(
                env!("CARGO_PKG_VERSION"),
                "kernel-v1",
                &source_hash,
                0,
            ),
        };
        let session = ura_core::analysis::session::AnalysisSession::new(
            ura_core::analysis::session::AnalysisInputs::from_loaded(&loaded),
        );
        Ok(Self {
            path,
            stored,
            session,
        })
    }

    pub fn save(&mut self) -> Result<()> {
        if self.stored.user_truth.facts != self.session.inputs.user_facts {
            self.stored.user_truth.revision += 1;
        }
        self.stored.user_truth.facts = self.session.inputs.user_facts.clone();
        self.stored.cache.state = self.session.state.clone();
        self.stored.cache_metadata = urastore::CacheMetadata::fresh(
            env!("CARGO_PKG_VERSION"),
            "kernel-v1",
            &self.stored.source.source_hash,
            self.stored.user_truth.revision,
        );
        urastore::save_project(&self.path, &self.stored)?;
        Ok(())
    }

    pub fn refresh(&mut self) -> Result<()> {
        self.session.refresh()?;
        Ok(())
    }

    pub fn force_reanalyze(&mut self) -> Result<()> {
        self.session
            .mark_dirty(ura_core::analysis::invalidation::DirtyInputs {
                source_bytes: true,
                ..Default::default()
            });
        self.refresh()
    }
}
