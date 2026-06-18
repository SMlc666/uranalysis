use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ura_core::model::{AnalysisState, UserFacts};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSource {
    pub source_bytes: Vec<u8>,
    pub source_hash: String,
    pub format: String,
    pub architecture: String,
    pub profile: String,
    pub entry: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UserTruth {
    pub facts: UserFacts,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AnalysisCache {
    pub state: AnalysisState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub schema_version: u32,
    pub engine_version: String,
    pub pass_graph_version: String,
    pub source_hash_at_cache_time: String,
    pub user_truth_revision: u64,
    pub pass_fingerprints: BTreeMap<String, String>,
}

impl CacheMetadata {
    pub fn fresh(
        engine_version: &str,
        pass_graph_version: &str,
        source_hash: &str,
        revision: u64,
    ) -> Self {
        Self {
            schema_version: 1,
            engine_version: engine_version.to_string(),
            pass_graph_version: pass_graph_version.to_string(),
            source_hash_at_cache_time: source_hash.to_string(),
            user_truth_revision: revision,
            pass_fingerprints: BTreeMap::new(),
        }
    }

    pub fn is_stale_for(&self, source: &ProjectSource, user_truth: &UserTruth) -> bool {
        self.source_hash_at_cache_time != source.source_hash
            || self.user_truth_revision != user_truth.revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredProject {
    pub source: ProjectSource,
    pub user_truth: UserTruth,
    pub cache: AnalysisCache,
    pub cache_metadata: CacheMetadata,
}
