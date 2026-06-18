use tempfile::tempdir;
use urastore::{
    load_project, save_project, AnalysisCache, CacheMetadata, ProjectSource, StoreError,
    StoredProject, UserTruth,
};

#[test]
fn stored_project_roundtrips_truth_and_cache() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sample.ura");
    let project = StoredProject {
        source: ProjectSource {
            source_bytes: vec![0x7f, b'E', b'L', b'F'],
            source_hash: "hash".to_string(),
            format: "elf".to_string(),
            architecture: "aarch64".to_string(),
            profile: "executable".to_string(),
            entry: 0x400080,
        },
        user_truth: UserTruth::default(),
        cache: AnalysisCache::default(),
        cache_metadata: CacheMetadata::fresh("0.1.0", "kernel-v1", "hash", 0),
    };

    save_project(&path, &project).unwrap();
    let loaded = load_project(&path).unwrap();

    assert_eq!(loaded.source.source_hash, "hash");
    assert_eq!(loaded.cache_metadata.source_hash_at_cache_time, "hash");
    assert!(loaded.cache_metadata.pass_fingerprints.is_empty());
}

#[test]
fn legacy_core_snapshot_is_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("legacy.ura");
    std::fs::write(&path, b"URA0legacy-body").unwrap();

    let err = load_project(&path).unwrap_err();
    assert!(matches!(err, StoreError::UnsupportedFormat(_)));
}
