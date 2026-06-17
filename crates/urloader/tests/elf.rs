use urloader::{load, LoadError};

#[test]
fn rejects_unknown_binary_magic() {
    let err = load(b"not a binary").unwrap_err();
    assert!(matches!(err, LoadError::UnknownFormat));
}
