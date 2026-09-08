//! Unit tests for .netrc file parsing.

use ut_core::netrc::NetrcDb;
use std::path::PathBuf;
use std::fs;

// ============================================================================
// Basic Parsing Tests
// ============================================================================

#[test]
fn test_netrc_new() {
    let db = NetrcDb::new();
    assert!(db.is_empty());
}

#[test]
fn test_parse_single_machine() {
    let content = r#"
machine ftp.example.com
login myuser
password mypass
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    let creds = db.lookup("ftp.example.com").unwrap();
    assert_eq!(creds.username, "myuser");
    assert_eq!(creds.password, "mypass");
}
