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

#[test]
fn test_parse_multiple_machines() {
    let content = r#"
machine host1.example.com
login user1
password pass1

machine host2.example.com
login user2
password pass2
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    let creds1 = db.lookup("host1.example.com").unwrap();
    assert_eq!(creds1.username, "user1");

    let creds2 = db.lookup("host2.example.com").unwrap();
    assert_eq!(creds2.username, "user2");
}
