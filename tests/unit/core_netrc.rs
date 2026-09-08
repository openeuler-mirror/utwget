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

#[test]
fn test_parse_with_default() {
    let content = r#"
machine specific.example.com
login specificuser
password specificpass

default
login anonymous
password anon@example.com
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    // Specific machine should match
    let creds = db.lookup("specific.example.com").unwrap();
    assert_eq!(creds.username, "specificuser");

    // Unknown machine should use default
    let creds = db.lookup("unknown.example.com").unwrap();
    assert_eq!(creds.username, "anonymous");
}

#[test]
fn test_parse_with_account() {
    let content = r#"
machine ftp.example.com
login myuser
password mypass
account myaccount
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    assert!(!db.is_empty());
    // Account is stored but not returned by lookup
}

// ============================================================================
// Lookup Tests
// ============================================================================

#[test]
fn test_lookup_case_insensitive() {
    let content = r#"
machine Example.COM
login myuser
password mypass
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    let creds = db.lookup("example.com").unwrap();
    assert_eq!(creds.username, "myuser");

    let creds = db.lookup("EXAMPLE.COM").unwrap();
    assert_eq!(creds.username, "myuser");
}

#[test]
fn test_lookup_no_match() {
    let content = r#"
machine ftp.example.com
login myuser
password mypass
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    assert!(db.lookup("other.com").is_none());
}

#[test]
fn test_lookup_no_match_no_default() {
    let content = r#"
machine ftp.example.com
login myuser
password mypass
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    // No default, so unknown host returns None
    assert!(db.lookup("unknown.com").is_none());
}

#[test]
fn test_lookup_missing_password() {
    let content = r#"
machine ftp.example.com
login myuser
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    // Entry without password should return None
    assert!(db.lookup("ftp.example.com").is_none());
}

#[test]
fn test_lookup_missing_login() {
    let content = r#"
machine ftp.example.com
password mypass
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    // Entry without login should return None
    assert!(db.lookup("ftp.example.com").is_none());
}

// ============================================================================
// Format Variations Tests
// ============================================================================

#[test]
fn test_parse_with_comments() {
    let content = r#"
# This is a comment
machine ftp.example.com
login myuser
password mypass
# Another comment
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    let creds = db.lookup("ftp.example.com").unwrap();
    assert_eq!(creds.username, "myuser");
}

#[test]
fn test_parse_with_whitespace() {
    let content = r#"
machine   ftp.example.com
login   myuser
password   mypass
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    let creds = db.lookup("ftp.example.com").unwrap();
    assert_eq!(creds.username, "myuser");
}

#[test]
fn test_parse_with_tabs() {
    let content = "machine\tftp.example.com\nlogin\tmyuser\npassword\tmypass";
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    let creds = db.lookup("ftp.example.com").unwrap();
    assert_eq!(creds.username, "myuser");
}
