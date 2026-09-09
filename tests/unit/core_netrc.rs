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

#[test]
fn test_parse_with_quoted_strings() {
    let content = r#"
machine ftp.example.com
login 'my user'
password 'my pass'
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    let creds = db.lookup("ftp.example.com").unwrap();
    assert_eq!(creds.username, "my user");
    assert_eq!(creds.password, "my pass");
}

#[test]
fn test_parse_empty_lines() {
    let content = r#"

machine ftp.example.com

login myuser

password mypass

"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    let creds = db.lookup("ftp.example.com").unwrap();
    assert_eq!(creds.username, "myuser");
}

// ============================================================================
// File Loading Tests
// ============================================================================

#[test]
fn test_load_from_file() {
    // Create a temp netrc file
    let content = r#"
machine test.example.com
login testuser
password testpass
"#;
    let temp_path = std::env::temp_dir().join("utwget_netrc_test.txt");
    fs::write(&temp_path, content).unwrap();

    let mut db = NetrcDb::new();
    db.load_from_file(&temp_path).unwrap();

    let creds = db.lookup("test.example.com").unwrap();
    assert_eq!(creds.username, "testuser");

    // Cleanup
    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_load_from_file_nonexistent() {
    let mut db = NetrcDb::new();
    let path = PathBuf::from("/nonexistent/path/netrc");

    let result = db.load_from_file(&path);
    assert!(result.is_err());
}

// ============================================================================
// Macro Definition Tests
// ============================================================================

#[test]
fn test_parse_with_macdef() {
    let content = r#"
machine ftp.example.com
login myuser
password mypass
macdef mymacro
cd /pub
get file.txt
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    // Macros are stored but not returned by lookup
    assert!(!db.is_empty());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_parse_empty_content() {
    let mut db = NetrcDb::new();
    db.load_from_str("");

    assert!(db.is_empty());
}

#[test]
fn test_parse_only_comments() {
    let content = r#"
# Comment 1
# Comment 2
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    assert!(db.is_empty());
}

#[test]
fn test_parse_only_default() {
    let content = r#"
default
login anonymous
password anon@example.com
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    // Default should match any host
    let creds = db.lookup("any.example.com").unwrap();
    assert_eq!(creds.username, "anonymous");
}

#[test]
fn test_load_from_str_clears_previous() {
    let mut db = NetrcDb::new();

    db.load_from_str("machine a.com\nlogin user\npassword pass");
    assert!(db.lookup("a.com").is_some());

    db.load_from_str("machine b.com\nlogin user\npassword pass");
    assert!(db.lookup("a.com").is_none());
    assert!(db.lookup("b.com").is_some());
}

#[test]
fn test_multiple_defaults() {
    // Only one default should be used (the last one)
    let content = r#"
default
login user1
password pass1

default
login user2
password pass2
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    let creds = db.lookup("unknown.com").unwrap();
    assert_eq!(creds.username, "user2");
}

#[test]
fn test_machine_without_credentials() {
    let content = r#"
machine ftp.example.com
"#;
    let mut db = NetrcDb::new();
    db.load_from_str(content);

    // Machine without login/password should not match
    assert!(db.lookup("ftp.example.com").is_none());
}
