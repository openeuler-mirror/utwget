//! Unit tests for wgetrc configuration file parsing.
//!
//! These tests verify the parsing and application of wgetrc configuration files,
//! including key-value settings, boolean toggles, and error handling.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use utwget_cli::wgetrc::{WgetrcCommand, WgetrcParser};
use ut_core::Config;

// ============================================================================
// Helper Functions
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create a temporary wgetrc file with the given content.
fn create_temp_wgetrc(content: &str) -> PathBuf {
    let temp_dir = std::env::temp_dir();
    let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = temp_dir.join(format!("test_wgetrc_{}_{}.tmp", std::process::id(), counter));
    let mut file = fs::File::create(&path).expect("Failed to create temp file");
    file.write_all(content.as_bytes()).expect("Failed to write temp file");
    file.flush().expect("Failed to flush temp file");
    path
}

/// Clean up a temporary file.
fn cleanup_temp_file(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

// ============================================================================
// File Parsing Tests
// ============================================================================

#[test]
fn test_parse_empty_file() {
    let path = create_temp_wgetrc("");
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert!(commands.is_empty());
}

#[test]
fn test_parse_comments_only() {
    let content = r#"# This is a comment
# Another comment
# Settings below are commented out
# quiet = on
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert!(commands.is_empty());
}

#[test]
fn test_parse_simple_key_value() {
    let content = r#"dir_prefix = /downloads
user_agent = MyDownloader/1.0
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0], WgetrcCommand::Set("dir_prefix".to_string(), "/downloads".to_string()));
    assert_eq!(commands[1], WgetrcCommand::Set("user_agent".to_string(), "MyDownloader/1.0".to_string()));
}

#[test]
fn test_parse_boolean_on() {
    let content = r#"quiet = on
verbose = ON
recursive = On
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0], WgetrcCommand::OnOff("quiet".to_string(), true));
    assert_eq!(commands[1], WgetrcCommand::OnOff("verbose".to_string(), true));
    assert_eq!(commands[2], WgetrcCommand::OnOff("recursive".to_string(), true));
}

#[test]
fn test_parse_boolean_off() {
    let content = r#"quiet = off
verbose = OFF
recursive = Off
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0], WgetrcCommand::OnOff("quiet".to_string(), false));
    assert_eq!(commands[1], WgetrcCommand::OnOff("verbose".to_string(), false));
    assert_eq!(commands[2], WgetrcCommand::OnOff("recursive".to_string(), false));
}

#[test]
fn test_parse_command_style() {
    let content = r#"accept *.html *.css
reject *.pdf
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0], WgetrcCommand::Command("accept".to_string(), vec!["*.html".to_string(), "*.css".to_string()]));
    assert_eq!(commands[1], WgetrcCommand::Command("reject".to_string(), vec!["*.pdf".to_string()]));
}
