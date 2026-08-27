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
