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
