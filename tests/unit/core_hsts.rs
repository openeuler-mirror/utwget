//! Unit tests for HSTS (HTTP Strict Transport Security) support.

use ut_core::hsts::HstsStore;
use ut_core::types::Scheme;
use std::path::PathBuf;
use std::fs;

// ============================================================================
// HSTS Entry Tests
// ============================================================================

#[test]
fn test_hsts_store_new() {
    let store = HstsStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}
