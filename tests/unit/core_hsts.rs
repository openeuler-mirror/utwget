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

#[test]
fn test_hsts_add_entry() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);

    assert!(!store.is_empty());
    assert_eq!(store.len(), 1);
}

#[test]
fn test_hsts_add_with_subdomains() {
    let mut store = HstsStore::new();
    store.add("example.com", true, 86400);

    let result = store.lookup("example.com");
    assert!(result.is_some());
    assert!(result.unwrap()); // include_subdomains should be true
}

#[test]
fn test_hsts_add_without_subdomains() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);

    let result = store.lookup("example.com");
    assert!(result.is_some());
    assert!(!result.unwrap()); // include_subdomains should be false
}

// ============================================================================
// HSTS Lookup Tests
// ============================================================================

#[test]
fn test_lookup_exact_match() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);

    assert!(store.lookup("example.com").is_some());
    assert!(store.lookup("other.com").is_none());
}
