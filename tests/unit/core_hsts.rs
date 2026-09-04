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

#[test]
fn test_lookup_case_insensitive() {
    let mut store = HstsStore::new();
    store.add("Example.COM", false, 86400);

    assert!(store.lookup("example.com").is_some());
    assert!(store.lookup("EXAMPLE.COM").is_some());
}

#[test]
fn test_lookup_subdomain() {
    let mut store = HstsStore::new();
    store.add("example.com", true, 86400);

    // Subdomain should match when include_subdomains is true
    assert!(store.lookup("www.example.com").is_some());
    assert!(store.lookup("api.example.com").is_some());
    assert!(store.lookup("deep.sub.example.com").is_some());
}

#[test]
fn test_lookup_subdomain_not_included() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);

    // Subdomain should NOT match when include_subdomains is false
    assert!(store.lookup("www.example.com").is_none());
}

#[test]
fn test_lookup_no_match() {
    let store = HstsStore::new();
    assert!(store.lookup("example.com").is_none());
}

// ============================================================================
// HSTS Upgrade Tests
// ============================================================================

#[test]
fn test_should_upgrade_http_to_https() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);

    // HTTP should be upgraded to HTTPS
    let result = store.should_upgrade("example.com", Scheme::Http);
    assert_eq!(result, Scheme::Https);
}

#[test]
fn test_should_upgrade_https_unchanged() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);

    // HTTPS should remain HTTPS
    let result = store.should_upgrade("example.com", Scheme::Https);
    assert_eq!(result, Scheme::Https);
}

#[test]
fn test_should_upgrade_no_hsts() {
    let store = HstsStore::new();

    // Without HSTS, HTTP should remain HTTP
    let result = store.should_upgrade("example.com", Scheme::Http);
    assert_eq!(result, Scheme::Http);
}

#[test]
fn test_should_upgrade_subdomain() {
    let mut store = HstsStore::new();
    store.add("example.com", true, 86400);

    // Subdomain should also be upgraded
    let result = store.should_upgrade("www.example.com", Scheme::Http);
    assert_eq!(result, Scheme::Https);
}

// ============================================================================
// HSTS Removal Tests
// ============================================================================

#[test]
fn test_remove_entry() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);
    assert_eq!(store.len(), 1);

    store.remove("example.com");
    assert!(store.is_empty());
}

#[test]
fn test_remove_nonexistent() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);

    store.remove("other.com");
    assert_eq!(store.len(), 1);
}

#[test]
fn test_add_with_zero_max_age_removes() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);
    assert_eq!(store.len(), 1);

    // Adding with max_age=0 should remove the entry
    store.add("example.com", false, 0);
    assert!(store.is_empty());
}
