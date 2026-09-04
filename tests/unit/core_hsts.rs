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

// ============================================================================
// HSTS Persistence Tests
// ============================================================================

#[test]
fn test_save_and_load() {
    let mut store = HstsStore::new();
    store.add("example.com", false, 86400);
    store.add("secure.com", true, 172800);

    // Save to temp file
    let temp_path = std::env::temp_dir().join("utwget_hsts_test.json");
    store.save_to_file(&temp_path).unwrap();

    // Load into new store
    let mut store2 = HstsStore::new();
    store2.load_from_file(&temp_path).unwrap();

    assert_eq!(store2.len(), 2);
    assert!(store2.lookup("example.com").is_some());
    assert!(store2.lookup("secure.com").is_some());

    // Cleanup
    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_load_nonexistent_file() {
    let mut store = HstsStore::new();
    let path = PathBuf::from("/nonexistent/path/hsts.json");

    // Loading nonexistent file should succeed without error
    let result = store.load_from_file(&path);
    assert!(result.is_ok());
}

#[test]
fn test_merge_persisted() {
    let mut store1 = HstsStore::new();
    store1.add("example.com", false, 86400);

    // Save to temp file
    let temp_path = std::env::temp_dir().join("utwget_hsts_merge_test.json");
    store1.save_to_file(&temp_path).unwrap();

    // Create another store and merge
    let mut store2 = HstsStore::new();
    store2.add("other.com", true, 86400);
    store2.merge_persisted(&temp_path);

    // Should have both entries
    assert!(store2.lookup("example.com").is_some());
    assert!(store2.lookup("other.com").is_some());

    // Cleanup
    let _ = fs::remove_file(&temp_path);
}

// ============================================================================
// HSTS Expiration Tests
// ============================================================================

#[test]
fn test_prune_expired() {
    let mut store = HstsStore::new();
    // Add entry with very short max-age
    store.add("example.com", false, 1);

    // Wait a bit
    std::thread::sleep(std::time::Duration::from_millis(1100));

    store.prune_expired();
    // Entry should be removed
    assert!(store.lookup("example.com").is_none());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_host() {
    let mut store = HstsStore::new();
    store.add("", false, 86400);

    // Empty host should still work
    assert!(store.lookup("").is_some());
}

#[test]
fn test_very_long_max_age() {
    let mut store = HstsStore::new();
    // Very long max-age (10 years in seconds)
    store.add("example.com", false, 10 * 365 * 24 * 60 * 60);

    assert!(store.lookup("example.com").is_some());
}
