use ut_core::HstsStore;
use ut_core::types::Scheme;

#[test]
fn hsts_add_from_header_and_upgrade() {
    let mut store = HstsStore::new();
    // Parse a standard STS header
    store.add_from_header("example.com", "max-age=31536000; includeSubDomains");
    // HTTP should be upgraded to HTTPS
    assert_eq!(store.should_upgrade("example.com", Scheme::Http), Scheme::Https);
    // Subdomain should also be upgraded
    assert_eq!(store.should_upgrade("sub.example.com", Scheme::Http), Scheme::Https);
    // HTTPS stays HTTPS
    assert_eq!(store.should_upgrade("example.com", Scheme::Https), Scheme::Https);
    // Unrelated host is not upgraded
    assert_eq!(store.should_upgrade("other.com", Scheme::Http), Scheme::Http);
}

#[test]
fn hsts_max_age_zero_removes() {
    let mut store = HstsStore::new();
    store.add_from_header("example.com", "max-age=3600");
    assert_eq!(store.should_upgrade("example.com", Scheme::Http), Scheme::Https);
    // max-age=0 deletes the entry
    store.add_from_header("example.com", "max-age=0");
    assert_eq!(store.should_upgrade("example.com", Scheme::Http), Scheme::Http);
}

#[test]
fn hsts_missing_max_age_ignored() {
    let mut store = HstsStore::new();
    store.add_from_header("example.com", "includeSubDomains");
    assert_eq!(store.should_upgrade("example.com", Scheme::Http), Scheme::Http);
}

#[test]
fn hsts_case_insensitive_directives() {
    let mut store = HstsStore::new();
    store.add_from_header("example.com", "Max-Age=3600; INCLUDESUBDOMAINS");
    assert_eq!(store.should_upgrade("sub.example.com", Scheme::Http), Scheme::Https);
}
