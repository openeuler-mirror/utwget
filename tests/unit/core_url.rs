//! Unit tests for URL parsing and manipulation.

use ut_core::url::{ParsedUrl, encode_iri, decode_iri};
use ut_core::types::Scheme;

// ============================================================================
// URL Parsing Tests
// ============================================================================

#[test]
fn test_parse_http_url() {
    let url = ParsedUrl::parse("http://example.com/path").unwrap();
    assert_eq!(url.scheme, Scheme::Http);
    assert_eq!(url.host, "example.com");
    assert_eq!(url.port, 80);
    assert_eq!(url.path, "/path");
}

#[test]
fn test_parse_https_url() {
    let url = ParsedUrl::parse("https://example.com/path").unwrap();
    assert_eq!(url.scheme, Scheme::Https);
    assert_eq!(url.host, "example.com");
    assert_eq!(url.port, 443);
    assert_eq!(url.path, "/path");
}
