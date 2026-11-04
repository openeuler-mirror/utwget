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

#[test]
fn test_parse_ftp_url() {
    let url = ParsedUrl::parse("ftp://ftp.example.com/files/file.txt").unwrap();
    assert_eq!(url.scheme, Scheme::Ftp);
    assert_eq!(url.host, "ftp.example.com");
    assert_eq!(url.port, 21);
    assert_eq!(url.path, "/files/file.txt");
}

#[test]
fn test_parse_ftps_url() {
    let url = ParsedUrl::parse("ftps://secure.example.com/files/file.txt").unwrap();
    assert_eq!(url.scheme, Scheme::Ftps);
    assert_eq!(url.host, "secure.example.com");
    assert_eq!(url.port, 990);
    assert_eq!(url.path, "/files/file.txt");
}

#[test]
fn test_parse_url_with_port() {
    let url = ParsedUrl::parse("http://example.com:8080/path").unwrap();
    assert_eq!(url.scheme, Scheme::Http);
    assert_eq!(url.host, "example.com");
    assert_eq!(url.port, 8080);
}

#[test]
fn test_parse_url_with_query() {
    let url = ParsedUrl::parse("http://example.com/path?key=value&foo=bar").unwrap();
    assert_eq!(url.path, "/path");
    assert_eq!(url.query.as_deref(), Some("key=value&foo=bar"));
}

#[test]
fn test_parse_url_with_fragment() {
    let url = ParsedUrl::parse("http://example.com/path#section").unwrap();
    assert_eq!(url.path, "/path");
    assert_eq!(url.fragment.as_deref(), Some("section"));
}

#[test]
fn test_parse_url_with_query_and_fragment() {
    let url = ParsedUrl::parse("http://example.com/path?q=1#frag").unwrap();
    assert_eq!(url.path, "/path");
    assert_eq!(url.query.as_deref(), Some("q=1"));
    assert_eq!(url.fragment.as_deref(), Some("frag"));
}
