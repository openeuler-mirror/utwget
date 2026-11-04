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

#[test]
fn test_parse_url_with_user_info() {
    let url = ParsedUrl::parse("https://user:pass@example.com/path").unwrap();
    assert_eq!(url.user.as_deref(), Some("user"));
    assert_eq!(url.password.as_deref(), Some("pass"));
    assert_eq!(url.host, "example.com");
}

#[test]
fn test_parse_url_with_user_only() {
    let url = ParsedUrl::parse("ftp://user@ftp.example.com/").unwrap();
    assert_eq!(url.user.as_deref(), Some("user"));
    assert_eq!(url.password, None);
}

#[test]
fn test_parse_url_root() {
    let url = ParsedUrl::parse("http://example.com/").unwrap();
    assert_eq!(url.path, "/");
    assert_eq!(url.dir, "/");
    assert_eq!(url.file, "");
}

#[test]
fn test_parse_url_no_path() {
    let url = ParsedUrl::parse("http://example.com").unwrap();
    assert_eq!(url.path, "/");
}

#[test]
fn test_parse_url_deep_path() {
    let url = ParsedUrl::parse("http://example.com/a/b/c/d/file.txt").unwrap();
    assert_eq!(url.path, "/a/b/c/d/file.txt");
    assert_eq!(url.dir, "/a/b/c/d/");
    assert_eq!(url.file, "file.txt");
}

#[test]
fn test_parse_ipv6_url() {
    let url = ParsedUrl::parse("http://[::1]:8080/path").unwrap();
    assert_eq!(url.host, "::1");
    assert_eq!(url.port, 8080);
}

#[test]
fn test_parse_ipv6_url_no_port() {
    let url = ParsedUrl::parse("http://[2001:db8::1]/path").unwrap();
    assert_eq!(url.host, "2001:db8::1");
    assert_eq!(url.port, 80);
}

#[test]
fn test_parse_url_with_params() {
    let url = ParsedUrl::parse("http://example.com/path;params?query").unwrap();
    assert_eq!(url.path, "/path");
    assert_eq!(url.params.as_deref(), Some("params"));
    assert_eq!(url.query.as_deref(), Some("query"));
}

// ============================================================================
// URL Merge Tests
// ============================================================================

#[test]
fn test_merge_relative_path() {
    let base = ParsedUrl::parse("http://example.com/dir/page.html").unwrap();
    let merged = base.merge("other.html").unwrap();
    assert_eq!(merged.path, "/dir/other.html");
    assert_eq!(merged.host, "example.com");
}

#[test]
fn test_merge_absolute_path() {
    let base = ParsedUrl::parse("http://example.com/dir/page.html").unwrap();
    let merged = base.merge("/other/path").unwrap();
    assert_eq!(merged.path, "/other/path");
}
