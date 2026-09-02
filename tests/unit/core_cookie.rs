//! Unit tests for Cookie handling.

use ut_core::cookie::{CookieJar, Cookie};
use ut_core::types::Scheme;
use std::io::Cursor;

// ============================================================================
// Cookie Parsing Tests
// ============================================================================

#[test]
fn test_parse_simple_cookie() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("session=abc123", "example.com", "/");

    assert_eq!(jar.len(), 1);
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "session");
    assert_eq!(cookies[0].value, "abc123");
}

#[test]
fn test_parse_cookie_with_path() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Path=/app", "example.com", "/");

    let cookies = jar.match_request("example.com", "/app", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].path, "/app");
}

#[test]
fn test_parse_cookie_with_domain() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Domain=.example.com", "www.example.com", "/");

    let cookies = jar.match_request("www.example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].domain, "example.com");
}

#[test]
fn test_parse_cookie_secure() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Secure", "example.com", "/");

    // Should not match for HTTP
    let cookies_http = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies_http.len(), 0);

    // Should match for HTTPS
    let cookies_https = jar.match_request("example.com", "/", Scheme::Https);
    assert_eq!(cookies_https.len(), 1);
    assert!(cookies_https[0].secure);
}

#[test]
fn test_parse_cookie_httponly() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; HttpOnly", "example.com", "/");

    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].httponly);
}
