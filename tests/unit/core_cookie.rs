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

#[test]
fn test_parse_cookie_max_age() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Max-Age=3600", "example.com", "/");

    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].expires.is_some());
    assert!(cookies[0].persistent);
}

#[test]
fn test_parse_cookie_expires() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie(
        "id=123; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
        "example.com",
        "/",
    );

    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    // Note: This cookie may be expired, so we just check parsing worked
    assert_eq!(jar.len(), 1);
}

#[test]
fn test_parse_cookie_multiple_attributes() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie(
        "session=xyz; Domain=.example.com; Path=/app; Secure; HttpOnly; Max-Age=86400",
        "www.example.com",
        "/app",
    );

    let cookies = jar.match_request("www.example.com", "/app/page", Scheme::Https);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "session");
    assert_eq!(cookies[0].domain, "example.com");
    assert_eq!(cookies[0].path, "/app");
    assert!(cookies[0].secure);
    assert!(cookies[0].httponly);
}

// ============================================================================
// Cookie Matching Tests
// ============================================================================

#[test]
fn test_match_exact_domain() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123", "example.com", "/");

    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
}

#[test]
fn test_match_subdomain() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Domain=.example.com", "example.com", "/");

    // Should match for subdomain
    let cookies = jar.match_request("www.example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);

    // Should also match for the domain itself
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
}

#[test]
fn test_match_path() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Path=/app", "example.com", "/");

    // Should match for exact path
    let cookies = jar.match_request("example.com", "/app", Scheme::Http);
    assert_eq!(cookies.len(), 1);

    // Should match for subpath
    let cookies = jar.match_request("example.com", "/app/page", Scheme::Http);
    assert_eq!(cookies.len(), 1);

    // Should not match for different path
    let cookies = jar.match_request("example.com", "/other", Scheme::Http);
    assert_eq!(cookies.len(), 0);
}

#[test]
fn test_match_root_path() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Path=/", "example.com", "/");

    // Root path should match all paths
    let cookies = jar.match_request("example.com", "/any/path", Scheme::Http);
    assert_eq!(cookies.len(), 1);
}

#[test]
fn test_match_multiple_cookies() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("a=1; Path=/", "example.com", "/");
    jar.parse_set_cookie("b=2; Path=/app", "example.com", "/app");
    jar.parse_set_cookie("c=3; Path=/app/admin", "example.com", "/app/admin");

    let cookies = jar.match_request("example.com", "/app/admin/page", Scheme::Http);
    assert_eq!(cookies.len(), 3);
}

#[test]
fn test_match_path_ordering() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("a=1; Path=/", "example.com", "/");
    jar.parse_set_cookie("b=2; Path=/app", "example.com", "/app");

    let cookies = jar.match_request("example.com", "/app/page", Scheme::Http);
    // Longer path should come first
    assert_eq!(cookies[0].path, "/app");
    assert_eq!(cookies[1].path, "/");
}
