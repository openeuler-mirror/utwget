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
