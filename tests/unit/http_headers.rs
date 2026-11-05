//! Unit tests for HTTP header parsing and formatting.
//!
//! Tests cover header line parsing, status line parsing, and header formatting.

use ut_http::headers::{
    parse_header_line, parse_status_line, format_header_line,
    CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING, LOCATION,
    WWW_AUTHENTICATE, AUTHORIZATION, HOST, USER_AGENT, CONNECTION,
    ACCEPT, ACCEPT_ENCODING, RANGE, IF_MODIFIED_SINCE, ETAG,
    SET_COOKIE, COOKIE, CONTENT_DISPOSITION, LAST_MODIFIED,
    ACCEPT_RANGES, CONTENT_ENCODING, CACHE_CONTROL, EXPIRES,
    DATE, SERVER, RETRY_AFTER, CONTENT_RANGE, VARY,
    STRICT_TRANSPORT_SECURITY, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
    REFERER, KEEP_ALIVE,
};

// =============================================================================
// Header Line Parsing Tests
// =============================================================================

#[test]
fn test_parse_header_line_simple() {
    let (key, value) = parse_header_line("Content-Type: text/html\r\n").unwrap();
    assert_eq!(key, "Content-Type");
    assert_eq!(value, "text/html");
}

#[test]
fn test_parse_header_line_no_crlf() {
    let (key, value) = parse_header_line("Host: example.com").unwrap();
    assert_eq!(key, "Host");
    assert_eq!(value, "example.com");
}

#[test]
fn test_parse_header_line_with_spaces() {
    let (key, value) = parse_header_line("Content-Length:  12345  \r\n").unwrap();
    assert_eq!(key, "Content-Length");
    assert_eq!(value, "12345");
}

#[test]
fn test_parse_header_line_empty_value() {
    let (key, value) = parse_header_line("X-Empty:\r\n").unwrap();
    assert_eq!(key, "X-Empty");
    assert_eq!(value, "");
}

#[test]
fn test_parse_header_line_no_colon() {
    assert!(parse_header_line("No colon here").is_none());
}

#[test]
fn test_parse_header_line_colon_in_value() {
    let (key, value) = parse_header_line("X-Time: 12:30:45\r\n").unwrap();
    assert_eq!(key, "X-Time");
    assert_eq!(value, "12:30:45");
}
