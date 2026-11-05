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

#[test]
fn test_parse_header_line_multiple_colons() {
    let (key, value) = parse_header_line("X-URL: http://example.com:8080/path\r\n").unwrap();
    assert_eq!(key, "X-URL");
    assert_eq!(value, "http://example.com:8080/path");
}

#[test]
fn test_parse_header_line_quoted_value() {
    let (key, value) = parse_header_line(r#"Content-Disposition: attachment; filename="test.txt""#).unwrap();
    assert_eq!(key, "Content-Disposition");
    assert_eq!(value, r#"attachment; filename="test.txt""#);
}

#[test]
fn test_parse_header_line_utf8() {
    let (key, value) = parse_header_line("X-Custom: 你好世界\r\n").unwrap();
    assert_eq!(key, "X-Custom");
    assert_eq!(value, "你好世界");
}

#[test]
fn test_parse_header_line_only_lf() {
    let (key, value) = parse_header_line("Host: example.com\n").unwrap();
    assert_eq!(key, "Host");
    assert_eq!(value, "example.com");
}

#[test]
fn test_parse_header_line_only_cr() {
    let (key, value) = parse_header_line("Host: example.com\r").unwrap();
    assert_eq!(key, "Host");
    assert_eq!(value, "example.com");
}

// =============================================================================
// Status Line Parsing Tests
// =============================================================================

#[test]
fn test_parse_status_line_200_ok() {
    let (version, code, reason) = parse_status_line("HTTP/1.1 200 OK\r\n").unwrap();
    assert_eq!(version, "HTTP/1.1");
    assert_eq!(code, 200);
    assert_eq!(reason, "OK");
}

#[test]
fn test_parse_status_line_404_not_found() {
    let (version, code, reason) = parse_status_line("HTTP/1.0 404 Not Found").unwrap();
    assert_eq!(version, "HTTP/1.0");
    assert_eq!(code, 404);
    assert_eq!(reason, "Not Found");
}
