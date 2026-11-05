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

#[test]
fn test_parse_status_line_500_internal_error() {
    let (version, code, reason) = parse_status_line("HTTP/1.1 500 Internal Server Error\r\n").unwrap();
    assert_eq!(version, "HTTP/1.1");
    assert_eq!(code, 500);
    assert_eq!(reason, "Internal Server Error");
}

#[test]
fn test_parse_status_line_301_moved() {
    let (version, code, reason) = parse_status_line("HTTP/1.1 301 Moved Permanently\r\n").unwrap();
    assert_eq!(version, "HTTP/1.1");
    assert_eq!(code, 301);
    assert_eq!(reason, "Moved Permanently");
}

#[test]
fn test_parse_status_line_302_found() {
    let (version, code, reason) = parse_status_line("HTTP/1.1 302 Found\r\n").unwrap();
    assert_eq!(version, "HTTP/1.1");
    assert_eq!(code, 302);
    assert_eq!(reason, "Found");
}

#[test]
fn test_parse_status_line_204_no_content() {
    let (version, code, reason) = parse_status_line("HTTP/1.1 204 No Content\r\n").unwrap();
    assert_eq!(version, "HTTP/1.1");
    assert_eq!(code, 204);
    assert_eq!(reason, "No Content");
}

#[test]
fn test_parse_status_line_100_continue() {
    let (version, code, reason) = parse_status_line("HTTP/1.1 100 Continue\r\n").unwrap();
    assert_eq!(version, "HTTP/1.1");
    assert_eq!(code, 100);
    assert_eq!(reason, "Continue");
}

#[test]
fn test_parse_status_line_invalid_no_space() {
    assert!(parse_status_line("HTTP/1.1").is_none());
}

#[test]
fn test_parse_status_line_invalid_no_code() {
    assert!(parse_status_line("HTTP/1.1 OK").is_none());
}

#[test]
fn test_parse_status_line_invalid_code() {
    assert!(parse_status_line("HTTP/1.1 ABC OK").is_none());
}

#[test]
fn test_parse_status_line_http2() {
    let (version, code, reason) = parse_status_line("HTTP/2.0 200 OK\r\n").unwrap();
    assert_eq!(version, "HTTP/2.0");
    assert_eq!(code, 200);
    assert_eq!(reason, "OK");
}

// =============================================================================
// Header Formatting Tests
// =============================================================================

#[test]
fn test_format_header_line_simple() {
    let line = format_header_line("Host", "example.com");
    assert_eq!(line, "Host: example.com\r\n");
}

#[test]
fn test_format_header_line_with_spaces() {
    let line = format_header_line("Content-Type", "text/html; charset=utf-8");
    assert_eq!(line, "Content-Type: text/html; charset=utf-8\r\n");
}

#[test]
fn test_format_header_line_empty_value() {
    let line = format_header_line("X-Empty", "");
    assert_eq!(line, "X-Empty: \r\n");
}

#[test]
fn test_format_header_line_utf8() {
    let line = format_header_line("X-Custom", "测试");
    assert_eq!(line, "X-Custom: 测试\r\n");
}

// =============================================================================
// Header Constants Tests
// =============================================================================

#[test]
fn test_header_constants() {
    // Verify header constants have expected values
    assert_eq!(CONTENT_LENGTH, "Content-Length");
    assert_eq!(CONTENT_TYPE, "Content-Type");
    assert_eq!(TRANSFER_ENCODING, "Transfer-Encoding");
    assert_eq!(LOCATION, "Location");
    assert_eq!(WWW_AUTHENTICATE, "WWW-Authenticate");
    assert_eq!(AUTHORIZATION, "Authorization");
    assert_eq!(HOST, "Host");
    assert_eq!(USER_AGENT, "User-Agent");
    assert_eq!(CONNECTION, "Connection");
    assert_eq!(ACCEPT, "Accept");
    assert_eq!(ACCEPT_ENCODING, "Accept-Encoding");
    assert_eq!(RANGE, "Range");
    assert_eq!(IF_MODIFIED_SINCE, "If-Modified-Since");
    assert_eq!(ETAG, "ETag");
    assert_eq!(SET_COOKIE, "Set-Cookie");
    assert_eq!(COOKIE, "Cookie");
    assert_eq!(CONTENT_DISPOSITION, "Content-Disposition");
    assert_eq!(LAST_MODIFIED, "Last-Modified");
    assert_eq!(ACCEPT_RANGES, "Accept-Ranges");
    assert_eq!(CONTENT_ENCODING, "Content-Encoding");
    assert_eq!(CACHE_CONTROL, "Cache-Control");
    assert_eq!(EXPIRES, "Expires");
    assert_eq!(DATE, "Date");
    assert_eq!(SERVER, "Server");
    assert_eq!(RETRY_AFTER, "Retry-After");
    assert_eq!(CONTENT_RANGE, "Content-Range");
    assert_eq!(VARY, "Vary");
    assert_eq!(STRICT_TRANSPORT_SECURITY, "Strict-Transport-Security");
    assert_eq!(PROXY_AUTHENTICATE, "Proxy-Authenticate");
    assert_eq!(PROXY_AUTHORIZATION, "Proxy-Authorization");
    assert_eq!(REFERER, "Referer");
    assert_eq!(KEEP_ALIVE, "Keep-Alive");
}
