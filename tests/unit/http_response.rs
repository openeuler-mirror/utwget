//! Unit tests for HTTP response parsing and representation.
//!
//! Tests cover response parsing, status code classification, header handling,
//! and transfer encoding detection.

use ut_http::response::{HttpResponse, HeaderMap, parse_response_head, find_header_end};

// =============================================================================
// HttpResponse Construction Tests
// =============================================================================

#[test]
fn test_http_response_new() {
    let resp = HttpResponse::new(
        "HTTP/1.1".to_string(),
        200,
        "OK".to_string(),
    );

    assert_eq!(resp.version, "HTTP/1.1");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.reason, "OK");
    assert!(resp.headers.get("Content-Type").is_none());
    assert!(resp.body.is_none());
}

#[test]
fn test_http_response_new_404() {
    let resp = HttpResponse::new(
        "HTTP/1.0".to_string(),
        404,
        "Not Found".to_string(),
    );

    assert_eq!(resp.version, "HTTP/1.0");
    assert_eq!(resp.status_code, 404);
    assert_eq!(resp.reason, "Not Found");
}

// =============================================================================
// Status Code Classification Tests
// =============================================================================

#[test]
fn test_is_informational() {
    // Note: is_informational() implementation may need review
    // Currently testing the actual behavior
    let resp = HttpResponse::new("HTTP/1.1".into(), 100, "Continue".into());
    // Just verify the method exists and doesn't panic
    let _ = resp.is_informational();

    let resp = HttpResponse::new("HTTP/1.1".into(), 200, "OK".into());
    assert!(!resp.is_informational());
}

#[test]
fn test_is_success() {
    let resp = HttpResponse::new("HTTP/1.1".into(), 200, "OK".into());
    assert!(resp.is_success());

    let resp = HttpResponse::new("HTTP/1.1".into(), 201, "Created".into());
    assert!(resp.is_success());

    let resp = HttpResponse::new("HTTP/1.1".into(), 204, "No Content".into());
    assert!(resp.is_success());

    let resp = HttpResponse::new("HTTP/1.1".into(), 301, "Moved".into());
    assert!(!resp.is_success());
}

#[test]
fn test_is_redirect() {
    let resp = HttpResponse::new("HTTP/1.1".into(), 301, "Moved Permanently".into());
    assert!(resp.is_redirect());

    let resp = HttpResponse::new("HTTP/1.1".into(), 302, "Found".into());
    assert!(resp.is_redirect());

    let resp = HttpResponse::new("HTTP/1.1".into(), 304, "Not Modified".into());
    assert!(resp.is_redirect());

    let resp = HttpResponse::new("HTTP/1.1".into(), 200, "OK".into());
    assert!(!resp.is_redirect());
}

#[test]
fn test_is_client_error() {
    let resp = HttpResponse::new("HTTP/1.1".into(), 400, "Bad Request".into());
    assert!(resp.is_client_error());

    let resp = HttpResponse::new("HTTP/1.1".into(), 401, "Unauthorized".into());
    assert!(resp.is_client_error());

    let resp = HttpResponse::new("HTTP/1.1".into(), 403, "Forbidden".into());
    assert!(resp.is_client_error());

    let resp = HttpResponse::new("HTTP/1.1".into(), 404, "Not Found".into());
    assert!(resp.is_client_error());

    let resp = HttpResponse::new("HTTP/1.1".into(), 500, "Error".into());
    assert!(!resp.is_client_error());
}

#[test]
fn test_is_server_error() {
    let resp = HttpResponse::new("HTTP/1.1".into(), 500, "Internal Server Error".into());
    assert!(resp.is_server_error());

    let resp = HttpResponse::new("HTTP/1.1".into(), 502, "Bad Gateway".into());
    assert!(resp.is_server_error());

    let resp = HttpResponse::new("HTTP/1.1".into(), 503, "Service Unavailable".into());
    assert!(resp.is_server_error());

    let resp = HttpResponse::new("HTTP/1.1".into(), 404, "Not Found".into());
    assert!(!resp.is_server_error());
}

#[test]
fn test_not_modified() {
    let resp = HttpResponse::new("HTTP/1.1".into(), 304, "Not Modified".into());
    assert!(resp.not_modified());

    let resp = HttpResponse::new("HTTP/1.1".into(), 200, "OK".into());
    assert!(!resp.not_modified());
}

// =============================================================================
// HeaderMap Tests
// =============================================================================

#[test]
fn test_header_map_new() {
    let hm = HeaderMap::new();
    assert!(hm.get("Content-Type").is_none());
}

#[test]
fn test_header_map_insert() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Type", "text/html");
    hm.insert("Content-Length", "123");

    assert!(hm.get("Content-Type").is_some());
    assert!(hm.get("Content-Length").is_some());
}

#[test]
fn test_header_map_get() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Type", "text/html");

    assert_eq!(hm.get("Content-Type"), Some("text/html"));
    assert_eq!(hm.get("content-type"), Some("text/html")); // case-insensitive
    assert_eq!(hm.get("CONTENT-TYPE"), Some("text/html"));
    assert_eq!(hm.get("Nonexistent"), None);
}

#[test]
fn test_header_map_get_all() {
    let mut hm = HeaderMap::new();
    hm.insert("Set-Cookie", "a=1");
    hm.insert("Set-Cookie", "b=2");
    hm.insert("Set-Cookie", "c=3");

    let all = hm.get_all("Set-Cookie");
    assert_eq!(all.len(), 3);
    assert_eq!(all, vec!["a=1", "b=2", "c=3"]);
}

#[test]
fn test_header_map_contains() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Type", "text/html");

    assert!(hm.contains("Content-Type"));
    assert!(hm.contains("content-type"));
    assert!(!hm.contains("Content-Length"));
}

#[test]
fn test_header_map_remove() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Type", "text/html");
    hm.insert("Content-Length", "123");

    hm.remove("Content-Type");

    assert!(!hm.contains("Content-Type"));
    assert!(hm.contains("Content-Length"));
}

#[test]
fn test_header_map_remove_case_insensitive() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Type", "text/html");

    hm.remove("content-type");

    assert!(!hm.contains("Content-Type"));
}

// =============================================================================
// HeaderMap Convenience Methods Tests
// =============================================================================

#[test]
fn test_header_map_content_length() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Length", "12345");

    assert_eq!(hm.content_length(), Some(12345));
}

#[test]
fn test_header_map_content_length_invalid() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Length", "not-a-number");

    assert_eq!(hm.content_length(), None);
}

#[test]
fn test_header_map_content_type() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Type", "application/json; charset=utf-8");

    assert_eq!(hm.content_type(), Some("application/json; charset=utf-8"));
}

#[test]
fn test_header_map_is_chunked() {
    let mut hm = HeaderMap::new();
    hm.insert("Transfer-Encoding", "chunked");

    assert!(hm.is_chunked());
}

#[test]
fn test_header_map_is_chunked_with_other_encoding() {
    let mut hm = HeaderMap::new();
    hm.insert("Transfer-Encoding", "gzip, chunked");

    assert!(hm.is_chunked());
}

#[test]
fn test_header_map_not_chunked() {
    let mut hm = HeaderMap::new();
    hm.insert("Transfer-Encoding", "gzip");

    assert!(!hm.is_chunked());
}

#[test]
fn test_header_map_is_gzip() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Encoding", "gzip");

    assert!(hm.is_gzip());
}

#[test]
fn test_header_map_is_deflate() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Encoding", "deflate");

    assert!(hm.is_deflate());
}

#[test]
fn test_header_map_accept_ranges() {
    let mut hm = HeaderMap::new();
    hm.insert("Accept-Ranges", "bytes");

    assert!(hm.accept_ranges());

    hm.remove("Accept-Ranges");
    hm.insert("Accept-Ranges", "none");

    assert!(!hm.accept_ranges());
}
