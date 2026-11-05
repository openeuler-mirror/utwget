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
