//! Unit tests for HTTP request building and serialization.
//!
//! Tests cover request construction, header manipulation, and serialization.

use ut_http::request::{HttpRequest, HttpVersion, HttpMethod};
use ut_http::headers::{HOST, USER_AGENT, ACCEPT, CONNECTION, CONTENT_LENGTH, RANGE, IF_MODIFIED_SINCE};

// =============================================================================
// HttpVersion Tests
// =============================================================================

#[test]
fn test_http_version_display() {
    assert_eq!(HttpVersion::Http10.to_string(), "HTTP/1.0");
    assert_eq!(HttpVersion::Http11.to_string(), "HTTP/1.1");
}

#[test]
fn test_http_version_default() {
    assert_eq!(HttpVersion::default(), HttpVersion::Http11);
}

#[test]
fn test_http_version_supports_keep_alive() {
    assert!(!HttpVersion::Http10.supports_keep_alive());
    assert!(HttpVersion::Http11.supports_keep_alive());
}

#[test]
fn test_http_version_supports_chunked() {
    assert!(!HttpVersion::Http10.supports_chunked());
    assert!(HttpVersion::Http11.supports_chunked());
}

// =============================================================================
// HttpMethod Tests
// =============================================================================

#[test]
fn test_http_method_display() {
    assert_eq!(format!("{}", HttpMethod::Get), "GET");
    assert_eq!(format!("{}", HttpMethod::Post), "POST");
    assert_eq!(format!("{}", HttpMethod::Head), "HEAD");
    assert_eq!(format!("{}", HttpMethod::Put), "PUT");
    assert_eq!(format!("{}", HttpMethod::Delete), "DELETE");
    assert_eq!(format!("{}", HttpMethod::Options), "OPTIONS");
    assert_eq!(format!("{}", HttpMethod::Patch), "PATCH");
}

// =============================================================================
// HttpRequest Construction Tests
// =============================================================================

#[test]
fn test_http_request_new_get() {
    let req = HttpRequest::new(
        HttpMethod::Get,
        "/path".to_string(),
        "example.com".to_string(),
    );

    assert_eq!(req.method, HttpMethod::Get);
    assert_eq!(req.path, "/path");
    assert_eq!(req.host, "example.com");
    assert_eq!(req.version, HttpVersion::Http11);
    assert!(req.headers.is_empty());
    assert!(req.body.is_none());
}
