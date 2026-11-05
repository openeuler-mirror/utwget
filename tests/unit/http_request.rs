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

#[test]
fn test_http_request_new_post() {
    let req = HttpRequest::new(
        HttpMethod::Post,
        "/api/users".to_string(),
        "api.example.com".to_string(),
    );

    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(req.path, "/api/users");
    assert_eq!(req.host, "api.example.com");
}

#[test]
fn test_http_request_new_head() {
    let req = HttpRequest::new(
        HttpMethod::Head,
        "/resource".to_string(),
        "example.com".to_string(),
    );

    assert_eq!(req.method, HttpMethod::Head);
}

#[test]
fn test_http_request_new_with_query() {
    let req = HttpRequest::new(
        HttpMethod::Get,
        "/search?q=rust&lang=en".to_string(),
        "example.com".to_string(),
    );

    assert_eq!(req.path, "/search?q=rust&lang=en");
}

#[test]
fn test_http_request_new_with_port() {
    let req = HttpRequest::new(
        HttpMethod::Get,
        "/".to_string(),
        "example.com:8080".to_string(),
    );

    assert_eq!(req.host, "example.com:8080");
}

// =============================================================================
// Header Manipulation Tests
// =============================================================================

#[test]
fn test_http_request_header_add() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/".to_string(),
        "example.com".to_string(),
    );

    req.header("Host", "example.com");
    req.header("Accept", "*/*");

    assert_eq!(req.headers.len(), 2);
    assert_eq!(req.get_header("Host"), Some("example.com"));
    assert_eq!(req.get_header("Accept"), Some("*/*"));
}

#[test]
fn test_http_request_header_case_insensitive() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/".to_string(),
        "example.com".to_string(),
    );

    req.header("Content-Type", "application/json");

    assert_eq!(req.get_header("content-type"), Some("application/json"));
    assert_eq!(req.get_header("CONTENT-TYPE"), Some("application/json"));
    assert_eq!(req.get_header("Content-Type"), Some("application/json"));
}

#[test]
fn test_http_request_header_duplicate() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/".to_string(),
        "example.com".to_string(),
    );

    // HTTP allows duplicate headers
    req.header("Set-Cookie", "a=1");
    req.header("Set-Cookie", "b=2");

    assert_eq!(req.headers.len(), 2);
    // get_header returns the first one
    assert_eq!(req.get_header("Set-Cookie"), Some("a=1"));
}

#[test]
fn test_http_request_header_remove() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/".to_string(),
        "example.com".to_string(),
    );

    req.header("Host", "example.com");
    req.header("Accept", "*/*");

    req.remove_header("Host");

    assert_eq!(req.headers.len(), 1);
    assert_eq!(req.get_header("Host"), None);
    assert_eq!(req.get_header("Accept"), Some("*/*"));
}

#[test]
fn test_http_request_header_remove_case_insensitive() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/".to_string(),
        "example.com".to_string(),
    );

    req.header("Content-Type", "text/html");
    req.remove_header("content-type");

    assert_eq!(req.get_header("Content-Type"), None);
}

#[test]
fn test_http_request_header_not_found() {
    let req = HttpRequest::new(
        HttpMethod::Get,
        "/".to_string(),
        "example.com".to_string(),
    );

    assert_eq!(req.get_header("Nonexistent"), None);
}

// =============================================================================
// Request Serialization Tests
// =============================================================================

#[test]
fn test_serialize_get_request() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/path".to_string(),
        "example.com".to_string(),
    );
    req.header("Host", "example.com");
    req.header("Accept", "*/*");

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.starts_with("GET /path HTTP/1.1\r\n"));
    assert!(text.contains("Host: example.com\r\n"));
    assert!(text.contains("Accept: */*\r\n"));
    assert!(text.ends_with("\r\n\r\n"));
}

#[test]
fn test_serialize_post_request_with_body() {
    let mut req = HttpRequest::new(
        HttpMethod::Post,
        "/api".to_string(),
        "example.com".to_string(),
    );
    req.header("Host", "example.com");
    req.header("Content-Type", "application/json");
    req.header("Content-Length", "2");
    req.body = Some(b"{}".to_vec());

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.starts_with("POST /api HTTP/1.1\r\n"));
    assert!(text.contains("Content-Type: application/json\r\n"));
    assert!(text.contains("Content-Length: 2\r\n"));
    assert!(text.ends_with("\r\n\r\n{}"));
}

#[test]
fn test_serialize_head_request() {
    let mut req = HttpRequest::new(
        HttpMethod::Head,
        "/resource".to_string(),
        "example.com".to_string(),
    );
    req.header("Host", "example.com");

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.starts_with("HEAD /resource HTTP/1.1\r\n"));
}

#[test]
fn test_serialize_http10_request() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/".to_string(),
        "example.com".to_string(),
    );
    req.version = HttpVersion::Http10;
    req.header("Host", "example.com");

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.starts_with("GET / HTTP/1.0\r\n"));
}

#[test]
fn test_serialize_request_with_query() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/search?q=rust&lang=en".to_string(),
        "example.com".to_string(),
    );
    req.header("Host", "example.com");

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.starts_with("GET /search?q=rust&lang=en HTTP/1.1\r\n"));
}

#[test]
fn test_serialize_request_with_encoded_path() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/path%20with%20spaces".to_string(),
        "example.com".to_string(),
    );
    req.header("Host", "example.com");

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.starts_with("GET /path%20with%20spaces HTTP/1.1\r\n"));
}

#[test]
fn test_serialize_empty_body() {
    let mut req = HttpRequest::new(
        HttpMethod::Post,
        "/api".to_string(),
        "example.com".to_string(),
    );
    req.header("Content-Length", "0");
    req.body = Some(Vec::new());

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.ends_with("\r\n\r\n"));
}

// =============================================================================
// Content-Length Tests
// =============================================================================

#[test]
fn test_content_length_from_header() {
    let mut req = HttpRequest::new(
        HttpMethod::Post,
        "/".to_string(),
        "example.com".to_string(),
    );
    req.header("Content-Length", "12345");

    assert_eq!(req.content_length(), Some(12345));
}

#[test]
fn test_content_length_missing() {
    let req = HttpRequest::new(
        HttpMethod::Get,
        "/".to_string(),
        "example.com".to_string(),
    );

    assert_eq!(req.content_length(), None);
}

#[test]
fn test_content_length_invalid() {
    let mut req = HttpRequest::new(
        HttpMethod::Post,
        "/".to_string(),
        "example.com".to_string(),
    );
    req.header("Content-Length", "not-a-number");

    assert_eq!(req.content_length(), None);
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_full_get_request() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/index.html".to_string(),
        "www.example.com".to_string(),
    );
    req.header(HOST, "www.example.com");
    req.header(USER_AGENT, "utwget/0.1.0");
    req.header(ACCEPT, "*/*");
    req.header(CONNECTION, "keep-alive");

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.contains("GET /index.html HTTP/1.1"));
    assert!(text.contains("Host: www.example.com"));
    assert!(text.contains("User-Agent: utwget/0.1.0"));
    assert!(text.contains("Accept: */*"));
    assert!(text.contains("Connection: keep-alive"));
}

#[test]
fn test_full_post_request() {
    let body = r#"{"name":"test","value":42}"#;
    let mut req = HttpRequest::new(
        HttpMethod::Post,
        "/api/data".to_string(),
        "api.example.com".to_string(),
    );
    req.header(HOST, "api.example.com");
    req.header(USER_AGENT, "utwget/0.1.0");
    req.header("Content-Type", "application/json");
    req.header(CONTENT_LENGTH, body.len().to_string());
    req.body = Some(body.as_bytes().to_vec());

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.contains("POST /api/data HTTP/1.1"));
    assert!(text.contains("Content-Type: application/json"));
    assert!(text.ends_with(body));
}

#[test]
fn test_range_request() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/large-file.bin".to_string(),
        "example.com".to_string(),
    );
    req.header(HOST, "example.com");
    req.header(RANGE, "bytes=1000-1999");

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.contains("Range: bytes=1000-1999"));
}

#[test]
fn test_conditional_request() {
    let mut req = HttpRequest::new(
        HttpMethod::Get,
        "/resource".to_string(),
        "example.com".to_string(),
    );
    req.header(HOST, "example.com");
    req.header(IF_MODIFIED_SINCE, "Wed, 21 Oct 2015 07:28:00 GMT");
    req.header("If-None-Match", "\"abc123\"");

    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.contains("If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT"));
    assert!(text.contains("If-None-Match: \"abc123\""));
}
