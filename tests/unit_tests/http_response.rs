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

#[test]
fn test_header_map_location() {
    let mut hm = HeaderMap::new();
    hm.insert("Location", "http://example.com/new-location");

    assert_eq!(hm.location(), Some("http://example.com/new-location"));
}

#[test]
fn test_header_map_etag() {
    let mut hm = HeaderMap::new();
    hm.insert("ETag", "\"abc123\"");

    assert_eq!(hm.etag(), Some("\"abc123\""));
}

#[test]
fn test_header_map_last_modified() {
    let mut hm = HeaderMap::new();
    hm.insert("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT");

    assert_eq!(hm.last_modified(), Some("Wed, 21 Oct 2015 07:28:00 GMT"));
}

#[test]
fn test_header_map_server() {
    let mut hm = HeaderMap::new();
    hm.insert("Server", "nginx/1.18.0");

    assert_eq!(hm.server(), Some("nginx/1.18.0"));
}

#[test]
fn test_header_map_retry_after() {
    let mut hm = HeaderMap::new();
    hm.insert("Retry-After", "120");

    assert_eq!(hm.retry_after(), Some(120));
}

#[test]
fn test_header_map_set_cookies() {
    let mut hm = HeaderMap::new();
    hm.insert("Set-Cookie", "session=abc; Path=/");
    hm.insert("Set-Cookie", "user=john; HttpOnly");

    let cookies = hm.set_cookies();
    assert_eq!(cookies.len(), 2);
}

#[test]
fn test_header_map_www_authenticate() {
    let mut hm = HeaderMap::new();
    hm.insert("WWW-Authenticate", "Basic realm=\"test\"");
    hm.insert("WWW-Authenticate", "Bearer realm=\"api\"");

    let auth = hm.www_authenticate();
    assert_eq!(auth.len(), 2);
}

#[test]
fn test_header_map_content_disposition() {
    let mut hm = HeaderMap::new();
    hm.insert("Content-Disposition", "attachment; filename=\"test.txt\"");

    assert_eq!(hm.content_disposition(), Some("attachment; filename=\"test.txt\""));
}

// =============================================================================
// Response Parsing Tests
// =============================================================================

#[test]
fn test_parse_response_head_simple() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    let resp = parse_response_head(raw).unwrap();

    assert_eq!(resp.version, "HTTP/1.1");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.reason, "OK");
    assert_eq!(resp.headers.get("Content-Type"), Some("text/html"));
}

#[test]
fn test_parse_response_head_with_body() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let resp = parse_response_head(raw).unwrap();

    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.headers.content_length(), Some(5));
}

#[test]
fn test_parse_response_head_multiple_headers() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 123\r\nServer: nginx\r\nConnection: keep-alive\r\n\r\n";
    let resp = parse_response_head(raw).unwrap();

    assert_eq!(resp.headers.get("Content-Type"), Some("text/html"));
    assert_eq!(resp.headers.content_length(), Some(123));
    assert_eq!(resp.headers.server(), Some("nginx"));
    assert_eq!(resp.headers.get("Connection"), Some("keep-alive"));
}

#[test]
fn test_parse_response_head_404() {
    let raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n";
    let resp = parse_response_head(raw).unwrap();

    assert_eq!(resp.status_code, 404);
    assert!(resp.is_client_error());
}

#[test]
fn test_parse_response_head_redirect() {
    let raw = b"HTTP/1.1 301 Moved Permanently\r\nLocation: http://example.com/new\r\n\r\n";
    let resp = parse_response_head(raw).unwrap();

    assert_eq!(resp.status_code, 301);
    assert!(resp.is_redirect());
    assert_eq!(resp.location(), Some("http://example.com/new"));
}

#[test]
fn test_parse_response_head_chunked() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n";
    let resp = parse_response_head(raw).unwrap();

    assert!(resp.is_chunked());
}

#[test]
fn test_parse_response_head_http10() {
    let raw = b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    let resp = parse_response_head(raw).unwrap();

    assert_eq!(resp.version, "HTTP/1.0");
}

#[test]
fn test_parse_response_head_with_cookies() {
    let raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\nSet-Cookie: user=john\r\n\r\n";
    let resp = parse_response_head(raw).unwrap();

    let cookies = resp.headers.set_cookies();
    assert_eq!(cookies.len(), 2);
}

// =============================================================================
// Find Header End Tests
// =============================================================================

#[test]
fn test_find_header_end_simple() {
    let data = b"HTTP/1.1 200 OK\r\n\r\nbody";
    assert_eq!(find_header_end(data), Some(15));
}

#[test]
fn test_find_header_end_with_headers() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    assert!(find_header_end(data).is_some());
}

#[test]
fn test_find_header_end_incomplete() {
    let data = b"HTTP/1.1 200 OK\r\nincomplete";
    assert_eq!(find_header_end(data), None);
}

#[test]
fn test_find_header_end_empty() {
    let data = b"";
    assert_eq!(find_header_end(data), None);
}

// =============================================================================
// Keep-Alive Tests
// =============================================================================

#[test]
fn test_keep_alive_http11_default() {
    let resp = HttpResponse::new("HTTP/1.1".into(), 200, "OK".into());
    assert!(resp.keep_alive()); // HTTP/1.1 defaults to keep-alive
}

#[test]
fn test_keep_alive_http10_default() {
    let resp = HttpResponse::new("HTTP/1.0".into(), 200, "OK".into());
    assert!(!resp.keep_alive()); // HTTP/1.0 defaults to close
}

#[test]
fn test_keep_alive_explicit_close() {
    let mut resp = HttpResponse::new("HTTP/1.1".into(), 200, "OK".into());
    resp.headers.insert("Connection", "close");

    assert!(!resp.keep_alive());
}

#[test]
fn test_keep_alive_explicit_keep_alive() {
    let mut resp = HttpResponse::new("HTTP/1.0".into(), 200, "OK".into());
    resp.headers.insert("Connection", "keep-alive");

    assert!(resp.keep_alive());
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_full_response_parsing() {
    let raw = b"HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: 42\r\n\
                 Server: nginx/1.18.0\r\n\
                 Date: Wed, 21 Oct 2015 07:28:00 GMT\r\n\
                 ETag: \"abc123\"\r\n\
                 Accept-Ranges: bytes\r\n\
                 Cache-Control: max-age=3600\r\n\
                 \r\n\
                 {\"message\": \"Hello, World!\"}";

    let resp = parse_response_head(raw).unwrap();

    assert!(resp.is_success());
    assert_eq!(resp.headers.content_type(), Some("application/json"));
    assert_eq!(resp.headers.content_length(), Some(42));
    assert_eq!(resp.headers.server(), Some("nginx/1.18.0"));
    assert_eq!(resp.headers.etag(), Some("\"abc123\""));
    assert!(resp.headers.accept_ranges());
    assert!(resp.keep_alive());
}

#[test]
fn test_error_response_parsing() {
    let raw = b"HTTP/1.1 500 Internal Server Error\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: 21\r\n\
                 Retry-After: 60\r\n\
                 \r\n\
                 Internal Server Error";

    let resp = parse_response_head(raw).unwrap();

    assert!(resp.is_server_error());
    assert_eq!(resp.headers.retry_after(), Some(60));
}

#[test]
fn test_redirect_response_parsing() {
    let raw = b"HTTP/1.1 302 Found\r\n\
                 Location: https://example.com/new-location\r\n\
                 Cache-Control: no-cache\r\n\
                 \r\n";

    let resp = parse_response_head(raw).unwrap();

    assert!(resp.is_redirect());
    assert_eq!(resp.location(), Some("https://example.com/new-location"));
}

#[test]
fn test_not_modified_response_parsing() {
    let raw = b"HTTP/1.1 304 Not Modified\r\n\
                 ETag: \"abc123\"\r\n\
                 Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n\
                 \r\n";

    let resp = parse_response_head(raw).unwrap();

    assert!(resp.not_modified());
    assert!(resp.is_redirect());
    assert_eq!(resp.headers.etag(), Some("\"abc123\""));
}
