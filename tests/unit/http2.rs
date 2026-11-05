//! Tests for HTTP/2 support.

#[cfg(test)]
mod tests {
    use ut_http::request::{HttpMethod, HttpRequest, HttpVersion};

    #[test]
    fn test_http2_version_display() {
        assert_eq!(HttpVersion::Http2.to_string(), "HTTP/2");
    }

    #[test]
    fn test_http2_supports_keep_alive() {
        assert!(HttpVersion::Http2.supports_keep_alive());
    }

    #[test]
    fn test_http2_is_http2() {
        assert!(HttpVersion::Http2.is_http2());
        assert!(!HttpVersion::Http11.is_http2());
        assert!(!HttpVersion::Http10.is_http2());
    }

    #[test]
    fn test_http2_request_build() {
        let req = HttpRequest::new(HttpMethod::Get, "/test".to_string(), "example.com".to_string());
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.path, "/test");
        assert_eq!(req.host, "example.com");
    }

    #[test]
    fn test_http2_version_supports_keep_alive() {
        assert!(HttpVersion::Http2.supports_keep_alive());
        assert!(HttpVersion::Http11.supports_keep_alive());
        assert!(!HttpVersion::Http10.supports_keep_alive());
    }

    #[test]
    fn test_http2_version_supports_chunked() {
        assert!(!HttpVersion::Http2.supports_chunked());
        assert!(HttpVersion::Http11.supports_chunked());
        assert!(!HttpVersion::Http10.supports_chunked());
    }

    #[test]
    fn test_http_request_method_variants() {
        let get_req = HttpRequest::new(HttpMethod::Get, "/".to_string(), "example.com".to_string());
        assert_eq!(get_req.method, HttpMethod::Get);

        let post_req = HttpRequest::new(HttpMethod::Post, "/submit".to_string(), "example.com".to_string());
        assert_eq!(post_req.method, HttpMethod::Post);

        let head_req = HttpRequest::new(HttpMethod::Head, "/".to_string(), "example.com".to_string());
        assert_eq!(head_req.method, HttpMethod::Head);
    }

    #[test]
    fn test_http_request_headers() {
        let mut req = HttpRequest::new(HttpMethod::Get, "/".to_string(), "example.com".to_string());
        req.headers.push(("Accept".to_string(), "application/json".to_string()));
        req.headers.push(("User-Agent".to_string(), "utwget/0.1.0".to_string()));
        
        assert!(req.headers.iter().any(|(k, v)| k == "Accept" && v == "application/json"));
        assert!(req.headers.iter().any(|(k, v)| k == "User-Agent" && v == "utwget/0.1.0"));
    }
}
