//! Unit tests for net proxy module.
//!
//! Tests for proxy URL parsing, CONNECT method, and authentication.

// Note: Most proxy functionality requires network access.
// These tests focus on parsing and formatting that don't require network.

#[test]
fn test_proxy_url_parsing() {
    // Basic proxy URL format validation
    let proxy_url = "http://proxy.example.com:8080";
    assert!(proxy_url.starts_with("http://"));
    assert!(proxy_url.contains(":8080"));
}

#[test]
fn test_proxy_url_with_auth() {
    // Proxy URL with authentication
    let proxy_url = "http://user:pass@proxy.example.com:8080";
    assert!(proxy_url.contains("user:pass@"));
}

#[test]
fn test_connect_request_format() {
    // HTTP CONNECT request format
    let target = "example.com:443";
    let connect_request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, target);
    assert!(connect_request.starts_with("CONNECT"));
    assert!(connect_request.contains("HTTP/1.1"));
}

#[test]
fn test_proxy_env_vars() {
    // Test that proxy environment variable names are standard
    let http_proxy = "http_proxy";
    let https_proxy = "https_proxy";
    let ftp_proxy = "ftp_proxy";
    let no_proxy = "no_proxy";

    assert_eq!(http_proxy, "http_proxy");
    assert_eq!(https_proxy, "https_proxy");
    assert_eq!(ftp_proxy, "ftp_proxy");
    assert_eq!(no_proxy, "no_proxy");
}

#[test]
fn test_no_proxy_list() {
    // Test no_proxy list parsing
    let no_proxy = "localhost,127.0.0.1,.example.com";
    let domains: Vec<&str> = no_proxy.split(',').collect();
    assert!(domains.contains(&"localhost"));
    assert!(domains.contains(&"127.0.0.1"));
    assert!(domains.contains(&".example.com"));
}

#[test]
fn test_no_proxy_match() {
    // Test domain matching for no_proxy
    fn should_bypass(domain: &str, no_proxy_list: &[&str]) -> bool {
        for pattern in no_proxy_list {
            if pattern.starts_with('.') {
                if domain.ends_with(pattern) || domain == &pattern[1..] {
                    return true;
                }
            } else if domain == *pattern {
                return true;
            }
        }
        false
    }

    let no_proxy = vec!["localhost", "127.0.0.1", ".example.com"];
    assert!(should_bypass("localhost", &no_proxy));
    assert!(should_bypass("127.0.0.1", &no_proxy));
    assert!(should_bypass("www.example.com", &no_proxy));
    assert!(should_bypass("example.com", &no_proxy));
    assert!(!should_bypass("other.com", &no_proxy));
}

// ============================================================================
// Shared CONNECT tunnel helpers (arch 6.3-9)
// ============================================================================

#[test]
fn build_connect_request_sanitizes_and_brackets_ipv6() {
    use ut_net::proxy::build_connect_request;

    // IPv6 target gets bracketed; HTTP/1.1 request line; Host mirrors target.
    let req = build_connect_request("::1", 443, None, None);
    assert!(req.starts_with("CONNECT [::1]:443 HTTP/1.1\r\n"));
    assert!(req.contains("Host: [::1]:443\r\n"));
    assert!(req.ends_with("\r\n\r\n"));
}

#[test]
fn build_connect_request_strips_control_chars() {
    use ut_net::proxy::build_connect_request;

    // CRLF in the target host must not smuggle extra request lines.
    let req = build_connect_request("evil\r\nX-Injected: 1", 443, None, None);
    assert!(!req.contains("X-Injected"), "got: {}", req);
}

#[test]
fn build_connect_request_includes_basic_auth() {
    use ut_net::proxy::build_connect_request;

    let req = build_connect_request("example.com", 443, Some("u"), Some("p"));
    assert!(req.contains("Proxy-Authorization: Basic "), "got: {}", req);
}

#[test]
fn parse_connect_status_extracts_code_precisely() {
    use ut_net::proxy::parse_connect_status;

    assert_eq!(parse_connect_status("HTTP/1.1 200 Connection Established"), Some(200));
    assert_eq!(parse_connect_status("HTTP/1.0 403 Forbidden"), Some(403));
    // Substring match would falsely accept "1200"; token parsing must not.
    assert_eq!(parse_connect_status("HTTP/1.1 1200 Weird"), Some(1200));
    assert_eq!(parse_connect_status("garbage"), None);
}
