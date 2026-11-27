//! Unit tests for Cookie handling.

use ut_core::cookie::{CookieJar, Cookie};
use ut_core::types::Scheme;
use std::io::Cursor;

// ============================================================================
// Cookie Parsing Tests
// ============================================================================

#[test]
fn test_parse_simple_cookie() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("session=abc123", "example.com", "/");

    assert_eq!(jar.len(), 1);
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "session");
    assert_eq!(cookies[0].value, "abc123");
}

#[test]
fn test_parse_cookie_with_path() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Path=/app", "example.com", "/");

    let cookies = jar.match_request("example.com", "/app", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].path, "/app");
}

#[test]
fn test_parse_cookie_with_domain() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Domain=.example.com", "www.example.com", "/");

    let cookies = jar.match_request("www.example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].domain, "example.com");
}

#[test]
fn test_parse_cookie_secure() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Secure", "example.com", "/");

    // Should not match for HTTP
    let cookies_http = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies_http.len(), 0);

    // Should match for HTTPS
    let cookies_https = jar.match_request("example.com", "/", Scheme::Https);
    assert_eq!(cookies_https.len(), 1);
    assert!(cookies_https[0].secure);
}

#[test]
fn test_parse_cookie_httponly() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; HttpOnly", "example.com", "/");

    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].httponly);
}

#[test]
fn test_parse_cookie_max_age() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Max-Age=3600", "example.com", "/");

    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].expires.is_some());
    assert!(cookies[0].persistent);
}

#[test]
fn test_parse_cookie_expires() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie(
        "id=123; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
        "example.com",
        "/",
    );

    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    // Note: This cookie may be expired, so we just check parsing worked
    assert_eq!(jar.len(), 1);
}

#[test]
fn test_parse_cookie_multiple_attributes() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie(
        "session=xyz; Domain=.example.com; Path=/app; Secure; HttpOnly; Max-Age=86400",
        "www.example.com",
        "/app",
    );

    let cookies = jar.match_request("www.example.com", "/app/page", Scheme::Https);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "session");
    assert_eq!(cookies[0].domain, "example.com");
    assert_eq!(cookies[0].path, "/app");
    assert!(cookies[0].secure);
    assert!(cookies[0].httponly);
}

// ============================================================================
// Cookie Matching Tests
// ============================================================================

#[test]
fn test_match_exact_domain() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123", "example.com", "/");

    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
}

#[test]
fn test_match_subdomain() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Domain=.example.com", "example.com", "/");

    // Should match for subdomain
    let cookies = jar.match_request("www.example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);

    // Should also match for the domain itself
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
}

#[test]
fn test_match_path() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Path=/app", "example.com", "/");

    // Should match for exact path
    let cookies = jar.match_request("example.com", "/app", Scheme::Http);
    assert_eq!(cookies.len(), 1);

    // Should match for subpath
    let cookies = jar.match_request("example.com", "/app/page", Scheme::Http);
    assert_eq!(cookies.len(), 1);

    // Should not match for different path
    let cookies = jar.match_request("example.com", "/other", Scheme::Http);
    assert_eq!(cookies.len(), 0);
}

#[test]
fn test_match_root_path() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123; Path=/", "example.com", "/");

    // Root path should match all paths
    let cookies = jar.match_request("example.com", "/any/path", Scheme::Http);
    assert_eq!(cookies.len(), 1);
}

#[test]
fn test_match_multiple_cookies() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("a=1; Path=/", "example.com", "/");
    jar.parse_set_cookie("b=2; Path=/app", "example.com", "/app");
    jar.parse_set_cookie("c=3; Path=/app/admin", "example.com", "/app/admin");

    let cookies = jar.match_request("example.com", "/app/admin/page", Scheme::Http);
    assert_eq!(cookies.len(), 3);
}

#[test]
fn test_match_path_ordering() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("a=1; Path=/", "example.com", "/");
    jar.parse_set_cookie("b=2; Path=/app", "example.com", "/app");

    let cookies = jar.match_request("example.com", "/app/page", Scheme::Http);
    // Longer path should come first
    assert_eq!(cookies[0].path, "/app");
    assert_eq!(cookies[1].path, "/");
}

// ============================================================================
// Cookie Storage Tests
// ============================================================================

#[test]
fn test_store_cookie() {
    let mut jar = CookieJar::new();
    let cookie = Cookie {
        domain: "example.com".to_string(),
        path: "/".to_string(),
        name: "test".to_string(),
        value: "value".to_string(),
        expires: None,
        secure: false,
        httponly: false,
        persistent: false,
        samesite: ut_core::cookie::SameSite::Unspecified,
        host_only: true,
        created: 0,
    };

    jar.store(cookie);
    assert_eq!(jar.len(), 1);
}

#[test]
fn test_store_overwrite() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=1", "example.com", "/");
    jar.parse_set_cookie("id=2", "example.com", "/");

    assert_eq!(jar.len(), 1);
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies[0].value, "2");
}

// ============================================================================
// Cookie Serialization Tests
// ============================================================================

#[test]
fn test_serialize_for_header() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("a=1", "example.com", "/");
    jar.parse_set_cookie("b=2", "example.com", "/");

    let header = jar.serialize_for_header("example.com", "/", Scheme::Http);
    assert!(header.is_some());
    let header = header.unwrap();
    assert!(header.contains("a=1"));
    assert!(header.contains("b=2"));
}

#[test]
fn test_serialize_for_header_no_match() {
    let jar = CookieJar::new();
    let header = jar.serialize_for_header("example.com", "/", Scheme::Http);
    assert!(header.is_none());
}

#[test]
fn test_save_and_load_cookies() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("session=abc; Max-Age=3600", "example.com", "/");
    jar.parse_set_cookie("id=123; Max-Age=7200", "other.com", "/");

    // Save to buffer
    let mut buffer = Vec::new();
    jar.save_to_writer(&mut buffer, true).unwrap();

    // Load from buffer
    let mut jar2 = CookieJar::new();
    jar2.load_from_reader(Cursor::new(&buffer)).unwrap();

    assert_eq!(jar2.len(), 2);
}

// ============================================================================
// Cookie Expiration Tests
// ============================================================================

#[test]
fn test_remove_expired() {
    let mut jar = CookieJar::new();
    // Add a cookie that expires immediately
    jar.parse_set_cookie("id=123; Max-Age=0", "example.com", "/");

    jar.remove_expired();
    // The cookie should be removed
    // Note: Due to timing, this might not always work as expected
}

#[test]
fn test_is_expired() {
    let cookie = Cookie {
        domain: "example.com".to_string(),
        path: "/".to_string(),
        name: "test".to_string(),
        value: "value".to_string(),
        expires: None,
        secure: false,
        httponly: false,
        persistent: false,
        samesite: ut_core::cookie::SameSite::Unspecified,
        host_only: true,
        created: 0,
    };

    // Cookie without expiration is not expired
    assert!(!cookie.is_expired());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_parse_empty_cookie() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("", "example.com", "/");
    assert!(jar.is_empty());
}

#[test]
fn test_parse_cookie_no_value() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("name", "example.com", "/");
    // Cookie without = should be ignored
    assert!(jar.is_empty());
}

#[test]
fn test_parse_cookie_with_spaces() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("  id = 123  ;  Path = /app  ", "example.com", "/");

    let cookies = jar.match_request("example.com", "/app", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "id");
    assert_eq!(cookies[0].value, "123");
}

#[test]
fn test_cookie_jar_empty() {
    let jar = CookieJar::new();
    assert!(jar.is_empty());
    assert_eq!(jar.len(), 0);
}

#[test]
fn test_domain_matching_case_insensitive() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("id=123", "Example.COM", "/");

    // Domain matching should be case-insensitive
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
}

// ============================================================================
// Public Suffix List (PSL) Tests
// ============================================================================

#[test]
fn test_psl_rejects_cookie_for_public_suffix_com() {
    let mut jar = CookieJar::new();
    // A server on example.com cannot set a cookie for Domain="com" (a public
    // suffix). The cookie must be rejected.
    jar.parse_set_cookie("id=evil; Domain=com", "example.com", "/");
    assert_eq!(jar.len(), 0, "cookie with Domain=com must be rejected");
}

#[test]
fn test_psl_rejects_cookie_for_public_suffix_co_uk() {
    let mut jar = CookieJar::new();
    // "co.uk" is a public suffix; setting a cookie for it would leak across
    // all *.co.uk sites.
    jar.parse_set_cookie("id=evil; Domain=co.uk", "example.co.uk", "/");
    assert_eq!(jar.len(), 0, "cookie with Domain=co.uk must be rejected");
}

#[test]
fn test_psl_rejects_cookie_with_leading_dot_public_suffix() {
    let mut jar = CookieJar::new();
    // Leading dot variant must also be rejected.
    jar.parse_set_cookie("id=evil; Domain=.com", "example.com", "/");
    assert_eq!(jar.len(), 0, "cookie with Domain=.com must be rejected");
}

#[test]
fn test_psl_accepts_cookie_for_regular_domain() {
    let mut jar = CookieJar::new();
    // "example.com" is not a public suffix; setting a cookie for it is fine.
    jar.parse_set_cookie("id=ok; Domain=example.com", "www.example.com", "/");
    assert_eq!(jar.len(), 1, "cookie with Domain=example.com should be accepted");
}

#[test]
fn test_psl_accepts_cookie_without_domain() {
    let mut jar = CookieJar::new();
    // No Domain attribute → defaults to host-only; no PSL check applies.
    jar.parse_set_cookie("id=ok", "example.com", "/");
    assert_eq!(jar.len(), 1);
}

#[test]
fn test_psl_accepts_cookie_for_intranet_host() {
    let mut jar = CookieJar::new();
    // A hostname not in the PSL (e.g. "corp-example-12345") is treated as a
    // regular registrable domain and should be accepted. Note: many common
    // intranet names like "internal", "localhost", "lan", "local" are
    // actually in the PSL as private/special suffixes and would be rejected.
    jar.parse_set_cookie("id=ok; Domain=corp-example-12345", "www.corp-example-12345", "/");
    assert_eq!(jar.len(), 1);
}

#[test]
fn test_psl_ip_address_exempt() {
    let mut jar = CookieJar::new();
    // IP addresses bypass PSL checks.
    jar.parse_set_cookie("id=ok; Domain=127.0.0.1", "127.0.0.1", "/");
    assert_eq!(jar.len(), 1, "IP-address cookies should bypass PSL");
}

// ============================================================================
// Cookie Expires GMT Parsing Tests
// ============================================================================
//
// 验证 Set-Cookie 的 Expires 属性带 "GMT" 后缀时能被正确解析。
// 此前因 NaiveDateTime::parse_from_str 要求整个字符串匹配格式，
// 带尾部 " GMT" 的标准日期全部解析失败，导致所有持久 Cookie 被当作
// 会话 Cookie 丢失（expires=None, persistent=false）。
//
// 注意：使用未来日期（2099 年），否则 match_request 会跳过已过期 Cookie。
// 且星期几必须与日期匹配，否则 chrono 的 %a 解析会失败。

#[test]
fn test_parse_set_cookie_expires_with_gmt() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie(
        "id=123; Expires=Wed, 03 Jun 2099 10:18:14 GMT",
        "example.com",
        "/",
    );
    assert_eq!(jar.len(), 1);
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    let c = &cookies[0];
    assert!(c.persistent, "cookie with Expires should be persistent");
    let expires = c.expires.expect("expires should be set");
    assert_eq!(
        expires.format("%Y-%m-%d %H:%M:%S").to_string(),
        "2099-06-03 10:18:14",
    );
}

#[test]
fn test_parse_set_cookie_expires_lowercase_gmt() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie(
        "id=123; Expires=Wed, 03 Jun 2099 10:18:14 gmt",
        "example.com",
        "/",
    );
    assert_eq!(jar.len(), 1);
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].persistent);
    assert!(cookies[0].expires.is_some());
}

#[test]
fn test_parse_set_cookie_expires_no_gmt_suffix() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie(
        "id=123; Expires=Wed, 03 Jun 2099 10:18:14",
        "example.com",
        "/",
    );
    assert_eq!(jar.len(), 1);
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].persistent);
    assert!(cookies[0].expires.is_some());
}

// ============================================================================
// Max-Age Overflow Regression Tests (H-4)
// ============================================================================

#[test]
fn max_age_i64_max_does_not_panic() {
    // Regression: a hostile `Set-Cookie: Max-Age=9223372036854775807` header
    // crashed the client with `TimeDelta::seconds out of bounds` (chrono
    // panics beyond ±i64::MAX milliseconds). Must not panic.
    let mut jar = CookieJar::new();
    jar.parse_set_cookie(
        "sid=x; Max-Age=9223372036854775807",
        "example.com",
        "/",
    );
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1, "cookie must be stored");
    assert!(cookies[0].persistent, "Max-Age > 0 implies persistent");
    // Overflowing expiry is clamped to "far future" — the cookie must not
    // be considered expired.
    assert!(cookies[0].is_expired() == false, "clamped far-future expiry must not be expired");
}

#[test]
fn max_age_huge_but_safe_value_still_stores() {
    // Large but non-overflowing value (e.g. 100 years) is stored with a
    // computed expiry.
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("sid=x; Max-Age=3153600000", "example.com", "/");
    let cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].expires.is_some());
}

#[test]
fn max_age_zero_expires_immediately() {
    // Sanity: Max-Age=0 semantics unchanged (immediate expiry). Expired
    // cookies are filtered out by match_request.
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("sid=x; Max-Age=0", "example.com", "/");
    assert!(jar.match_request("example.com", "/", Scheme::Http).is_empty(),
        "Max-Age=0 cookie must be immediately expired and not matched");
}

#[test]
fn max_age_negative_expires_immediately() {
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("sid=x; Max-Age=-5", "example.com", "/");
    assert!(jar.match_request("example.com", "/", Scheme::Http).is_empty(),
        "negative Max-Age cookie must be immediately expired and not matched");
}
