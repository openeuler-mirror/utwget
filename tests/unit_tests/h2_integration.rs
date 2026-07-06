// HTTP/2 连接池与多路复用单元测试

use ut_retriever::h2_integration::{ConnectionPool, h2_pool, is_h2_forbidden_header, should_use_http2};
use ut_core::url::ParsedUrl;
use ut_core::Config;

/// Mock connection for testing pool logic without a real network.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MockConn {
    id: u32,
    alive: bool,
}

#[test]
fn test_pool_new_is_empty() {
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(4);
    assert!(pool.is_empty());
    assert_eq!(pool.len(), 0);
}

#[test]
fn test_pool_put_and_take() {
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(4);
    let conn = MockConn { id: 1, alive: true };
    pool.put("example.com".to_string(), 443, conn);

    assert_eq!(pool.len(), 1);
    assert!(!pool.is_empty());

    let taken = pool.take("example.com", 443);
    assert!(taken.is_some());
    assert_eq!(taken.unwrap().id, 1);

    // After take, pool is empty
    assert!(pool.is_empty());
}

#[test]
fn test_pool_take_missing_returns_none() {
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(4);
    assert!(pool.take("missing.com", 443).is_none());
}

#[test]
fn test_pool_take_wrong_key_returns_none() {
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(4);
    pool.put("a.com".to_string(), 443, MockConn { id: 1, alive: true });
    assert!(pool.take("b.com", 443).is_none());
    // Wrong port
    assert!(pool.take("a.com", 8443).is_none());
}

#[test]
fn test_pool_multiple_hosts() {
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(8);
    pool.put("a.com".to_string(), 443, MockConn { id: 1, alive: true });
    pool.put("b.com".to_string(), 443, MockConn { id: 2, alive: true });
    pool.put("c.com".to_string(), 8443, MockConn { id: 3, alive: true });

    assert_eq!(pool.len(), 3);

    // Each key retrieves its own connection
    assert_eq!(pool.take("b.com", 443).unwrap().id, 2);
    assert_eq!(pool.take("a.com", 443).unwrap().id, 1);
    assert_eq!(pool.take("c.com", 8443).unwrap().id, 3);
    assert!(pool.is_empty());
}

#[test]
fn test_pool_eviction_when_full() {
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(2);
    pool.put("a.com".to_string(), 443, MockConn { id: 1, alive: true });
    pool.put("b.com".to_string(), 443, MockConn { id: 2, alive: true });
    assert_eq!(pool.len(), 2);

    // Adding a third entry should evict one (cache is at capacity)
    pool.put("c.com".to_string(), 443, MockConn { id: 3, alive: true });
    assert_eq!(pool.len(), 2, "pool should not exceed max_entries");

    // The new entry must be present
    assert!(pool.take("c.com", 443).is_some());
}

#[test]
fn test_pool_replace_existing_does_not_evict() {
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(2);
    pool.put("a.com".to_string(), 443, MockConn { id: 1, alive: true });
    pool.put("b.com".to_string(), 443, MockConn { id: 2, alive: true });

    // Replacing an existing key should NOT evict (contains_key check)
    pool.put("a.com".to_string(), 443, MockConn { id: 99, alive: true });
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.take("a.com", 443).unwrap().id, 99);
    assert_eq!(pool.take("b.com", 443).unwrap().id, 2);
}

#[test]
fn test_pool_clear() {
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(4);
    pool.put("a.com".to_string(), 443, MockConn { id: 1, alive: true });
    pool.put("b.com".to_string(), 443, MockConn { id: 2, alive: true });
    assert_eq!(pool.len(), 2);

    pool.clear();
    assert!(pool.is_empty());
    assert!(pool.take("a.com", 443).is_none());
}

#[test]
fn test_pool_max_entries_minimum_one() {
    // max_entries = 0 should be clamped to 1
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(0);
    pool.put("a.com".to_string(), 443, MockConn { id: 1, alive: true });
    assert_eq!(pool.len(), 1);
}

#[test]
fn test_pool_take_removes_entry() {
    let pool: ConnectionPool<MockConn> = ConnectionPool::new(4);
    pool.put("a.com".to_string(), 443, MockConn { id: 1, alive: true });

    let _ = pool.take("a.com", 443);
    // Second take should return None (entry was removed, not just peeked)
    assert!(pool.take("a.com", 443).is_none());
}

#[test]
fn test_is_h2_forbidden_header() {
    // Connection-specific headers must be dropped
    assert!(is_h2_forbidden_header("connection"));
    assert!(is_h2_forbidden_header("transfer-encoding"));
    assert!(is_h2_forbidden_header("keep-alive"));
    assert!(is_h2_forbidden_header("proxy-connection"));
    assert!(is_h2_forbidden_header("upgrade"));
    assert!(is_h2_forbidden_header("host"));
    assert!(is_h2_forbidden_header("te"));

    // Normal headers are allowed
    assert!(!is_h2_forbidden_header("content-type"));
    assert!(!is_h2_forbidden_header("content-length"));
    assert!(!is_h2_forbidden_header("user-agent"));
    assert!(!is_h2_forbidden_header("accept-encoding"));
    assert!(!is_h2_forbidden_header("cookie"));
    assert!(!is_h2_forbidden_header("set-cookie"));
}

#[test]
fn test_should_use_http2_requires_force_flag() {
    let mut config = Config::default();
    config.http.force_http2 = false;
    let url = ParsedUrl::parse("https://example.com/").unwrap();
    assert!(!should_use_http2(&url, &config));

    config.http.force_http2 = true;
    assert!(should_use_http2(&url, &config));
}

#[test]
fn test_should_use_http2_requires_https() {
    let mut config = Config::default();
    config.http.force_http2 = true;

    // HTTP (not HTTPS) should not use HTTP/2
    let url = ParsedUrl::parse("http://example.com/").unwrap();
    assert!(!should_use_http2(&url, &config));

    // HTTPS should use HTTP/2
    let url = ParsedUrl::parse("https://example.com/").unwrap();
    assert!(should_use_http2(&url, &config));
}

#[test]
fn test_h2_pool_singleton_is_consistent() {
    // The process-wide pool should always return the same instance
    let p1 = h2_pool() as *const _;
    let p2 = h2_pool() as *const _;
    assert_eq!(p1, p2, "h2_pool() must return the same singleton");
}
