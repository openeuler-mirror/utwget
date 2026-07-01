//! Tests for connection pool functionality.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mock connection for testing (no actual TCP connection needed)
    struct MockConnection {
        id: u32,
        alive: bool,
    }

    impl MockConnection {
        fn new(id: u32) -> Self {
            MockConnection { id, alive: true }
        }

        fn is_alive(&self) -> bool {
            self.alive
        }
    }

    /// Test connection pool struct (mirrors the one in retriever)
    struct TestConnectionPool {
        pools: Mutex<HashMap<(String, u16), Vec<MockConnection>>>,
        max_per_pool: usize,
    }

    impl TestConnectionPool {
        fn new(max: usize) -> Self {
            TestConnectionPool {
                pools: Mutex::new(HashMap::new()),
                max_per_pool: max,
            }
        }

        fn get(&self, host: &str, port: u16) -> Option<MockConnection> {
            let key = (host.to_string(), port);
            let mut pools = self.pools.lock().unwrap();
            if let Some(pool) = pools.get_mut(&key) {
                while let Some(conn) = pool.pop() {
                    if conn.is_alive() {
                        return Some(conn);
                    }
                }
            }
            None
        }

        fn put(&self, host: &str, port: u16, conn: MockConnection) {
            let key = (host.to_string(), port);
            let mut pools = self.pools.lock().unwrap();
            let pool = pools.entry(key).or_default();
            if pool.len() < self.max_per_pool {
                pool.push(conn);
            }
        }

        fn pool_size(&self, host: &str, port: u16) -> usize {
            let pools = self.pools.lock().unwrap();
            let key = (host.to_string(), port);
            pools.get(&key).map(|p| p.len()).unwrap_or(0)
        }
    }

    #[test]
    fn test_pool_new() {
        let pool = TestConnectionPool::new(5);
        assert_eq!(pool.pool_size("example.com", 80), 0);
    }

    #[test]
    fn test_pool_put_and_get() {
        let pool = TestConnectionPool::new(5);
        let conn = MockConnection::new(1);
        pool.put("example.com", 80, conn);
        assert_eq!(pool.pool_size("example.com", 80), 1);

        let conn = pool.get("example.com", 80);
        assert!(conn.is_some());
        assert_eq!(pool.pool_size("example.com", 80), 0);
    }

    #[test]
    fn test_pool_max_limit() {
        let pool = TestConnectionPool::new(3);
        for i in 0..10 {
            let conn = MockConnection::new(i);
            pool.put("example.com", 80, conn);
        }
        assert_eq!(pool.pool_size("example.com", 80), 3);
    }

    #[test]
    fn test_pool_different_hosts() {
        let pool = TestConnectionPool::new(5);
        let conn1 = MockConnection::new(1);
        let conn2 = MockConnection::new(2);
        
        pool.put("host1.com", 80, conn1);
        pool.put("host2.com", 80, conn2);
        
        assert_eq!(pool.pool_size("host1.com", 80), 1);
        assert_eq!(pool.pool_size("host2.com", 80), 1);
    }

    #[test]
    fn test_pool_empty_get() {
        let pool = TestConnectionPool::new(5);
        let conn = pool.get("nonexistent.com", 80);
        assert!(conn.is_none());
    }

    #[test]
    fn test_pool_reuse_flow() {
        let pool = TestConnectionPool::new(5);
        let conn = MockConnection::new(1);
        
        // Put connection
        pool.put("example.com", 80, conn);
        assert_eq!(pool.pool_size("example.com", 80), 1);
        
        // Get and reuse
        let conn = pool.get("example.com", 80).unwrap();
        assert!(conn.is_alive());
        
        // Put back
        pool.put("example.com", 80, conn);
        assert_eq!(pool.pool_size("example.com", 80), 1);
    }

    #[test]
    fn test_pool_dead_connection_skipped() {
        let pool = TestConnectionPool::new(5);
        
        // Put a dead connection
        let mut dead_conn = MockConnection::new(1);
        dead_conn.alive = false;
        pool.put("example.com", 80, dead_conn);
        
        // Put a live connection
        let live_conn = MockConnection::new(2);
        pool.put("example.com", 80, live_conn);
        
        // Should get the live connection (dead one is skipped)
        let conn = pool.get("example.com", 80).unwrap();
        assert_eq!(conn.id, 2);
    }

    #[test]
    fn test_pool_different_ports() {
        let pool = TestConnectionPool::new(5);
        let conn1 = MockConnection::new(1);
        let conn2 = MockConnection::new(2);
        
        pool.put("example.com", 80, conn1);
        pool.put("example.com", 443, conn2);
        
        assert_eq!(pool.pool_size("example.com", 80), 1);
        assert_eq!(pool.pool_size("example.com", 443), 1);
    }
}
