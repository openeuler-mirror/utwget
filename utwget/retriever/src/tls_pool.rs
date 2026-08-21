//! TLS connection pool for reusing secure connections.
//!
//! This module provides a connection pool that supports both plain TCP
//! and TLS connections, allowing reuse of established connections to
//! improve performance for multiple requests to the same host.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use ut_net::transport::Transport;
use ut_net::tls::TlsError;

/// Maximum age of an idle connection before it's considered expired (5 minutes).
const MAX_IDLE_AGE: std::time::Duration = std::time::Duration::from_secs(300);

/// A pooled connection that can be either TCP or TLS.
enum PooledConnection {
    /// Plain TCP connection.
    Tcp(std::net::TcpStream),
    /// TLS connection wrapped in a trait object.
    Tls(Box<dyn Transport<Error = TlsError>>),
}

impl PooledConnection {
    /// Check if the connection is still alive.
    fn is_alive(&self) -> bool {
        match self {
            PooledConnection::Tcp(stream) => stream.peer_addr().is_ok(),
            PooledConnection::Tls(transport) => transport.is_alive(),
        }
    }
}

/// A connection entry with metadata.
struct ConnectionEntry {
    /// The pooled connection.
    conn: PooledConnection,
    /// When this connection was last used.
    last_used: Instant,
}

/// Connection pool for reusing TCP and TLS connections.
///
/// This pool manages connections keyed by (host, port) and supports
/// both plain TCP and TLS connections. Connections are automatically
/// expired after a configurable idle timeout.
pub struct TlsConnectionPool {
    /// Pooled connections keyed by (host, port, use_tls).
    pools: Mutex<HashMap<(String, u16, bool), Vec<ConnectionEntry>>>,
    /// Maximum connections per pool key.
    max_per_pool: usize,
}

impl TlsConnectionPool {
    /// Create a new TLS connection pool.
    ///
    /// # Arguments
    ///
    /// * `max_per_pool` - Maximum number of connections to pool per (host, port, use_tls) key.
    pub fn new(max_per_pool: usize) -> Self {
        TlsConnectionPool {
            pools: Mutex::new(HashMap::new()),
            max_per_pool,
        }
    }

    /// Get a connection from the pool.
    ///
    /// Returns a pooled connection if one is available and still alive.
    /// Expired connections are automatically removed.
    ///
    /// # Arguments
    ///
    /// * `host` - The target hostname.
    /// * `port` - The target port.
    /// * `use_tls` - Whether this is a TLS connection.
    ///
    /// # Returns
    ///
    /// A `PooledConnection` if one is available, `None` otherwise.
    fn get(&self, host: &str, port: u16, use_tls: bool) -> Option<PooledConnection> {
        let key = (host.to_string(), port, use_tls);
        let mut pools = self.pools.lock().unwrap();
        if let Some(pool) = pools.get_mut(&key) {
            // Remove expired connections and find a valid one
            pool.retain(|entry| entry.last_used.elapsed() < MAX_IDLE_AGE);
            while let Some(entry) = pool.pop() {
                if entry.conn.is_alive() {
                    debug!("reusing pooled connection to {}:{}", host, port);
                    return Some(entry.conn);
                }
            }
        }
        None
    }

    /// Return a connection to the pool for reuse.
    ///
    /// # Arguments
    ///
    /// * `host` - The target hostname.
    /// * `port` - The target port.
    /// * `use_tls` - Whether this is a TLS connection.
    /// * `conn` - The connection to return to the pool.
    fn put(&self, host: &str, port: u16, use_tls: bool, conn: PooledConnection) {
        let key = (host.to_string(), port, use_tls);
        let mut pools = self.pools.lock().unwrap();
        let pool = pools.entry(key).or_insert_with(Vec::new);
        if pool.len() < self.max_per_pool {
            pool.push(ConnectionEntry {
                conn,
                last_used: Instant::now(),
            });
        }
    }

    /// Get a TCP connection from the pool.
    pub fn get_tcp(&self, host: &str, port: u16) -> Option<std::net::TcpStream> {
        match self.get(host, port, false) {
            Some(PooledConnection::Tcp(stream)) => Some(stream),
            _ => None,
        }
    }

    /// Return a TCP connection to the pool.
    pub fn put_tcp(&self, host: &str, port: u16, conn: std::net::TcpStream) {
        self.put(host, port, false, PooledConnection::Tcp(conn));
    }

    /// Get a TLS connection from the pool.
    pub fn get_tls(&self, host: &str, port: u16) -> Option<Box<dyn Transport<Error = TlsError>>> {
        match self.get(host, port, true) {
            Some(PooledConnection::Tls(transport)) => Some(transport),
            _ => None,
        }
    }

    /// Return a TLS connection to the pool.
    pub fn put_tls(&self, host: &str, port: u16, conn: Box<dyn Transport<Error = TlsError>>) {
        self.put(host, port, true, PooledConnection::Tls(conn));
    }

    /// Clear all connections from the pool.
    pub fn clear(&self) {
        let mut pools = self.pools.lock().unwrap();
        pools.clear();
    }

    /// Get the total number of pooled connections.
    pub fn total_pooled(&self) -> usize {
        let pools = self.pools.lock().unwrap();
        pools.values().map(|pool| pool.len()).sum()
    }
}
