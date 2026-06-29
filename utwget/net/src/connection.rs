//! Connection management module.
//!
//! This module provides connection pooling, DNS caching, and unified connection
//! management for both plain TCP and TLS connections. It supports:
//!
//! - Idle connection reuse for improved performance
//! - DNS result caching with configurable TTL
//! - Automatic connection cleanup for expired idle connections
//! - Support for both direct and proxy connections
//! - TLS upgrade with configurable options

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ut_core::AddressFamily;
use ut_core::error::TlsError;

use crate::dns::{DnsError, DnsResolver};
use crate::proxy;
use crate::tcp;
use crate::tls::{TlsConfig, TlsConnector};
use crate::transport::{Interest, Transport};

/// Default TTL for DNS cache entries (5 minutes).
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Maximum number of idle connections per connection key.
const MAX_IDLE_PER_KEY: usize = 5;

/// Maximum age of an idle connection before it's considered expired (2 minutes).
const MAX_IDLE_AGE: Duration = Duration::from_secs(120);

/// Connection manager that handles connection pooling, DNS caching, and TLS.
///
/// This is the primary interface for establishing network connections. It manages:
/// - DNS resolution with caching to avoid repeated lookups
/// - Idle connection pooling for connection reuse
/// - TLS/SSL connections with configurable verification
/// - Proxy connections with authentication support
///
/// # Type Parameters
///
/// * `R` - The DNS resolver implementation (must implement [`DnsResolver`])
/// * `T` - The TLS connector implementation (must implement [`TlsConnector`])
///
/// # Example
///
/// ```ignore
/// use utwget_net::connection::ConnectionManager;
/// use utwget_net::dns::StdResolver;
/// use utwget_net::tls::RustlsConnector;
///
/// let resolver = StdResolver::new();
/// let tls = RustlsConnector::new();
/// let mut manager = ConnectionManager::new(resolver, tls);
///
/// // Connect to a host
/// let conn = manager.connect("example.com", 443, true, None, None, None, None, None)?;
/// ```
pub struct ConnectionManager<R: DnsResolver, T: TlsConnector> {
    /// DNS resolver for hostname resolution.
    resolver: R,
    /// TLS connector for secure connections.
    tls: Arc<T>,
    /// DNS cache for storing resolved addresses.
    dns_cache: DnsCache,
    /// Pool of idle connections organized by connection key.
    idle_connections: HashMap<ConnectionKey, Vec<IdleConnection>>,
    /// Timeout for establishing new connections.
    connect_timeout: Duration,
    /// Timeout for read operations.
    read_timeout: Duration,
    /// Timeout for DNS resolution.
    dns_timeout: Duration,
    /// Optional local address to bind for outgoing connections.
    bind_address: Option<IpAddr>,
    /// Address family preference (IPv4, IPv6, or unspecified).
    address_family: AddressFamily,
}

/// Key for identifying and caching connections.
///
/// Connections are identified by their scheme (http/https), host, port,
/// and whether TLS is used. This allows connection reuse for identical
/// connection parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    /// The URL scheme (e.g., "http" or "https").
    pub scheme: String,
    /// The hostname or IP address.
    pub host: String,
    /// The port number.
    pub port: u16,
    /// Whether TLS/SSL is enabled for this connection.
    pub use_tls: bool,
}

/// Internal DNS cache for storing resolved addresses.
///
/// Maps hostnames to a list of socket addresses and the time they were cached.
struct DnsCache {
    /// Cached DNS entries: hostname -> (addresses, timestamp).
    entries: HashMap<String, (Vec<std::net::SocketAddr>, Instant)>,
    /// Time-to-live for cache entries.
    ttl: Duration,
}

/// An idle connection waiting to be reused.
///
/// Stores the transport and the time it was created for expiration tracking.
struct IdleConnection {
    /// The underlying transport.
    transport: Box<dyn Transport<Error = io::Error>>,
    /// Time when this connection was created/idled.
    created: Instant,
}

/// A managed connection returned by the connection manager.
///
/// This wraps a transport (TCP or TLS) and tracks whether it can be reused
/// and returned to the idle pool.
pub struct ManagedConnection {
    /// The connection key identifying this connection.
    key: ConnectionKey,
    /// The underlying transport (TCP or TLS).
    transport: ManagedTransport,
    /// Whether this connection can be returned to the idle pool.
    reusable: bool,
}

/// Internal enum for holding either a TCP or TLS transport.
enum ManagedTransport {
    /// Plain TCP transport.
    Tcp(Box<dyn Transport<Error = io::Error>>),
    /// TLS transport.
    Tls(Box<dyn Transport<Error = TlsError>>),
}

impl<R: DnsResolver, T: TlsConnector> ConnectionManager<R, T> {
    /// Creates a new connection manager with the given resolver and TLS connector.
    ///
    /// # Arguments
    ///
    /// * `resolver` - The DNS resolver to use for hostname resolution.
    /// * `tls` - The TLS connector for establishing secure connections.
    ///
    /// # Returns
    ///
    /// A new `ConnectionManager` with default timeout settings:
    /// - Connect timeout: 30 seconds
    /// - Read timeout: 60 seconds
    /// - DNS timeout: 15 seconds
    pub fn new(resolver: R, tls: T) -> Self {
        Self {
            resolver,
            tls: Arc::new(tls),
            dns_cache: DnsCache::new(DNS_CACHE_TTL),
            idle_connections: HashMap::new(),
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(60),
            dns_timeout: Duration::from_secs(15),
            bind_address: None,
            address_family: AddressFamily::Unspecified,
        }
    }

    /// Sets the connection timeout.
    ///
    /// This is the timeout for establishing a new TCP connection.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The connection timeout duration.
    ///
    /// # Returns
    ///
    /// The modified `ConnectionManager` for method chaining.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the read timeout.
    ///
    /// This timeout applies to all read operations on established connections.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The read timeout duration.
    ///
    /// # Returns
    ///
    /// The modified `ConnectionManager` for method chaining.
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Sets the DNS resolution timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The DNS resolution timeout duration.
    ///
    /// # Returns
    ///
    /// The modified `ConnectionManager` for method chaining.
    pub fn with_dns_timeout(mut self, timeout: Duration) -> Self {
        self.dns_timeout = timeout;
        self
    }

    /// Sets the local address to bind for outgoing connections.
    ///
    /// This is useful for multi-homed systems where you want to specify
    /// which network interface to use for outgoing connections.
    ///
    /// # Arguments
    ///
    /// * `addr` - The local IP address to bind.
    ///
    /// # Returns
    ///
    /// The modified `ConnectionManager` for method chaining.
    pub fn with_bind_address(mut self, addr: IpAddr) -> Self {
        self.bind_address = Some(addr);
        self
    }

    /// Sets the address family preference for connections.
    ///
    /// This controls whether to use IPv4, IPv6, or allow either.
    ///
    /// # Arguments
    ///
    /// * `family` - The address family preference.
    ///
    /// # Returns
    ///
    /// The modified `ConnectionManager` for method chaining.
    pub fn with_address_family(mut self, family: AddressFamily) -> Self {
        self.address_family = family;
        self
    }

    /// Establishes a connection to the specified host.
    ///
    /// This method first checks for an available idle connection. If none is
    /// available, it establishes a new connection, optionally through a proxy
    /// and with TLS.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to connect to.
    /// * `port` - The port number to connect to.
    /// * `use_tls` - Whether to establish a TLS connection.
    /// * `tls_config` - Optional TLS configuration (certificate verification, etc.).
    /// * `proxy_host` - Optional proxy hostname.
    /// * `proxy_port` - Optional proxy port (required if `proxy_host` is set).
    /// * `proxy_user` - Optional proxy authentication username.
    /// * `proxy_password` - Optional proxy authentication password.
    ///
    /// # Returns
    ///
    /// A `ManagedConnection` on success, or a `ConnectionError` on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - DNS resolution fails
    /// - TCP connection fails
    /// - TLS handshake fails
    /// - Proxy connection or authentication fails
    pub fn connect(
        &mut self,
        host: &str,
        port: u16,
        use_tls: bool,
        tls_config: Option<&TlsConfig>,
        proxy_host: Option<&str>,
        proxy_port: Option<u16>,
        proxy_user: Option<&str>,
        proxy_password: Option<&str>,
    ) -> Result<ManagedConnection, ConnectionError> {
        let scheme = if use_tls { "https" } else { "http" };
        let key = ConnectionKey {
            scheme: scheme.to_string(),
            host: host.to_string(),
            port,
            use_tls,
        };

        // Try to reuse an idle connection
        if let Some(conn) = self.take_idle_connection(&key) {
            return Ok(conn);
        }

        // Establish a new connection
        let tcp_stream = if let (Some(ph), Some(pp)) = (proxy_host, proxy_port) {
            proxy::connect_via_proxy(
                ph,
                pp,
                host,
                port,
                self.connect_timeout,
                self.read_timeout,
                proxy_user,
                proxy_password,
            )
            .map_err(ConnectionError::Proxy)?
        } else {
            tcp::connect_to_host(
                host,
                port,
                self.address_family,
                self.connect_timeout,
                self.bind_address,
            )
            .map_err(ConnectionError::Connect)?
        };

        let mut tcp_transport = crate::transport::TcpTransport::new(tcp_stream);
        tcp_transport
            .set_read_timeout(Some(self.read_timeout))
            .ok();
        tcp_transport
            .set_write_timeout(Some(self.read_timeout))
            .ok();

        // Upgrade to TLS if requested
        let transport: ManagedTransport = if use_tls {
            let config = tls_config.cloned().unwrap_or_default();
            let tls_transport = self
                .tls
                .connect(Box::new(tcp_transport), host, port, &config)
                .map_err(ConnectionError::Tls)?;

            ManagedTransport::Tls(tls_transport)
        } else {
            ManagedTransport::Tcp(Box::new(tcp_transport))
        };

        Ok(ManagedConnection {
            key,
            transport,
            reusable: true,
        })
    }

    /// Establishes a simple connection without proxy or custom TLS config.
    ///
    /// This is a convenience method that calls [`connect`](Self::connect) with
    /// default parameters.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to connect to.
    /// * `port` - The port number to connect to.
    /// * `use_tls` - Whether to establish a TLS connection.
    ///
    /// # Returns
    ///
    /// A `ManagedConnection` on success, or a `ConnectionError` on failure.
    pub fn connect_simple(
        &mut self,
        host: &str,
        port: u16,
        use_tls: bool,
    ) -> Result<ManagedConnection, ConnectionError> {
        self.connect(host, port, use_tls, None, None, None, None, None)
    }

    /// Returns a connection to the idle pool for reuse.
    ///
    /// The connection will only be pooled if it's marked as reusable and
    /// is still alive. TLS connections are not pooled (they require
    /// a fresh handshake for each use).
    ///
    /// # Arguments
    ///
    /// * `conn` - The connection to return to the pool.
    pub fn return_connection(&mut self, conn: ManagedConnection) {
        if !conn.reusable {
            return;
        }

        if let ManagedTransport::Tcp(ref t) = conn.transport {
            if !t.is_alive() {
                return;
            }
        }

        let key = conn.key.clone();
        let transport = match conn.transport {
            ManagedTransport::Tcp(t) => {
                let tcp: Box<dyn Transport<Error = io::Error>> = t;
                IdleConnection {
                    transport: tcp,
                    created: Instant::now(),
                }
            }
            ManagedTransport::Tls(_) => return, // Don't pool TLS connections
        };

        let entry = self.idle_connections.entry(key).or_default();
        if entry.len() >= MAX_IDLE_PER_KEY {
            return;
        }

        entry.push(transport);
    }

    /// Closes all idle connections in the pool.
    ///
    /// This immediately removes all idle connections without waiting for
    /// their natural expiration.
    pub fn close_idle_connections(&mut self) {
        self.idle_connections.clear();
    }

    /// Removes expired idle connections from the pool.
    ///
    /// Connections that have been idle for longer than `MAX_IDLE_AGE` are
    /// removed. This should be called periodically to clean up stale connections.
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        for conns in self.idle_connections.values_mut() {
            conns.retain(|c| now.duration_since(c.created) < MAX_IDLE_AGE);
        }
        self.idle_connections.retain(|_, v| !v.is_empty());
    }

    /// Resolves a hostname using the DNS resolver with caching.
    ///
    /// If the result is in the cache and not expired, returns the cached
    /// addresses. Otherwise, performs a fresh DNS lookup and caches the result.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to resolve.
    /// * `port` - The port to associate with the addresses.
    ///
    /// # Returns
    ///
    /// A vector of socket addresses on success, or a `ConnectionError` on failure.
    #[allow(dead_code)]
    fn resolve_cached(
        &mut self,
        host: &str,
        port: u16,
    ) -> Result<Vec<std::net::SocketAddr>, ConnectionError> {
        if let Some((addrs, cached_at)) = self.dns_cache.get(host) {
            if cached_at.elapsed() < self.dns_cache.ttl() {
                return Ok(addrs.clone());
            }
        }

        let addrs = self
            .resolver
            .resolve(host, port, self.address_family, self.dns_timeout)
            .map_err(ConnectionError::Dns)?;

        self.dns_cache.put(host.to_string(), addrs.clone());

        Ok(addrs)
    }

    /// Takes an idle connection from the pool if one is available.
    ///
    /// Only returns connections that are still alive and not expired.
    ///
    /// # Arguments
    ///
    /// * `key` - The connection key to look for.
    ///
    /// # Returns
    ///
    /// An idle `ManagedConnection` if available, or `None`.
    fn take_idle_connection(&mut self, key: &ConnectionKey) -> Option<ManagedConnection> {
        let conns = self.idle_connections.get_mut(key)?;
        let now = Instant::now();
        while let Some(conn) = conns.pop() {
            if now.duration_since(conn.created) < MAX_IDLE_AGE && conn.transport.is_alive() {
                return Some(ManagedConnection {
                    key: key.clone(),
                    transport: ManagedTransport::Tcp(conn.transport),
                    reusable: true,
                });
            }
        }
        None
    }

    /// Finds an idle connection key that could be upgraded to TLS.
    ///
    /// This is currently not implemented and always returns `None`.
    #[allow(dead_code)]
    fn find_idle_key_for_tls(&self, _host: &str, _port: u16) -> Option<ConnectionKey> {
        None
    }
}
