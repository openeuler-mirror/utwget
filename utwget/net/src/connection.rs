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
