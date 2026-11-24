//! DNS cache and resolution utilities.
//!
//! This module encapsulates the process-wide DNS cache used by the Retriever
//! to avoid repeated lookups for the same host. The cache is keyed by
//! (host, port) because resolved SocketAddr values include the port.
//!
//! Also provides SSRF helper functions for IP address classification.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use ut_core::WgetError;

/// DNS cache entry type: resolved addresses + when they were cached.
pub type DnsCacheEntry = (Vec<SocketAddr>, Instant);

/// DNS cache key: (host, port).
pub type DnsCacheKey = (String, u16);

/// DNS cache entry TTL (seconds).
pub const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Process-wide DNS cache.
/// Caches resolved socket addresses with a TTL to avoid repeated DNS lookups
/// for the same host. The cache is keyed by (host, port) because the resolved
/// SocketAddr values include the port — caching by host alone would cause a
/// request to port 443 to reuse addresses resolved for port 80 (or vice versa).
/// Disabled when `--no-dns-cache` is set (per-Retriever).
static DNS_CACHE: OnceLock<Mutex<HashMap<DnsCacheKey, DnsCacheEntry>>> = OnceLock::new();

/// Get the process-wide DNS cache (lazily initialized).
pub fn dns_cache() -> &'static Mutex<HashMap<DnsCacheKey, DnsCacheEntry>> {
    DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up a cached DNS entry.
///
/// Returns `Some(addresses)` if a non-stale cache entry exists, `None` otherwise.
pub fn cache_lookup(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let cache = dns_cache().lock().ok()?;
    let (addrs, cached_at) = cache.get(&(host.to_string(), port))?;
    if cached_at.elapsed() < DNS_CACHE_TTL {
        Some(addrs.clone())
    } else {
        None
    }
}

/// Store resolved addresses in the DNS cache.
pub fn cache_insert(host: &str, port: u16, addrs: Vec<SocketAddr>) {
    if let Ok(mut cache) = dns_cache().lock() {
        cache.insert((host.to_string(), port), (addrs, Instant::now()));
    }
}

/// Resolve a hostname to socket addresses with an optional timeout.
///
/// Uses a background thread + channel pattern for timeout. On timeout, the
/// resolver thread is detached and will exit naturally when `to_socket_addrs()`
/// returns (channel send failure is silently ignored).
///
/// # Arguments
///
/// * `host` - The hostname to resolve.
/// * `port` - The target port.
/// * `timeout` - Optional DNS timeout duration.
///
/// # Returns
///
/// A vector of `SocketAddr` on success, or `WgetError` on failure.
pub fn resolve_with_timeout(
    host: &str,
    port: u16,
    timeout: Option<Duration>,
) -> Result<Vec<SocketAddr>, WgetError> {
    use std::net::ToSocketAddrs;

    let addrs = if let Some(dns_timeout) = timeout {
        let host_owned = host.to_string();
        let (tx, rx) = std::sync::mpsc::channel();

        let _handle = std::thread::Builder::new()
            .name(format!("dns-resolve-{}", host))
            .spawn(move || {
                let result = (host_owned.as_str(), port).to_socket_addrs();
                let _ = tx.send(result); // receiver may be dropped on timeout
            })
            .map_err(|e| WgetError::DnsResolution(format!("failed to spawn DNS thread: {}", e)))?;

        match rx.recv_timeout(dns_timeout) {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(e)) => {
                return Err(WgetError::DnsResolution(format!("{}", e)));
            }
            Err(_) => {
                log::debug!("DNS resolution timeout for {}, detaching resolver thread", host);
                return Err(WgetError::DnsTimeout);
            }
        }
    } else {
        (host, port)
            .to_socket_addrs()
            .map_err(|e| WgetError::DnsResolution(format!("{}", e)))?
    };

    Ok(addrs.collect())
}

/// Returns true if the IP address is in a private (RFC 1918) or link-local
/// range, used for SSRF awareness on redirects.
pub fn is_private_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private()       // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local() // 169.254.0.0/16 (cloud metadata)
                || v4.is_unspecified() // 0.0.0.0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()
        }
    }
}
