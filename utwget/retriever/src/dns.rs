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

/// Maximum number of cached DNS entries. Each entry holds a handful of
/// SocketAddrs; unbounded growth would let a workload touching many hosts
/// (or a malicious recursive page full of unique hostnames) balloon the
/// cache (M23). Oldest entries (by insertion, roughly) are evicted first.
pub const DNS_CACHE_MAX_ENTRIES: usize = 1024;

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
///
/// Evicts expired entries first, then — if still above the capacity limit —
/// drops the entries closest to expiry to bound memory (M23).
pub fn cache_insert(host: &str, port: u16, addrs: Vec<SocketAddr>) {
    if let Ok(mut cache) = dns_cache().lock() {
        // Cheap opportunistic cleanup: drop expired entries on every insert.
        cache.retain(|_, (_, cached_at)| cached_at.elapsed() < DNS_CACHE_TTL);

        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            // Evict the soonest-to-expire entries (approximate LRU: entries
            // inserted earliest expire first since the TTL is uniform).
            let mut by_expiry: Vec<_> = cache
                .iter()
                .map(|(k, (_, t))| (*t, k.clone()))
                .collect();
            by_expiry.sort_by_key(|(t, _)| *t);
            let excess = cache.len() + 1 - DNS_CACHE_MAX_ENTRIES;
            for (_, key) in by_expiry.into_iter().take(excess) {
                cache.remove(&key);
            }
        }

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
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to their
/// embedded IPv4 form first: `::ffff:127.0.0.1` would otherwise be
/// classified as a plain V6 address, bypassing every private-range check
/// while still connecting to 127.0.0.1 (H-2). Also covers loopback,
/// unspecified, broadcast, CGNAT (100.64.0.0/10), and IPv6 ULA/unique-local
/// ranges that cloud-internal services commonly use.
pub fn is_private_ip(addr: &IpAddr) -> bool {
    // Normalize IPv4-mapped IPv6 (::ffff:0:0/96) to the embedded IPv4
    // address so the V4 private ranges apply.
    let addr = match addr {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                // IPv4-compatible (::a.b.c.d, deprecated but still routable
                // on some stacks) — also normalize.
                if let Some(v4) = to_ipv4_compatible(v6) {
                    IpAddr::V4(v4)
                } else {
                    addr.to_owned()
                }
            }
        }
        _ => addr.to_owned(),
    };

    match addr {
        IpAddr::V4(v4) => {
            v4.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_loopback()    // 127.0.0.0/8
                || v4.is_link_local()  // 169.254.0.0/16 (cloud metadata)
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast()   // 255.255.255.255
                || is_cgnat_v4(&v4)    // 100.64.0.0/10 (carrier/NAT44)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()     // ::1
                || v6.is_unspecified() // ::
                || v6.is_multicast()
                // IPv6 unique-local (fc00::/7): the V6 equivalent of RFC 1918
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // IPv6 link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Returns `Some(v4)` for deprecated IPv4-compatible addresses (`::a.b.c.d`,
/// the first 96 bits zero and the last 32 bits nonzero). Distinct from
/// IPv4-mapped (`::ffff:a.b.c.d`) which `to_ipv4_mapped()` already covers.
fn to_ipv4_compatible(v6: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let segs = v6.segments();
    if segs[0] == 0
        && segs[1] == 0
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
        && !(segs[6] == 0 && segs[7] <= 1)
    {
        // Exclude :: (unspecified) and ::1 (loopback) which are V6-special.
        Some(std::net::Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            segs[6] as u8,
            (segs[7] >> 8) as u8,
            segs[7] as u8,
        ))
    } else {
        None
    }
}

/// Carrier-grade NAT range 100.64.0.0/10 (RFC 6598) — shared address space
/// used inside ISP and cloud networks; not covered by `Ipv4Addr::is_private`.
fn is_cgnat_v4(v4: &std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}
