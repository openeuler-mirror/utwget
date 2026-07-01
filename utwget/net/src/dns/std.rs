//! Standard library DNS resolver implementation.
//!
//! This module provides a DNS resolver that uses the standard library's
//! `ToSocketAddrs` trait for hostname resolution. This delegates to the
//! operating system's resolver (typically `getaddrinfo` on Unix systems).

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use super::{AddressFamily, DnsError, DnsResolver};

/// A DNS resolver that uses the standard library's `ToSocketAddrs`.
///
/// This resolver delegates to the operating system's DNS resolution
/// mechanisms. On Unix systems, this typically uses `getaddrinfo`,
/// which respects system configuration like `/etc/resolv.conf`,
/// `/etc/hosts`, and any system-level DNS caching.
///
/// # Address Family Filtering
///
/// Unlike [`StdResolver`](super::std_resolver::StdResolver), this implementation
/// filters results based on the requested address family:
///
/// - `AddressFamily::Ipv4` - Returns only IPv4 addresses
/// - `AddressFamily::Ipv6` - Returns only IPv6 addresses
/// - `AddressFamily::PreferIpv4` - Prefers IPv4, falls back to IPv6
/// - `AddressFamily::PreferIpv6` - Prefers IPv6, falls back to IPv4
/// - `AddressFamily::Unspecified` - Returns all addresses
///
/// # Timeout
///
/// The timeout parameter is accepted for API compatibility but is not
/// enforced by this resolver. The OS controls resolution timeouts.
pub struct StdResolver;

impl StdResolver {
    /// Creates a new standard resolver.
    ///
    /// # Example
    ///
    /// ```
    /// use utwget_net::dns::std::StdResolver;
    ///
    /// let resolver = StdResolver::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
}

impl Default for StdResolver {
    /// Creates a default standard resolver.
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver for StdResolver {
    /// Resolves a hostname to socket addresses.
    ///
    /// This method formats the host and port as `host:port`, delegates to
    /// the standard library's `to_socket_addrs` for resolution, and filters
    /// the results based on the requested address family.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to resolve (e.g., "example.com").
    /// * `port` - The port number to associate with resolved addresses.
    /// * `family` - The address family preference for filtering results.
    /// * `timeout` - Timeout for the DNS query (ignored by this resolver).
    ///
    /// # Returns
    ///
    /// A vector of `SocketAddr` values matching the address family filter.
    ///
    /// # Errors
    ///
    /// * `DnsError::HostNotFound` - If the hostname does not exist.
    /// * `DnsError::ResolveFailed` - If the OS resolution fails.
    fn resolve(
        &self,
        host: &str,
        port: u16,
        family: AddressFamily,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, DnsError> {
        let addr_str = format!("{}:{}", host, port);

        let socket_addrs = (addr_str.as_str(), 0u16).to_socket_addrs().map_err(|e| {
            DnsError::ResolveFailed {
                host: host.to_string(),
                detail: e.to_string(),
            }
        })?;

        let mut addrs: Vec<SocketAddr> = socket_addrs
            .filter(|a| address_matches_family(a, family))
            .map(|mut a| {
                a.set_port(port);
                a
            })
            .collect();

        if addrs.is_empty() {
            return Err(DnsError::HostNotFound(host.to_string()));
        }

        let _ = timeout;

        Ok(addrs)
    }
}

/// Checks if a socket address matches the requested address family.
///
/// # Arguments
///
/// * `addr` - The socket address to check.
/// * `family` - The address family to match against.
///
/// # Returns
///
/// `true` if the address matches the family filter, `false` otherwise.
fn address_matches_family(addr: &SocketAddr, family: AddressFamily) -> bool {
    use std::net::IpAddr::{V4, V6};
    match (addr.ip(), family) {
        (V4(_), AddressFamily::Ipv4) => true,
        (V6(_), AddressFamily::Ipv6) => true,
        (V4(_), AddressFamily::Ipv6) => false,
        (V6(_), AddressFamily::Ipv4) => false,
        (V4(_), AddressFamily::PreferIpv6) => false,
        (V6(_), AddressFamily::PreferIpv4) => false,
        (_, AddressFamily::PreferIpv4) => matches!(addr.ip(), V4(_)),
        (_, AddressFamily::PreferIpv6) => matches!(addr.ip(), V6(_)),
        (_, AddressFamily::Unspecified) => true,
    }
}
