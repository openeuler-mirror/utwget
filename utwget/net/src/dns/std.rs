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
