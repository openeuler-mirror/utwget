//! Standard library DNS resolver implementation.
//!
//! This module provides a simple DNS resolver that delegates to the
//! standard library's `ToSocketAddrs` trait. It is the default resolver
//! used when no custom DNS implementation is needed.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use super::{AddressFamily, DnsError, DnsResolver};

/// A DNS resolver that delegates to the standard library's `ToSocketAddrs` trait.
///
/// This is the default resolver used when no custom DNS implementation is needed.
/// It performs DNS lookups using the operating system's standard resolution
/// mechanisms (e.g., glibc's `getaddrinfo` on Linux).
///
/// # Characteristics
///
/// - Uses OS-level DNS resolution (respects `/etc/resolv.conf`, `/etc/hosts`)
/// - Does not enforce timeout (OS controls resolution timeout)
/// - Does not filter by address family (returns all addresses from OS)
///
/// # Example
///
/// ```
/// use utwget_net::dns::{DnsResolver, StdResolver};
/// use ut_core::AddressFamily;
/// use std::time::Duration;
///
/// let resolver = StdResolver::new();
/// // let addrs = resolver.resolve("example.com", 443, AddressFamily::Unspecified, Duration::from_secs(10));
/// ```
pub struct StdResolver;

impl StdResolver {
    /// Creates a new `StdResolver`.
    ///
    /// # Example
    ///
    /// ```
    /// use utwget_net::dns::StdResolver;
    ///
    /// let resolver = StdResolver::new();
    /// ```
    pub fn new() -> Self {
        StdResolver
    }
}
