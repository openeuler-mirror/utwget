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

impl Default for StdResolver {
    /// Creates a default `StdResolver`.
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver for StdResolver {
    /// Resolves a hostname and port into a list of socket addresses.
    ///
    /// This method formats the host and port as `host:port`, delegates to the
    /// standard library's `to_socket_addrs` for resolution, and collects all
    /// returned addresses. The `family` and `timeout` parameters are respected
    /// by the trait interface but are not used by this resolver, which relies
    /// entirely on the OS-level resolution behavior.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to resolve (e.g., `"example.com"`).
    /// * `port` - The port number to associate with the resolved addresses.
    /// * `_family` - The desired address family (IPv4 or IPv6). Ignored by this
    ///   resolver; the OS determines which addresses are returned.
    /// * `_timeout` - An optional timeout for the DNS query. Ignored by this
    ///   resolver; the OS controls resolution timeout.
    ///
    /// # Returns
    ///
    /// A vector of `SocketAddr` values for the resolved hostname and port.
    ///
    /// # Errors
    ///
    /// * `DnsError::ResolveFailed` - If the OS-level resolution fails
    ///   (e.g., the hostname does not exist or a network error occurs).
    /// * `DnsError::NoAddresses` - If resolution succeeds but returns
    ///   no addresses for the given hostname and port.
    fn resolve(
        &self,
        host: &str,
        port: u16,
        _family: AddressFamily,
        _timeout: Duration,
    ) -> Result<Vec<SocketAddr>, DnsError> {
        let addr = format!("{}:{}", host, port);
        let addrs: Vec<SocketAddr> = addr
            .to_socket_addrs()
            .map_err(|e| DnsError::ResolveFailed {
                host: host.to_string(),
                detail: e.to_string(),
            })?
            .collect();

        if addrs.is_empty() {
            return Err(DnsError::NoAddresses {
                host: host.to_string(),
                port,
            });
        }

        Ok(addrs)
    }
}
