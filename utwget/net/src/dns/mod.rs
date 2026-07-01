//! DNS resolution module.
//!
//! This module provides DNS resolution capabilities with support for:
//!
//! - Custom DNS resolver implementations via the [`DnsResolver`] trait
//! - Standard system DNS resolution via [`StdResolver`]
//! - Address family filtering (IPv4, IPv6, or both)
//! - Configurable timeouts
//!
//! # Example
//!
//! ```ignore
//! use utwget_net::dns::{DnsResolver, StdResolver};
//! use ut_core::AddressFamily;
//! use std::time::Duration;
//!
//! let resolver = StdResolver::new();
//! let addrs = resolver.resolve("example.com", 443, AddressFamily::Unspecified, Duration::from_secs(10))?;
//! ```

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use ut_core::AddressFamily;

pub mod std_resolver;

/// Trait for DNS resolution implementations.
///
/// Implementations of this trait provide hostname to IP address resolution.
/// The trait is designed to be thread-safe (`Send + Sync`) for use in
/// async or multi-threaded contexts.
///
/// # Example Implementation
///
/// ```ignore
/// use utwget_net::dns::{DnsResolver, DnsError};
/// use ut_core::AddressFamily;
/// use std::net::SocketAddr;
/// use std::time::Duration;
///
/// struct MyResolver;
///
/// impl DnsResolver for MyResolver {
///     fn resolve(
///         &self,
///         host: &str,
///         port: u16,
///         family: AddressFamily,
///         timeout: Duration,
///     ) -> Result<Vec<SocketAddr>, DnsError> {
///         // Custom resolution logic
///         todo!()
///     }
/// }
/// ```
pub trait DnsResolver: Send + Sync {
    /// Resolves a hostname to a list of socket addresses.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to resolve (e.g., "example.com").
    /// * `port` - The port number to associate with resolved addresses.
    /// * `family` - The address family preference (IPv4, IPv6, or unspecified).
    /// * `timeout` - Maximum time to wait for resolution.
    ///
    /// # Returns
    ///
    /// A vector of `SocketAddr` values on success.
    ///
    /// # Errors
    ///
    /// Returns a `DnsError` if resolution fails, times out, or returns no addresses.
    fn resolve(
        &self,
        host: &str,
        port: u16,
        family: AddressFamily,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, DnsError>;
}

/// Error type for DNS resolution operations.
///
/// This enum covers all possible failure modes for DNS resolution.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// The hostname could not be found.
    ///
    /// This typically indicates that the hostname does not exist
    /// in the DNS system (NXDOMAIN).
    #[error("host not found: {0}")]
    HostNotFound(String),

    /// No addresses were found for the hostname and port.
    ///
    /// The hostname may exist but has no addresses matching
    /// the requested address family.
    #[error("no addresses found for {host}:{port}")]
    NoAddresses { host: String, port: u16 },

    /// DNS resolution failed for a specific reason.
    ///
    /// This is a general error that includes the hostname and
    /// a detail message describing the failure.
    #[error("DNS resolution failed for {host}: {detail}")]
    ResolveFailed { host: String, detail: String },

    /// DNS query timed out.
    ///
    /// The resolution did not complete within the specified timeout.
    #[error("DNS query timed out for {host} after {timeout:?}")]
    Timeout { host: String, timeout: Duration },

    /// I/O error during DNS resolution.
    ///
    /// This wraps underlying system I/O errors that may occur
    /// during resolution.
    #[error("DNS I/O error: {0}")]
    Io(#[from] io::Error),
}
