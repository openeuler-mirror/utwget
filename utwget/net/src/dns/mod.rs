//! DNS resolution module.
//!
//! This module provides DNS error types used by the TCP connection layer.
//!
//! The actual DNS resolution is performed inline in `retriever.rs` and
//! `tcp.rs` using the standard library's `ToSocketAddrs` trait with
//! channel-based timeouts. A pluggable `DnsResolver` trait was defined
//! here historically but was never wired into the connection path; it has
//! been removed to reduce dead code. If pluggable DNS is needed in the
//! future (e.g., DoH/DoT), re-introduce a trait here and inject it
//! through `RuntimeContext`.

use std::io;

/// Error type for DNS resolution operations.
///
/// This enum covers all possible failure modes for DNS resolution.
/// It is used by `tcp.rs`'s `ConnectError::DnsFailed` variant.
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

use std::time::Duration;
