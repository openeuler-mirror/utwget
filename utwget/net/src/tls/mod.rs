//! TLS/SSL support module.
//!
//! This module provides TLS (Transport Layer Security) capabilities for
//! secure connections. It supports:
//!
//! - TLS 1.2 and TLS 1.3 protocols
//! - Certificate verification with custom CA certificates
//! - Client certificate authentication
//! - Skipping certificate verification (insecure, for testing)
//!
//! # Feature Flags
//!
//! - `tls-rustls` (default): Uses the `rustls` library for TLS implementation.
//!
//! # Example
//!
//! ```ignore
//! use utwget_net::tls::{TlsConnector, TlsConfig, RustlsConnector};
//!
//! let connector = RustlsConnector::new();
//! let config = TlsConfig::default();
//!
//! // Connect with TLS
//! let tls_transport = connector.connect(tcp_transport, "example.com", 443, &config)?;
//! ```

use std::path::PathBuf;

pub use ut_core::error::TlsError;
use ut_core::{CheckCertMode, SecureProtocol};

pub mod rustls_impl;

/// Trait for TLS connector implementations.
///
/// Implementations of this trait can establish TLS connections over
/// an existing TCP transport.
///
/// # Type Safety
///
/// The trait takes a `Box<dyn Transport<Error = io::Error>>` and returns
/// a `Box<dyn Transport<Error = TlsError>>`, ensuring type-safe error
/// handling for TLS operations.
pub trait TlsConnector: Send + Sync {
    /// Establishes a TLS connection over an existing TCP transport.
    ///
    /// # Arguments
    ///
    /// * `tcp` - The underlying TCP transport to upgrade.
    /// * `host` - The hostname for SNI (Server Name Indication).
    /// * `port` - The port number (for logging/debugging).
    /// * `config` - TLS configuration options.
    ///
    /// # Returns
    ///
    /// A TLS transport on success, or a `TlsError` on failure.
    fn connect(
        &self,
        tcp: Box<dyn crate::transport::Transport<Error = std::io::Error>>,
        host: &str,
        port: u16,
        config: &TlsConfig,
    ) -> Result<Box<dyn crate::transport::Transport<Error = TlsError>>, TlsError>;
}
