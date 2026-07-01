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

/// Configuration options for TLS connections.
///
/// This struct controls various aspects of TLS behavior including
/// certificate verification, protocol versions, and client authentication.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Certificate verification mode.
    ///
    /// - `CheckCertMode::On` - Verify certificates (default)
    /// - `CheckCertMode::Off` - Skip verification (insecure)
    pub check_certificate: CheckCertMode,

    /// Path to a custom CA certificate file.
    ///
    /// If set, this CA certificate will be used to verify server certificates
    /// instead of the system's default CA store.
    pub ca_cert: Option<PathBuf>,

    /// Path to the client certificate file.
    ///
    /// Required for mutual TLS (mTLS) authentication.
    pub cert_file: Option<PathBuf>,

    /// Path to the client private key file.
    ///
    /// Required for mutual TLS (mTLS) authentication.
    pub private_key: Option<PathBuf>,

    /// Path to a directory containing CA certificates.
    ///
    /// All `.pem`, `.crt`, and `.cer` files in this directory will be loaded
    /// as trusted CA certificates.
    pub ca_directory: Option<PathBuf>,

    /// Minimum/maximum TLS protocol version.
    ///
    /// - `SecureProtocol::Auto` - Use default (TLS 1.2 and 1.3)
    /// - `SecureProtocol::TlsV1_2` - Use only TLS 1.2
    /// - `SecureProtocol::TlsV1_3` - Use only TLS 1.3
    /// - `SecureProtocol::Pfs` - Use protocols with perfect forward secrecy
    pub secure_protocol: SecureProtocol,

    /// Custom cipher suite specification.
    ///
    /// If set, restricts the cipher suites used for the connection.
    /// The format is implementation-specific.
    pub ciphers: Option<String>,
}

impl Default for TlsConfig {
    /// Creates a default TLS configuration.
    ///
    /// Default settings:
    /// - Certificate verification: enabled
    /// - Protocol: auto (TLS 1.2 and 1.3)
    /// - No custom CA, client cert, or cipher suites
    fn default() -> Self {
        Self {
            check_certificate: CheckCertMode::On,
            ca_cert: None,
            cert_file: None,
            private_key: None,
            ca_directory: None,
            secure_protocol: SecureProtocol::Auto,
            ciphers: None,
        }
    }
}
