//! rustls-based TLS implementation.
//!
//! This module provides a TLS connector implementation using the `rustls` library.
//! It supports:
//!
//! - TLS 1.2 and TLS 1.3
//! - Certificate verification with system or custom CA certificates
//! - Client certificate authentication (mTLS)
//! - Skipping certificate verification (insecure, for testing)
//!
//! # Security Considerations
//!
//! By default, server certificates are verified against the system's trusted
//! CA certificates. Use `CheckCertMode::Off` to disable verification only
//! for testing purposes.

use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};

use super::{TlsConfig, TlsConnector, TlsError, CheckCertMode};
use crate::transport::{Interest, TcpTransport, Transport};
use ut_core::SecureProtocol;

/// TLS connector using the rustls library.
///
/// This is the primary TLS implementation for the net module. It provides
/// a secure, modern TLS implementation with support for TLS 1.2 and 1.3.
///
/// # Example
///
/// ```ignore
/// use utwget_net::tls::{TlsConnector, TlsConfig, RustlsConnector};
///
/// let connector = RustlsConnector::new();
/// let config = TlsConfig::default();
/// let tls_transport = connector.connect(tcp_transport, "example.com", 443, &config)?;
/// ```
pub struct RustlsConnector;

impl RustlsConnector {
    /// Creates a new rustls-based TLS connector.
    ///
    /// # Example
    ///
    /// ```
    /// use utwget_net::tls::rustls_impl::RustlsConnector;
    ///
    /// let connector = RustlsConnector::new();
    /// ```
    pub fn new() -> Self {
        Self
    }

    /// Builds a rustls `ClientConfig` from the given `TlsConfig`.
    ///
    /// This method:
    /// 1. Loads CA certificates from file or directory if specified
    /// 2. Falls back to system root certificates if no custom CAs
    /// 3. Loads client certificate and key for mTLS if specified
    /// 4. Configures protocol versions based on `secure_protocol`
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS configuration options.
    ///
    /// # Returns
    ///
    /// An `Arc<ClientConfig>` on success, or a `TlsError` on failure.
    fn build_config(config: &TlsConfig) -> Result<Arc<ClientConfig>, TlsError> {
        // Build root certificate store
        let mut root_store = RootCertStore::empty();
        let should_verify = config.check_certificate != CheckCertMode::Off;

        if should_verify {
            // Load CA certificates from file if specified
            if let Some(ref ca_cert_path) = config.ca_cert {
                let certs = load_certs_from_file(ca_cert_path)?;
                for cert in certs {
                    root_store.add(cert).map_err(|e| TlsError::CertError(e.to_string()))?;
                }
            }

            // Load CA certificates from directory if specified
            if let Some(ref ca_dir) = config.ca_directory {
                load_certs_from_dir(ca_dir, &mut root_store)?;
            }

            // Use system root certificates if none specified
            if root_store.is_empty() {
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
        }

        // Load client certificate and private key if specified
        let client_auth = match (&config.cert_file, &config.private_key) {
            (Some(cert_path), Some(key_path)) => {
                let certs = load_certs_from_file(cert_path)?;
                let key = load_private_key_from_file(key_path)?;
                Some((certs, key))
            }
            _ => None,
        };

        // Build client config based on secure protocol setting
        let client_config = match config.secure_protocol {
            SecureProtocol::TlsV1_2 => {
                Self::build_config_with_versions(&root_store, should_verify, client_auth, &[&rustls::version::TLS12])?
            }
            SecureProtocol::TlsV1_3 => {
                Self::build_config_with_versions(&root_store, should_verify, client_auth, &[&rustls::version::TLS13])?
            }
            SecureProtocol::Auto | SecureProtocol::Pfs => {
                Self::build_config_with_versions(&root_store, should_verify, client_auth, rustls::ALL_VERSIONS)?
            }
        };

        Ok(Arc::new(client_config))
    }

    /// Builds a `ClientConfig` with specific protocol versions.
    ///
    /// # Arguments
    ///
    /// * `root_store` - The root certificate store for verification.
    /// * `should_verify` - Whether to verify server certificates.
    /// * `client_auth` - Optional client certificate and key for mTLS.
    /// * `versions` - The TLS protocol versions to support.
    ///
    /// # Returns
    ///
    /// A `ClientConfig` on success, or a `TlsError` on failure.
    fn build_config_with_versions(
        root_store: &RootCertStore,
        should_verify: bool,
        client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Result<ClientConfig, TlsError> {
        let cfg = if !should_verify {
            // Skip certificate verification
            let verifier: Arc<dyn ServerCertVerifier> = Arc::new(SkipServerVerification);
            ClientConfig::builder_with_protocol_versions(versions)
                .dangerous()
                .with_custom_certificate_verifier(verifier)
        } else {
            ClientConfig::builder_with_protocol_versions(versions)
                .with_root_certificates(root_store.clone())
        };

        match client_auth {
            Some((certs, key)) => cfg.with_client_auth_cert(certs, key)
                .map_err(|e| TlsError::CertError(e.to_string())),
            None => Ok(cfg.with_no_client_auth()),
        }
    }
}

impl TlsConnector for RustlsConnector {
    /// Establishes a TLS connection over an existing TCP transport.
    ///
    /// This method:
    /// 1. Extracts the underlying `TcpStream` from the transport
    /// 2. Builds a rustls client configuration
    /// 3. Creates a TLS connection with SNI
    /// 4. Performs the TLS handshake
    ///
    /// # Arguments
    ///
    /// * `tcp` - The TCP transport to upgrade to TLS.
    /// * `host` - The hostname for SNI (Server Name Indication).
    /// * `_port` - The port number (currently unused, for future use).
    /// * `config` - TLS configuration options.
    ///
    /// # Returns
    ///
    /// A TLS transport on success, or a `TlsError` on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The transport is not a `TcpTransport`
    /// - The TLS configuration is invalid
    /// - The hostname is not valid for SNI
    /// - The TLS handshake fails
    fn connect(
        &self,
        mut tcp: Box<dyn Transport<Error = io::Error>>,
        host: &str,
        _port: u16,
        config: &TlsConfig,
    ) -> Result<Box<dyn Transport<Error = TlsError>>, TlsError> {
        let tcp_transport = tcp
            .as_any_mut()
            .downcast_mut::<TcpTransport>()
            .ok_or_else(|| {
                TlsError::HandshakeFailed("expected TcpTransport for TLS upgrade".into())
            })?;

        let stream = tcp_transport
            .take_stream()
            .map_err(TlsError::Io)?;

        let client_config = Self::build_config(config)?;

        let server_name = ServerName::try_from(host)
            .map_err(|e| TlsError::HandshakeFailed(format!("invalid server name '{}': {}", host, e)))?
            .to_owned();

        let conn = ClientConnection::new(client_config, server_name)
            .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;

        let mut tls = TlsTransport {
            stream: Some(stream),
            conn: Some(conn),
            peek_buf: Vec::new(),
            alive: true,
        };

        tls.complete_handshake()?;

        Ok(Box::new(tls))
    }
}

/// Internal TLS transport implementation.
///
/// Wraps a TCP stream and rustls connection to provide a `Transport`
/// implementation for TLS connections.
struct TlsTransport {
    /// The underlying TCP stream.
    stream: Option<TcpStream>,
    /// The rustls client connection state.
    conn: Option<ClientConnection>,
    /// Buffer for peeked data.
    peek_buf: Vec<u8>,
    /// Whether the connection is still alive.
    alive: bool,
}

impl TlsTransport {
    /// Completes the TLS handshake.
    ///
    /// This method drives the handshake process by reading and writing
    /// TLS records until the handshake is complete.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful handshake, or a `TlsError` on failure.
    fn complete_handshake(&mut self) -> Result<(), TlsError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            TlsError::HandshakeFailed("stream not available".into())
        })?;
        let conn = self.conn.as_mut().ok_or_else(|| {
            TlsError::HandshakeFailed("connection not available".into())
        })?;

        loop {
            if conn.wants_write() {
                let _ = conn.write_tls(&mut *stream).map_err(TlsError::Io)?;
                continue;
            }

            if conn.wants_read() {
                match conn.read_tls(&mut *stream) {
                    Ok(0) => {
                        return Err(TlsError::HandshakeFailed(
                            "connection closed during TLS handshake".into(),
                        ))
                    }
                    Ok(_) => {}
                    Err(e) => return Err(TlsError::Io(e)),
                }
                conn.process_new_packets()
                    .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
                continue;
            }

            break;
        }

        Ok(())
    }
}
