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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};

use super::{TlsConfig, TlsConnector, TlsError, CheckCertMode};
use crate::transport::{Interest, TcpTransport, Transport};
use ut_core::SecureProtocol;

/// Process-wide cache of compiled TLS ClientConfig, keyed by config signature.
///
/// Building a ClientConfig is expensive (loads CA certs, parses keys), so we
/// cache the result keyed by the relevant config fields. This avoids rebuilding
/// the config on every TLS connection when the same TLS settings are reused.
///
/// The cache is bounded to prevent memory exhaustion from crafted configurations.
static CONFIG_CACHE: OnceLock<Mutex<std::collections::HashMap<String, Arc<ClientConfig>>>> = OnceLock::new();

/// Maximum number of cached TLS configurations.
const MAX_CONFIG_CACHE_SIZE: usize = 32;

fn config_cache() -> &'static Mutex<std::collections::HashMap<String, Arc<ClientConfig>>> {
    CONFIG_CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

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

    /// Returns a cached `Arc<ClientConfig>` for the given `TlsConfig`,
    /// building it on first use and reusing it for subsequent calls with
    /// the same effective configuration.
    ///
    /// This dramatically reduces TLS setup overhead when many connections
    /// reuse the same TLS settings (the common case).
    pub fn cached_config(config: &TlsConfig) -> Result<Arc<ClientConfig>, TlsError> {
        let key = Self::config_signature(config);
        let cache = config_cache();
        // Fast path: config already cached
        if let Ok(map) = cache.lock() {
            if let Some(c) = map.get(&key) {
                return Ok(Arc::clone(c));
            }
        }
        // Slow path: build and cache
        let built = Arc::new(Self::build_config(config)?);
        if let Ok(mut map) = cache.lock() {
            // Evict if at capacity to prevent unbounded memory growth
            if map.len() >= MAX_CONFIG_CACHE_SIZE {
                map.clear();
            }
            map.insert(key, built.clone());
        }
        Ok(built)
    }

    /// Builds a cache key string from the TLS config fields that affect the
    /// resulting `ClientConfig`.
    fn config_signature(config: &TlsConfig) -> String {
        format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            config.check_certificate,
            config.ca_cert,
            config.cert_file,
            config.private_key,
            config.ca_directory,
            config.secure_protocol,
            config.ciphers,
        )
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
    pub fn build_config(config: &TlsConfig) -> Result<ClientConfig, TlsError> {
        // Build root certificate store
        let mut root_store = RootCertStore::empty();
        let should_verify = config.check_certificate != CheckCertMode::Off;
        if !should_verify {
            log::warn!("TLS certificate verification is DISABLED (--no-check-certificate). \
                        This makes the connection vulnerable to man-in-the-middle attacks.");
        }

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

        Ok(client_config)
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

        let client_config = Self::cached_config(config)?;

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
            // Always flush any pending TLS records rustls wants to write (this
            // covers the ClientHello up front and the client Finished once the
            // server flight has been processed).
            if conn.wants_write() {
                let _ = conn.write_tls(&mut *stream).map_err(TlsError::Io)?;
                continue;
            }

            // Only read while the handshake is still in progress. Once rustls
            // reports `is_handshaking() == false` the handshake is complete; at
            // that point `wants_read()` may still be true (e.g. a TLS 1.3
            // NewSessionTicket or application data is pending on the socket),
            // but blocking here to drain it would deadlock — the server is now
            // waiting for our HTTP request, not sending more handshake data.
            // Any such leftover bytes are left for `TlsTransport::read` to
            // consume on demand.
            if conn.is_handshaking() && conn.wants_read() {
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

impl Transport for TlsTransport {
    type Error = TlsError;

    /// Reads decrypted application data from the TLS connection.
    ///
    /// If there's data in the peek buffer, it's returned first. Otherwise the
    /// implementation loops over `read_tls` / `process_new_packets` until either
    /// decrypted application data is available to return, or the underlying TCP
    /// connection reaches a clean end (returning `Ok(0)` only in that case).
    ///
    /// This is required because a single TLS record may carry non-application
    /// data (handshake/ alert fragments) and `ClientConnection::reader()` yields
    /// `0` when no plaintext is currently buffered *without* meaning EOF. Returning
    /// `0` prematurely would be misread by callers as end-of-stream, truncating
    /// responses. The loop guarantees we only report `0` on a real TCP close.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read data into.
    ///
    /// # Returns
    ///
    /// The number of bytes read on success, or a `TlsError` on failure.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if !self.peek_buf.is_empty() {
            let n = self.peek_buf.len().min(buf.len());
            buf[..n].copy_from_slice(&self.peek_buf[..n]);
            self.peek_buf.drain(..n);
            return Ok(n);
        }

        let stream = self.stream.as_mut().ok_or_else(|| {
            TlsError::HandshakeFailed("stream not available".into())
        })?;
        let conn = self.conn.as_mut().ok_or_else(|| {
            TlsError::HandshakeFailed("connection not available".into())
        })?;

        loop {
            // Deliver any already-decrypted application data. rustls reports
            // "no plaintext currently buffered, connection still open" either as
            // `Ok(0)` or as an `UnexpectedEof`/`WouldBlock` error depending on
            // version — neither is a real EOF here, so we treat both as "need to
            // pull more TLS records" and only propagate genuine I/O errors.
            let n = {
                let mut reader = conn.reader();
                match reader.read(buf) {
                    Ok(n) => n,
                    Err(e)
                        if e.kind() == io::ErrorKind::UnexpectedEof
                            || e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        0
                    }
                    Err(e) => return Err(TlsError::Io(e)),
                }
            };
            if n > 0 {
                return Ok(n);
            }

            // No plaintext ready: pull more TLS records off the wire. A return of
            // 0 here means the TCP side is closed, which is the only legitimate
            // EOF condition (covers clean close_notify as well, since rustls
            // surfaces that as 0 from the reader only after draining).
            match conn.read_tls(&mut *stream) {
                Ok(0) => return Ok(0),
                Ok(_) => {}
                Err(e) => return Err(TlsError::Io(e)),
            }
            conn.process_new_packets()
                .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
        }
    }

    /// Writes data to the TLS connection.
    ///
    /// Data is encrypted and written to the underlying TCP stream.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data to write.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a `TlsError` on failure.
    fn write(&mut self, buf: &[u8]) -> Result<(), TlsError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            TlsError::HandshakeFailed("stream not available".into())
        })?;
        let conn = self.conn.as_mut().ok_or_else(|| {
            TlsError::HandshakeFailed("connection not available".into())
        })?;

        {
            let mut writer = conn.writer();
            writer.write_all(buf).map_err(TlsError::Io)?;
            writer.flush().map_err(TlsError::Io)?;
        }

        loop {
            if conn.wants_write() {
                let _ = conn.write_tls(&mut *stream).map_err(TlsError::Io)?;
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Polls the connection for readiness.
    ///
    /// Checks whether the underlying TCP stream is ready for
    /// reading or writing.
    ///
    /// # Arguments
    ///
    /// * `interest` - What operations to check for.
    /// * `timeout` - Maximum time to wait.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if ready, `Ok(false)` if timeout, or an error.
    fn poll_ready(&mut self, interest: Interest, timeout: Duration) -> Result<bool, TlsError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            TlsError::HandshakeFailed("stream not available".into())
        })?;

        #[cfg(unix)]
        {
            let fd = stream.as_raw_fd();
            stream.set_nonblocking(true).map_err(TlsError::Io)?;
            let result = crate::transport::poll_fd(fd, interest, timeout);
            let _ = stream.set_nonblocking(false);
            return result.map_err(TlsError::Io);
        }

        #[cfg(not(unix))]
        {
            // Non-unix fallback: try non-blocking peek to check readiness.
            // This is less efficient than poll(2) but correct.
            stream.set_nonblocking(true).map_err(TlsError::Io)?;
            let deadline = std::time::Instant::now() + timeout;
            let result = loop {
                if interest.readable {
                    let mut buf = [0u8; 1];
                    match stream.peek(&mut buf) {
                        Ok(_) => break Ok(true),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => break Err(TlsError::Io(e)),
                    }
                }
                if interest.writable {
                    // For write readiness, try a zero-byte write check
                    // by checking if the stream is in a writable state
                    break Ok(true);
                }
                if std::time::Instant::now() >= deadline {
                    break Ok(false);
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let _ = stream.set_nonblocking(false);
            return result;
        }
    }

    /// Peeks data from the TLS connection without consuming it.
    ///
    /// This is implemented by reading data into an internal buffer
    /// and returning it on subsequent reads.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to peek data into.
    ///
    /// # Returns
    ///
    /// The number of bytes peeked on success, or a `TlsError` on failure.
    fn peek(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if !self.peek_buf.is_empty() {
            let n = self.peek_buf.len().min(buf.len());
            buf[..n].copy_from_slice(&self.peek_buf[..n]);
            return Ok(n);
        }

        let mut temp_buf = vec![0u8; buf.len()];
        let n = self.read(&mut temp_buf)?;
        self.peek_buf.extend_from_slice(&temp_buf[..n]);
        buf[..n].copy_from_slice(&temp_buf[..n]);
        Ok(n)
    }

    /// Closes the TLS connection.
    ///
    /// Sends a close notify alert and shuts down the underlying stream.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a `TlsError` on failure.
    fn close(&mut self) -> Result<(), TlsError> {
        if let Some(mut conn) = self.conn.take() {
            conn.send_close_notify();
            if conn.wants_write() {
                if let Some(stream) = self.stream.as_mut() {
                    if let Err(e) = conn.write_tls(&mut *stream) {
                        log::debug!("TLS write_tls during close failed: {}", e);
                    }
                    if let Err(e) = stream.shutdown(std::net::Shutdown::Both) {
                        log::debug!("TLS stream shutdown failed: {}", e);
                    }
                }
            }
        } else if let Some(stream) = self.stream.take() {
            if let Err(e) = stream.shutdown(std::net::Shutdown::Both) {
                log::debug!("TLS stream shutdown failed: {}", e);
            }
        }
        self.alive = false;
        Ok(())
    }

    /// Checks if the connection is still alive.
    ///
    /// # Returns
    ///
    /// `true` if the connection is alive, `false` otherwise.
    fn is_alive(&self) -> bool {
        self.alive && self.conn.is_some()
    }

    /// Returns a reference to the transport as `Any`.
    ///
    /// Used for downcasting to concrete types.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Returns a mutable reference to the transport as `Any`.
    ///
    /// Used for downcasting to concrete types.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport")
            .field("alive", &self.alive)
            .field("has_conn", &self.conn.is_some())
            .finish()
    }
}

/// Loads certificates from a PEM file.
///
/// # Arguments
///
/// * `path` - Path to the PEM file containing certificates.
///
/// # Returns
///
/// A vector of certificates on success, or a `TlsError` on failure.
fn load_certs_from_file(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let data = std::fs::read(path).map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?;
    let certs = rustls_pemfile::certs(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?;

    if certs.is_empty() {
        return Err(TlsError::InvalidCertFile(path.to_path_buf()));
    }

    Ok(certs.into_iter().map(|c| c.to_owned()).collect())
}

/// Loads certificates from a directory.
///
/// Scans the directory for `.pem`, `.crt`, and `.cer` files and
/// adds them to the root certificate store.
///
/// # Arguments
///
/// * `dir` - Path to the directory containing certificate files.
/// * `root_store` - The root certificate store to add certificates to.
///
/// # Returns
///
/// `Ok(())` on success, or a `TlsError` on failure.
fn load_certs_from_dir(dir: &std::path::Path, root_store: &mut RootCertStore) -> Result<(), TlsError> {
    if !dir.is_dir() {
        return Err(TlsError::InvalidCertFile(dir.to_path_buf()));
    }

    for entry in std::fs::read_dir(dir).map_err(|_| TlsError::InvalidCertFile(dir.to_path_buf()))? {
        let entry = entry.map_err(|_| TlsError::InvalidCertFile(dir.to_path_buf()))?;
        let path = entry.path();

        // Only process .pem, .crt, .cer files
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase());
        if !matches!(ext.as_deref(), Some("pem") | Some("crt") | Some("cer")) {
            continue;
        }

        match load_certs_from_file(&path) {
            Ok(certs) => {
                for cert in certs {
                    if let Err(e) = root_store.add(cert) {
                        log::warn!("Failed to add certificate from {}: {}", path.display(), e);
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to load certificates from {}: {}", path.display(), e);
            }
        }
    }

    Ok(())
}

/// Loads a private key from a file.
///
/// Tries to load the key in the following formats:
/// 1. PKCS#8 (recommended)
/// 2. RSA (PKCS#1)
/// 3. EC (SEC1)
///
/// # Arguments
///
/// * `path` - Path to the private key file.
///
/// # Returns
///
/// The private key on success, or a `TlsError` on failure.
fn load_private_key_from_file(path: &std::path::Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let data = std::fs::read(path).map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?;

    // Try PKCS8 private key first
    if let Some(key) = rustls_pemfile::private_key(&mut data.as_slice())
        .map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?
    {
        return Ok(key);
    }

    // Try RSA private key
    let rsa_keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?;

    if let Some(key) = rsa_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    // Try EC private key
    let ec_keys: Vec<_> = rustls_pemfile::ec_private_keys(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?;

    if let Some(key) = ec_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    Err(TlsError::InvalidCertFile(path.to_path_buf()))
}

/// A certificate verifier that skips all verification.
///
/// **WARNING**: This is insecure and should only be used for testing.
/// It accepts any server certificate without verification.
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    /// Verifies the server certificate (always succeeds).
    ///
    /// **WARNING**: This implementation always returns success,
    /// effectively skipping all certificate verification.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// Verifies a TLS 1.2 signature (always succeeds).
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Verifies a TLS 1.3 signature (always succeeds).
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Returns the supported signature schemes.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
