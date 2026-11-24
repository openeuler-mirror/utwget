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
use ut_core::types::KeyFileType;
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
/// use ut_net::tls::{TlsConnector, TlsConfig, RustlsConnector};
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
    /// use ut_net::tls::rustls_impl::RustlsConnector;
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
        // --ciphers 选项：解析 OpenSSL/GnuTLS 风格的 cipher 字符串为 rustls
        // cipher suite 列表。支持的格式：
        // - IANA 名称: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        // - OpenSSL 短名: AES256-GCM-SHA384
        // - 通配符: ALL, HIGH
        // 用户传入的字符串按逗号/冒号分隔，每个名称映射到 rustls ALL_CIPHER_SUITES
        // 中的对应项。不认识的名称跳过并 warn。
        let custom_cipher_suites: Option<Vec<rustls::SupportedCipherSuite>> = config.ciphers.as_ref().map(|c| {
            parse_cipher_list(c)
        });

        if let Some(ref suites) = custom_cipher_suites {
            if suites.is_empty() {
                log::warn!("--ciphers=\"{}\" matched no known cipher suites; falling back to default", config.ciphers.as_ref().unwrap());
            } else {
                log::info!("--ciphers matched {} cipher suite(s): {:?}",
                    suites.len(),
                    suites.iter().map(|s| s.suite()).collect::<Vec<_>>());
            }
        }

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
                let certs = load_certs_from_file(ca_cert_path, KeyFileType::Pem)?;
                for cert in certs {
                    root_store.add(cert).map_err(|e| TlsError::CertError(e.to_string()))?;
                }
            }

            // Load CA certificates from directory if specified
            if let Some(ref ca_dir) = config.ca_directory {
                load_certs_from_dir(ca_dir, &mut root_store)?;
            }

            // Load system root certificates when no custom CA is specified.
            // Try the OS native trust store first (matches GNU wget's
            // GnuTLS behavior of using the system CA bundle), falling back
            // to the bundled Mozilla root list if native certs are
            // unavailable (e.g. minimal containers).
            if root_store.is_empty() {
                let result = rustls_native_certs::load_native_certs();
                if !result.errors.is_empty() {
                    log::warn!("failed to load some native root certs: {} errors", result.errors.len());
                }
                for cert in &result.certs {
                    root_store.add(cert.clone()).ok();
                }
                if root_store.is_empty() {
                    log::warn!("no native root certs found; falling back to Mozilla roots");
                    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                }
            }
        }

        // Load client certificate and private key if specified
        let client_auth = match (&config.cert_file, &config.private_key) {
            (Some(cert_path), Some(key_path)) => {
                let certs = load_certs_from_file(cert_path, config.cert_type)?;
                let key = load_private_key_from_file(key_path, config.private_key_type)?;
                Some((certs, key))
            }
            _ => None,
        };

        // Load CRL file if --crl-file is specified.
        // CRLs (Certificate Revocation Lists) allow the client to reject
        // certificates that have been revoked by the CA before their expiry.
        // Supports both PEM (-----BEGIN X509 CRL-----) and DER formats.
        let crls: Vec<rustls::pki_types::CertificateRevocationListDer<'static>> = if let Some(ref crl_path) = config.crl_file {
            match load_crls_from_file(crl_path) {
                Ok(c) => {
                    log::info!("loaded {} CRL(s) from {}", c.len(), crl_path.display());
                    c
                }
                Err(e) => {
                    return Err(TlsError::CertError(format!(
                        "failed to load CRL file {}: {}", crl_path.display(), e
                    )));
                }
            }
        } else {
            Vec::new()
        };

        // Build client config based on secure protocol setting
        let suites_ref = custom_cipher_suites.as_deref();
        let crls_ref = if crls.is_empty() { None } else { Some(&crls[..]) };
        // Parse --pinnedpubkey into SHA-256 hash digests
        let pinned_pins: Vec<Vec<u8>> = config.pinned_pubkey
            .as_ref()
            .map(|s| parse_pinnedpubkey(s))
            .unwrap_or_default();
        let pinned_ref = if pinned_pins.is_empty() { None } else { Some(&pinned_pins[..]) };
        let client_config = match config.secure_protocol {
            SecureProtocol::TlsV1_2 => {
                Self::build_config_with_versions(&root_store, should_verify, client_auth, &[&rustls::version::TLS12], suites_ref, crls_ref, pinned_ref)?
            }
            SecureProtocol::TlsV1_3 => {
                Self::build_config_with_versions(&root_store, should_verify, client_auth, &[&rustls::version::TLS13], suites_ref, crls_ref, pinned_ref)?
            }
            SecureProtocol::Auto => {
                Self::build_config_with_versions(&root_store, should_verify, client_auth, rustls::ALL_VERSIONS, suites_ref, crls_ref, pinned_ref)?
            }
            SecureProtocol::Pfs => {
                let mut config = Self::build_config_with_versions(
                    &root_store, should_verify, client_auth, rustls::ALL_VERSIONS, suites_ref, crls_ref, pinned_ref)?;
                config.resumption = rustls::client::Resumption::disabled();
                config
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
        custom_suites: Option<&[rustls::SupportedCipherSuite]>,
        crls: Option<&[rustls::pki_types::CertificateRevocationListDer<'static>]>,
        pinned_pins: Option<&[Vec<u8>]>,
    ) -> Result<ClientConfig, TlsError> {
        // Helper: wrap a verifier with PinnedPubKeyVerifier if pinned_pins is set.
        let wrap_verifier = |verifier: Arc<dyn ServerCertVerifier>| -> Arc<dyn ServerCertVerifier> {
            if let Some(pins) = pinned_pins {
                if !pins.is_empty() {
                    return Arc::new(PinnedPubKeyVerifier {
                        inner: verifier,
                        pins: pins.to_vec(),
                    });
                }
            }
            verifier
        };

        // 如果用户通过 --ciphers 指定了 cipher suite 列表，用自定义 CryptoProvider。
        // 否则使用默认 provider（包含 ring 的全部 cipher suite）。
        if let Some(suites) = custom_suites {
            if !suites.is_empty() {
                // 构造自定义 CryptoProvider：ring 默认 provider 但 cipher_suites 被过滤
                let provider = Arc::new(rustls::crypto::CryptoProvider {
                    cipher_suites: suites.to_vec(),
                    ..rustls::crypto::ring::default_provider()
                });
                let cfg = if !should_verify {
                    let verifier: Arc<dyn ServerCertVerifier> = wrap_verifier(Arc::new(SkipServerVerification));
                    ClientConfig::builder_with_provider(provider)
                        .with_protocol_versions(versions)
                        .map_err(|e| TlsError::HandshakeFailed(format!("protocol version error: {}", e)))?
                        .dangerous()
                        .with_custom_certificate_verifier(verifier)
                } else if let Some(crl_list) = crls {
                    // 有 CRL 时，用 WebPkiServerVerifier + with_crls 做吊销检查
                    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                        Arc::new(root_store.clone()),
                        provider.clone(),
                    )
                    .with_crls(crl_list.iter().cloned())
                    .build()
                    .map_err(|e| TlsError::CertError(format!("CRL verifier build error: {}", e)))?;
                    let verifier = wrap_verifier(verifier as Arc<dyn ServerCertVerifier>);
                    ClientConfig::builder_with_provider(provider)
                        .with_protocol_versions(versions)
                        .map_err(|e| TlsError::HandshakeFailed(format!("protocol version error: {}", e)))?
                        .dangerous()
                        .with_custom_certificate_verifier(verifier)
                } else {
                    // 无 CRL 但可能有 pinnedpubkey
                    if pinned_pins.is_some() {
                        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                            Arc::new(root_store.clone()),
                            provider.clone(),
                        )
                        .build()
                        .map_err(|e| TlsError::CertError(format!("verifier build error: {}", e)))?;
                        let verifier = wrap_verifier(verifier as Arc<dyn ServerCertVerifier>);
                        ClientConfig::builder_with_provider(provider)
                            .with_protocol_versions(versions)
                            .map_err(|e| TlsError::HandshakeFailed(format!("protocol version error: {}", e)))?
                            .dangerous()
                            .with_custom_certificate_verifier(verifier)
                    } else {
                        ClientConfig::builder_with_provider(provider)
                            .with_protocol_versions(versions)
                            .map_err(|e| TlsError::HandshakeFailed(format!("protocol version error: {}", e)))?
                            .with_root_certificates(root_store.clone())
                    }
                };

                return match client_auth {
                    Some((certs, key)) => cfg.with_client_auth_cert(certs, key)
                        .map_err(|e| TlsError::CertError(e.to_string())),
                    None => Ok(cfg.with_no_client_auth()),
                };
            }
        }

        // 默认路径（无 --ciphers 或匹配为空）
        let cfg = if !should_verify {
            let verifier: Arc<dyn ServerCertVerifier> = wrap_verifier(Arc::new(SkipServerVerification));
            ClientConfig::builder_with_protocol_versions(versions)
                .dangerous()
                .with_custom_certificate_verifier(verifier)
        } else if let Some(crl_list) = crls {
            // 有 CRL 时，用 WebPkiServerVerifier + with_crls 做吊销检查
            let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store.clone()))
                .with_crls(crl_list.iter().cloned())
                .build()
                .map_err(|e| TlsError::CertError(format!("CRL verifier build error: {}", e)))?;
            let verifier = wrap_verifier(verifier as Arc<dyn ServerCertVerifier>);
            ClientConfig::builder_with_protocol_versions(versions)
                .dangerous()
                .with_custom_certificate_verifier(verifier)
        } else if pinned_pins.is_some() {
            // 有 pinnedpubkey 但无 CRL
            let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store.clone()))
                .build()
                .map_err(|e| TlsError::CertError(format!("verifier build error: {}", e)))?;
            let verifier = wrap_verifier(verifier as Arc<dyn ServerCertVerifier>);
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
        if !self.alive || self.conn.is_none() || self.stream.is_none() {
            return false;
        }
        // Probe the underlying TCP socket: a non-blocking MSG_PEEK recv
        // returns 0 if the remote closed (EOF) or an error (ECONNRESET)
        // if the connection was reset. Either way the connection is dead.
        // If there is pending data (n > 0), the connection is alive.
        // EAGAIN/EWOULDBLOCK means no data but connection is still open.
        use std::os::unix::io::AsRawFd;
        let stream = self.stream.as_ref().unwrap();
        let fd = stream.as_raw_fd();
        unsafe {
            let mut buf = [0u8; 1];
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT);
            if n == 0 {
                // Remote closed
                return false;
            }
            if n < 0 {
                let errno = *libc::__errno_location();
                // EAGAIN or EWOULDBLOCK: connection still open, no data
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    return true;
                }
                // Any other error: connection is dead
                return false;
            }
            // n > 0: there's pending data, connection is alive
            true
        }
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

/// On drop, attempt a graceful TLS close_notify so the server sees a
/// clean shutdown rather than a TCP RST.  This matches `close()` but is
/// best-effort (errors are logged at debug level, never propagated).
impl Drop for TlsTransport {
    fn drop(&mut self) {
        if self.alive {
            let _ = self.close();
        }
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
fn load_certs_from_file(path: &std::path::Path, cert_type: KeyFileType) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    // Soft warning when client certificate file is world/group readable.
    // Certificates are public material; we still load it but warn the user.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 {
                log::warn!(
                    "certificate file {} has permissive permissions (mode {:o}); \
                     recommend 0644 or stricter",
                    path.display(),
                    mode & 0o777,
                );
            }
        }
    }

    let data = std::fs::read(path).map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?;

    if cert_type == KeyFileType::Der || cert_type == KeyFileType::Asn1 {
        return Ok(vec![CertificateDer::from(data)]);
    }

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

        match load_certs_from_file(&path, KeyFileType::Pem) {
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
fn load_private_key_from_file(path: &std::path::Path, key_type: KeyFileType) -> Result<PrivateKeyDer<'static>, TlsError> {
    // SSH-style permission check: refuse private keys readable by group/other.
    // This prevents accidentally using a key copied from a shared mount with
    // mode 0644. mode & 0o077 must be 0 (only owner has access).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(TlsError::InsecureKeyFile(path.to_path_buf()));
        }
    }

    let data = std::fs::read(path).map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?;

    if key_type == KeyFileType::Der || key_type == KeyFileType::Asn1 {
        if data.is_empty() {
            return Err(TlsError::InvalidCertFile(path.to_path_buf()));
        }
        return Ok(PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(data),
        ));
    }

    if let Some(key) = rustls_pemfile::private_key(&mut data.as_slice())
        .map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?
    {
        return Ok(key);
    }

    let rsa_keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::InvalidCertFile(path.to_path_buf()))?;

    if let Some(key) = rsa_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

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

/// A certificate verifier that enforces public-key pinning (--pinnedpubkey).
///
/// Wraps an inner verifier (either the standard `WebPkiServerVerifier` or
/// `SkipServerVerification`). After the inner verifier runs, this verifier
/// additionally checks that the SHA-256 hash of the server's public key
/// (SubjectPublicKeyInfo) matches one of the pinned hashes.
///
/// Format: `sha256//<base64-hash>` (matching curl/wget --pinnedpubkey syntax).
/// Multiple pins separated by `;`.
struct PinnedPubKeyVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    /// Pinned SHA-256 hashes (raw 32-byte digests, base64-decoded).
    pins: Vec<Vec<u8>>,
}

impl std::fmt::Debug for PinnedPubKeyVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedPubKeyVerifier")
            .field("pins_count", &self.pins.len())
            .finish()
    }
}

impl ServerCertVerifier for PinnedPubKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // First, let the inner verifier do its job (chain validation, etc.)
        let verified = self.inner.verify_server_cert(
            end_entity, intermediates, server_name, ocsp_response, now,
        )?;

        // Then, check public key pinning.
        let spki = extract_spki(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("pinnedpubkey: failed to extract SubjectPublicKeyInfo".into())
        })?;
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(spki);

        for pin in &self.pins {
            if pin == hash.as_slice() {
                return Ok(verified);
            }
        }

        Err(rustls::Error::General(
            "pinnedpubkey: server public key does not match any pinned hash".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Parse a --pinnedpubkey string into a list of SHA-256 hash digests.
///
/// Format: `sha256//<base64>` (matching curl/wget). Multiple pins
/// separated by `;`. Returns an empty vec if no valid pins found.
fn parse_pinnedpubkey(s: &str) -> Vec<Vec<u8>> {
    let mut pins = Vec::new();
    for entry in s.split(';') {
        let entry = entry.trim();
        if let Some(rest) = entry.strip_prefix("sha256//") {
            // base64 standard (with padding) or URL-safe
            let hash = base64_decode(rest);
            if hash.len() == 32 {
                pins.push(hash);
            } else {
                log::warn!("--pinnedpubkey: invalid sha256 hash length ({}), expected 32", hash.len());
            }
        } else {
            log::warn!("--pinnedpubkey: unsupported format '{}' (only sha256// is supported)", entry);
        }
    }
    pins
}

/// Base64 decoder supporting both standard and URL-safe alphabets.
fn base64_decode(s: &str) -> Vec<u8> {
    // Try standard base64 first, then URL-safe
    use base64::Engine;
    if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(s) {
        return v;
    }
    if let Ok(v) = base64::engine::general_purpose::URL_SAFE.decode(s) {
        return v;
    }
    Vec::new()
}

/// Extract the SubjectPublicKeyInfo (SPKI) from a DER-encoded X.509 certificate.
///
/// The SPKI is the raw DER bytes including the outer SEQUENCE tag, matching
/// what curl/wget hash for --pinnedpubkey. Uses a minimal DER walker.
fn extract_spki(cert_der: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;
    // Outer SEQUENCE (Certificate)
    let (_, body) = read_der_tlv(cert_der, &mut pos)?;
    // Inner SEQUENCE (TBSCertificate)
    let mut tbs_pos = 0;
    let (tbs_tag, tbs_body) = read_der_tlv(body, &mut tbs_pos)?;
    if tbs_tag != 0x30 { return None; } // must be SEQUENCE
    // Now walk through TBSCertificate fields:
    let mut field_pos = 0;
    // 1. version: [0] EXPLICIT (optional, context-specific tag 0xA0)
    let (_, _) = read_der_tlv(tbs_body, &mut field_pos)?;
    // Actually, version may or may not be present (context tag [0]).
    // Let's handle both cases: if first byte is 0xA0, skip version;
    // otherwise it's serialNumber.
    // Re-parse more carefully:
    let mut fp = 0;
    // Optional: version [0] (0xA0)
    if tbs_body.first() == Some(&0xA0) {
        let _ = read_der_tlv(tbs_body, &mut fp)?;
    }
    // serialNumber (INTEGER)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // signature (AlgorithmIdentifier SEQUENCE)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // issuer (SEQUENCE)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // validity (SEQUENCE)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // subject (SEQUENCE)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // Next field: SubjectPublicKeyInfo (SEQUENCE) - this is what we want
    let spki_start = fp;
    let (spki_tag, _) = read_der_tlv(tbs_body, &mut fp)?;
    if spki_tag != 0x30 { return None; } // must be SEQUENCE
    let spki_end = fp;
    Some(&tbs_body[spki_start..spki_end])
}

/// Read a DER Tag-Length-Value element, returning (tag_byte, value_slice)
/// and advancing `pos` past the entire TLV.
fn read_der_tlv<'a>(buf: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    if *pos >= buf.len() { return None; }
    let tag = buf[*pos];
    *pos += 1;
    if *pos >= buf.len() { return None; }
    let first_len_byte = buf[*pos];
    *pos += 1;
    let len = if first_len_byte & 0x80 == 0 {
        // Short form: length is the byte itself
        first_len_byte as usize
    } else {
        // Long form: lower 7 bits give number of subsequent length bytes
        let num_bytes = (first_len_byte & 0x7F) as usize;
        if num_bytes > 4 || *pos + num_bytes > buf.len() { return None; }
        let mut l = 0usize;
        for i in 0..num_bytes {
            l = (l << 8) | (buf[*pos + i] as usize);
        }
        *pos += num_bytes;
        l
    };
    if *pos + len > buf.len() { return None; }
    let value = &buf[*pos..*pos + len];
    *pos += len;
    Some((tag, value))
}
///
/// Supports the following formats (colon or comma separated):
///
/// - **IANA names**: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
/// - **OpenSSL short names**: `AES256-GCM-SHA384`
/// - **Keywords**: `ALL` (all available), `HIGH` (all AES/ChaCha suites)
///
/// Unknown names are silently skipped (with a debug log). The returned list
/// preserves the order of the input, matching the server's preference.
fn parse_cipher_list(ciphers: &str) -> Vec<rustls::SupportedCipherSuite> {
    use rustls::crypto::ring;

    // Build a lookup table mapping various cipher names to rustls suites.
    let all_suites = ring::ALL_CIPHER_SUITES;

    let mut result: Vec<rustls::SupportedCipherSuite> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for token in ciphers.split(|c| c == ':' || c == ',') {
        let token = token.trim().to_uppercase();
        if token.is_empty() {
            continue;
        }

        // Handle keywords
        match token.as_str() {
            "ALL" => {
                for suite in all_suites {
                    let key = format!("{:?}", suite.suite());
                    if seen.insert(key) {
                        result.push(*suite);
                    }
                }
                continue;
            }
            "HIGH" => {
                // HIGH = all AEAD suites (AES-GCM, ChaCha20-Poly1305)
                for suite in all_suites {
                    let name = format!("{:?}", suite.suite());
                    if (name.contains("GCM") || name.contains("CHACHA20"))
                        && seen.insert(name.clone())
                    {
                        result.push(*suite);
                    }
                }
                continue;
            }
            _ => {}
        }

        // Match by IANA name or OpenSSL short name
        let matched = all_suites.iter().find(|suite| {
            let iana = format!("{:?}", suite.suite());
            // IANA name match (case-insensitive)
            if iana.eq_ignore_ascii_case(&token) {
                return true;
            }
            // OpenSSL short name mapping
            let openssl = iana_to_openssl(&iana);
            if openssl.eq_ignore_ascii_case(&token) {
                return true;
            }
            false
        });

        if let Some(suite) = matched {
            let key = format!("{:?}", suite.suite());
            if seen.insert(key) {
                result.push(*suite);
            }
        } else {
            log::debug!("--ciphers: unknown cipher \"{}\" (skipped)", token);
        }
    }

    result
}

/// Map IANA cipher suite name to OpenSSL short name.
fn iana_to_openssl(iana: &str) -> String {
    // Common mappings: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 -> AES256-GCM-SHA384
    // This is a simplified mapping for the most common suites.
    match iana {
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" | "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => "AES256-GCM-SHA384".into(),
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" | "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => "AES128-GCM-SHA256".into(),
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => "CHACHA20-POLY1305".into(),
        "TLS13_AES_256_GCM_SHA384" => "TLS_AES_256_GCM_SHA384".into(),
        "TLS13_AES_128_GCM_SHA256" => "TLS_AES_128_GCM_SHA256".into(),
        "TLS13_CHACHA20_POLY1305_SHA256" => "TLS_CHACHA20_POLY1305_SHA256".into(),
        _ => iana.to_string(),
    }
}

/// Load CRLs (Certificate Revocation Lists) from a file.
///
/// Supports both PEM (-----BEGIN X509 CRL-----) and DER formats.
/// A PEM file may contain multiple CRLs; a DER file contains exactly one.
///
/// # Arguments
///
/// * `path` - Path to the CRL file.
///
/// # Returns
///
/// A vector of `CertificateRevocationListDer` on success.
fn load_crls_from_file(path: &std::path::Path) -> Result<Vec<rustls::pki_types::CertificateRevocationListDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;

    // Check if the file is PEM (ASCII armor) or DER (binary).
    let is_pem = data.windows(5).any(|w| w == b"-----");
    if is_pem {
        // Parse PEM using rustls_pemfile::crls()
        let cursor = std::io::Cursor::new(&data);
        let mut buf_reader = std::io::BufReader::new(cursor);
        let mut crls = Vec::new();
        for item in rustls_pemfile::crls(&mut buf_reader) {
            match item {
                Ok(crl) => crls.push(crl),
                Err(e) => {
                    log::warn!("skipping unparseable CRL block in {}: {}", path.display(), e);
                }
            }
        }
        if crls.is_empty() {
            return Err(format!("no valid CRLs found in PEM file {}", path.display()));
        }
        Ok(crls)
    } else {
        // DER format: single CRL
        Ok(vec![rustls::pki_types::CertificateRevocationListDer::from(data)])
    }
}
