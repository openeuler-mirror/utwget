//! FTPS (FTP over TLS/SSL) implementation
//!
//! Supports both explicit and implicit FTPS:
//! - Explicit FTPS: Connect to standard FTP port (21), then upgrade with AUTH TLS
//! - Implicit FTPS: Connect directly to TLS port (990) with TLS handshake

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::command::FtpResponse;
use crate::client::{FtpError, validate_ftp_input};
use ut_core::types::SecureProtocol;

/// FTPS configuration
#[derive(Debug, Clone)]
pub struct FtpsConfig {
    /// Whether to verify server certificate
    pub verify_certificate: bool,
    /// Path to CA certificate file
    pub ca_cert: Option<std::path::PathBuf>,
    /// Path to client certificate file
    pub client_cert: Option<std::path::PathBuf>,
    /// Path to client private key file
    pub client_key: Option<std::path::PathBuf>,
    /// Whether to require TLS for data connection
    pub require_data_tls: bool,
    /// Minimum/maximum TLS protocol version (mirrors --secure-protocol).
    pub secure_protocol: SecureProtocol,
}

impl Default for FtpsConfig {
    fn default() -> Self {
        Self {
            verify_certificate: true,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            require_data_tls: false,
            secure_protocol: SecureProtocol::Auto,
        }
    }
}

/// Try to parse a complete FTP response (RFC 959) from a byte buffer.
///
/// Returns `Some((response, consumed))` if the buffer contains a full
/// response (single- or multi-line), where `consumed` is the number of
/// bytes that make up the response. Returns `None` if more data is needed.
///
/// - Single-line: `"NNN text\r\n"`
/// - Multi-line: `"NNN-text\r\n...NNN text\r\n"` where intermediate lines use
///   `NNN-` and the final line uses `NNN ` (code + space).
fn parse_complete_response(data: &[u8]) -> Option<(FtpResponse, usize)> {
    let s = std::str::from_utf8(data).ok()?;
    let first_line_end = s.find('\n')?;
    let first_line = s[..first_line_end].trim_end_matches('\r');
    if first_line.len() < 3 {
        return None;
    }
    let code: u16 = first_line[..3].parse().ok()?;

    let classify = |code: u16| -> (bool, bool, bool, bool, bool) {
        (
            code >= 100 && code < 200,
            code >= 200 && code < 300,
            code >= 300 && code < 400,
            code >= 400 && code < 500,
            code >= 500 && code < 600,
        )
    };

    // Single-line response: "NNN ..." (no '-' after code, or line too short)
    if first_line.len() < 4 || first_line.as_bytes()[3] != b'-' {
        let text = if first_line.len() > 4 {
            first_line[4..].trim().to_string()
        } else {
            String::new()
        };
        let text_clone = text.clone();
        let (ppc, pco, pi, tn, pn) = classify(code);
        return Some((
            FtpResponse {
                code,
                text,
                lines: vec![text_clone],
                is_positive_preliminary: ppc,
                is_positive_completion: pco,
                is_positive_intermediate: pi,
                is_transient_negative: tn,
                is_permanent_negative: pn,
            },
            first_line_end + 1,
        ));
    }

    // Multi-line response: first line is "NNN-..."
    let mut lines = vec![first_line[4..].to_string()];
    let end_marker = format!("{} ", code);
    let mut pos = first_line_end + 1;
    loop {
        let rest = &s[pos..];
        let line_end = rest.find('\n')?;
        let line = rest[..line_end].trim_end_matches('\r');
        pos += line_end + 1;
        if line.len() >= 4 && line[..4] == end_marker {
            lines.push(line[4..].to_string());
            break;
        }
        lines.push(line.to_string());
    }
    let text = lines.join("\n");
    let (ppc, pco, pi, tn, pn) = classify(code);
    Some((
        FtpResponse {
            code,
            text,
            lines,
            is_positive_preliminary: ppc,
            is_positive_completion: pco,
            is_positive_intermediate: pi,
            is_transient_negative: tn,
            is_permanent_negative: pn,
        },
        pos,
    ))
}

/// FTPS client supporting FTP over TLS/SSL
pub struct FtpsClient {
    /// Raw TCP stream (before TLS upgrade)
    raw_stream: Option<TcpStream>,
    /// TLS connection (after TLS upgrade)
    ctrl_tls: Option<TlsConnection>,
    host: Option<String>,
    passive: bool,
    _is_ipv6: bool,
    binary: bool,
    current_dir: String,
    config: FtpsConfig,
    is_tls: bool,
}

/// Wrapper for TLS connection
struct TlsConnection {
    stream: TcpStream,
    conn: ClientConnection,
}

impl TlsConnection {
    fn complete_handshake(&mut self) -> io::Result<()> {
        loop {
            if !self.conn.is_handshaking() {
                break;
            }

            if self.conn.wants_write() {
                self.conn.write_tls(&mut self.stream)?;
                continue;
            }

            if self.conn.wants_read() {
                match self.conn.read_tls(&mut self.stream)? {
                    0 => return Err(io::Error::new(io::ErrorKind::ConnectionReset, "connection closed")),
                    _ => {}
                }
                self.conn.process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                continue;
            }

            break;
        }
        Ok(())
    }

    /// Read decrypted application data from the TLS connection.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // Try to read from the TLS reader first
            match self.conn.reader().read(buf) {
                Ok(0) => {}
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof
                    || e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            // No buffered data: pull more TLS records from the network
            match self.conn.read_tls(&mut self.stream) {
                Ok(0) => return Ok(0),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
            self.conn.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
    }
}

impl FtpsClient {
    /// Create a new FTPS client with default configuration
    pub fn new() -> Self {
        Self {
            raw_stream: None,
            ctrl_tls: None,
            host: None,
            passive: true,
            _is_ipv6: false,
            binary: true,
            current_dir: String::new(),
            config: FtpsConfig::default(),
            is_tls: false,
        }
    }

    /// Create a new FTPS client with custom configuration
    pub fn with_config(config: FtpsConfig) -> Self {
        Self {
            raw_stream: None,
            ctrl_tls: None,
            host: None,
            passive: true,
            _is_ipv6: false,
            binary: true,
            current_dir: String::new(),
            config,
            is_tls: false,
        }
    }

    /// Set passive mode
    pub fn with_passive(mut self, passive: bool) -> Self {
        self.passive = passive;
        self
    }

    /// Connect using implicit FTPS (direct TLS to port 990)
    pub fn connect_implicit(&mut self, host: &str, port: u16) -> Result<FtpResponse, FtpError> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| FtpError::Connect(e.to_string()))?;
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();

        // Perform TLS handshake immediately
        let tls_conn = self.wrap_tls(stream, host)?;

        self.ctrl_tls = Some(tls_conn);
        self.host = Some(host.to_string());
        self.is_tls = true;

        // Read welcome message over TLS
        let welcome = self.read_response()?;

        log::debug!("FTPS (implicit) connected to {}:{}", host, port);
        Ok(welcome)
    }

    /// Connect using explicit FTPS (connect to port 21, then upgrade with AUTH TLS)
    pub fn connect_explicit(&mut self, host: &str, port: u16) -> Result<FtpResponse, FtpError> {
        // First connect as plain FTP
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| FtpError::Connect(e.to_string()))?;
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();

        // Read welcome message
        let welcome = self.read_response_from_stream(&stream)?;

        if !welcome.is_positive_completion {
            return Err(FtpError::Connect(format!(
                "server refused connection: {} {}", welcome.code, welcome.text
            )));
        }

        self.raw_stream = Some(stream);
        self.host = Some(host.to_string());

        log::debug!("FTP connected to {}:{}", host, port);

        // Send AUTH TLS command to upgrade to TLS
        self.upgrade_to_tls(host)?;

        Ok(welcome)
    }

    /// Read FTP response from a plain TCP stream.
    ///
    /// Handles multi-line FTP responses (RFC 959):
    /// - Intermediate lines start with "NNN-" (code + dash)
    /// - Final line starts with "NNN " (code + space)
    fn read_response_from_stream(&self, stream: &TcpStream) -> Result<FtpResponse, FtpError> {
        // Helper: read one line (terminated by \n) from the TCP stream byte-by-byte
        // to avoid buffering data that belongs to the next response.
        fn read_line(stream: &TcpStream) -> Result<String, FtpError> {
            let mut bytes = Vec::new();
            let mut buf = [0u8; 1];
            loop {
                let n = (&*stream).read(&mut buf).map_err(FtpError::Io)?;
                if n == 0 {
                    if bytes.is_empty() {
                        return Err(FtpError::Connect("connection closed".into()));
                    }
                    break; // EOF mid-line: return what we have
                }
                bytes.push(buf[0]);
                if buf[0] == b'\n' {
                    break;
                }
            }
            String::from_utf8(bytes)
                .map_err(|e| FtpError::ParseError(format!("invalid UTF-8 in response: {}", e)))
        }

        // First line: must contain at least the 3-digit code.
        let first_line = read_line(stream)?;
        let trimmed = first_line.trim_end_matches(|c| c == '\r' || c == '\n');
        if trimmed.len() < 3 {
            return Err(FtpError::ParseError(format!("response too short: {}", trimmed)));
        }
        let code: u16 = trimmed[..3].parse().map_err(|_| {
            FtpError::ParseError(format!("invalid code: {}", &trimmed[..3]))
        })?;
        log::debug!("FTPS < {}", trimmed);

        let classify = |code: u16| -> (bool, bool, bool, bool, bool) {
            (
                code >= 100 && code < 200,
                code >= 200 && code < 300,
                code >= 300 && code < 400,
                code >= 400 && code < 500,
                code >= 500 && code < 600,
            )
        };

        // Multi-line response: first line is "NNN-..."
        if trimmed.len() >= 4 && trimmed.as_bytes()[3] == b'-' {
            let mut lines = vec![trimmed[4..].to_string()];
            let end_marker = format!("{} ", code);
            loop {
                let line = read_line(stream)?;
                let t = line.trim_end_matches(|c| c == '\r' || c == '\n');
                log::debug!("FTPS < {}", t);
                // Final line starts with "<code> "
                if t.len() >= 4 && t[..4] == end_marker {
                    lines.push(t[4..].to_string());
                    break;
                }
                lines.push(t.to_string());
            }
            let text = lines.join("\n");
            let (ppc, pco, pi, tn, pn) = classify(code);
            return Ok(FtpResponse {
                code,
                text,
                lines,
                is_positive_preliminary: ppc,
                is_positive_completion: pco,
                is_positive_intermediate: pi,
                is_transient_negative: tn,
                is_permanent_negative: pn,
            });
        }

        // Single-line response
        let text = if trimmed.len() > 4 {
            trimmed[4..].trim().to_string()
        } else {
            String::new()
        };
        let text_clone = text.clone();
        let (ppc, pco, pi, tn, pn) = classify(code);
        Ok(FtpResponse {
            code,
            text,
            lines: vec![text_clone],
            is_positive_preliminary: ppc,
            is_positive_completion: pco,
            is_positive_intermediate: pi,
            is_transient_negative: tn,
            is_permanent_negative: pn,
        })
    }

    /// Send command to plain TCP stream
    fn send_cmd_to_stream(&self, stream: &TcpStream, cmd: &str) -> Result<(), FtpError> {
        let cmd_bytes = format!("{}\r\n", cmd);
        (&*stream).write_all(cmd_bytes.as_bytes())
            .map_err(FtpError::Io)?;
        (&*stream).flush()
            .map_err(FtpError::Io)?;
        let log_cmd = if cmd.starts_with("PASS ") { "PASS <redacted>" } else { cmd };
        log::debug!("FTPS > {}", log_cmd);
        Ok(())
    }

    /// Upgrade plain FTP connection to TLS (AUTH TLS)
    fn upgrade_to_tls(&mut self, host: &str) -> Result<(), FtpError> {
        // Get the raw stream
        let stream = self.raw_stream.take()
            .ok_or_else(|| FtpError::Connect("no control connection".into()))?;

        // Send AUTH TLS command
        self.send_cmd_to_stream(&stream, "AUTH TLS")?;
        let resp = self.read_response_from_stream(&stream)?;

        if !resp.is_positive_completion {
            // Try AUTH SSL as fallback
            self.send_cmd_to_stream(&stream, "AUTH SSL")?;
            let resp2 = self.read_response_from_stream(&stream)?;
            if !resp2.is_positive_completion {
                return Err(FtpError::Connect(format!(
                    "server does not support TLS: {} {}", resp2.code, resp2.text
                )));
            }
        }

        // Wrap the stream with TLS
        let tls_conn = self.wrap_tls(stream, host)?;
        self.ctrl_tls = Some(tls_conn);
        self.is_tls = true;

        // Set protection level to private (encrypted data channel)
        self.send_cmd("PBSZ 0")?;
        let _ = self.read_response()?;

        self.send_cmd("PROT P")?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            self.config.require_data_tls = true;
        } else {
            // Server refused encrypted data channel: data transfers will be
            // sent in cleartext even though the control channel is encrypted.
            // Warn the user - they may believe the entire session is encrypted.
            log::warn!(
                "FTPS: server refused PROT P ({}); data channel will be UNENCRYPTED. \
                 Control channel is still encrypted, but file contents are sent in cleartext.",
                resp.text.trim()
            );
        }

        log::debug!("FTPS: TLS upgrade complete");
        Ok(())
    }

    /// Wrap a TCP stream with TLS
    fn wrap_tls(&self, stream: TcpStream, host: &str) -> Result<TlsConnection, FtpError> {
        let config = self.build_tls_config()?;
        let server_name = ServerName::try_from(host)
            .map_err(|e| FtpError::Connect(format!("invalid server name: {}", e)))?
            .to_owned();

        let conn = ClientConnection::new(config, server_name)
            .map_err(|e| FtpError::Connect(format!("TLS error: {}", e)))?;

        let mut tls = TlsConnection { stream, conn };
        tls.complete_handshake()
            .map_err(|e| FtpError::Connect(format!("TLS handshake failed: {}", e)))?;

        Ok(tls)
    }

    /// Build TLS client configuration
    fn build_tls_config(&self) -> Result<Arc<ClientConfig>, FtpError> {
        let mut root_store = RootCertStore::empty();

        if self.config.verify_certificate {
            // Load custom CA if specified
            if let Some(ref ca_path) = self.config.ca_cert {
                let data = std::fs::read(ca_path)
                    .map_err(|e| FtpError::Connect(format!("cannot read CA cert: {}", e)))?;
                let certs = rustls_pemfile::certs(&mut data.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| FtpError::Connect(format!("cannot parse CA cert: {}", e)))?;
                for cert in certs {
                    root_store.add(cert.to_owned())
                        .map_err(|e| FtpError::Connect(format!("cannot add CA cert: {}", e)))?;
                }
            }

            // Load system root certificates, falling back to Mozilla roots.
            if root_store.is_empty() {
                let result = rustls_native_certs::load_native_certs();
                for cert in &result.certs {
                    root_store.add(cert.clone()).ok();
                }
                if root_store.is_empty() {
                    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                }
            }

            // Select TLS protocol versions based on --secure-protocol, mirroring
            // the HTTPS path in net/src/tls/rustls_impl.rs:175-185.
            let versions: &[&'static rustls::SupportedProtocolVersion] = match self.config.secure_protocol {
                SecureProtocol::TlsV1_2 => &[&rustls::version::TLS12],
                SecureProtocol::TlsV1_3 => &[&rustls::version::TLS13],
                SecureProtocol::Auto | SecureProtocol::Pfs => rustls::ALL_VERSIONS,
            };

            Ok(Arc::new(
                ClientConfig::builder_with_protocol_versions(versions)
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            ))
        } else {
            // Skip certificate verification
            let verifier: Arc<dyn ServerCertVerifier> = Arc::new(SkipServerVerification);
            // Still honor --secure-protocol even when verification is skipped.
            let versions: &[&'static rustls::SupportedProtocolVersion] = match self.config.secure_protocol {
                SecureProtocol::TlsV1_2 => &[&rustls::version::TLS12],
                SecureProtocol::TlsV1_3 => &[&rustls::version::TLS13],
                SecureProtocol::Auto | SecureProtocol::Pfs => rustls::ALL_VERSIONS,
            };
            Ok(Arc::new(
                ClientConfig::builder_with_protocol_versions(versions)
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth(),
            ))
        }
    }

    /// Send an FTP command over the TLS connection.
    fn send_cmd(&mut self, cmd: &str) -> Result<(), FtpError> {
        if let Some(ref mut tls) = self.ctrl_tls {
            let mut writer = tls.conn.writer();
            writer.write_all(format!("{}\r\n", cmd).as_bytes())
                .map_err(FtpError::Io)?;
            writer.flush().map_err(FtpError::Io)?;

            // Flush TLS layer
            while tls.conn.wants_write() {
                tls.conn.write_tls(&mut tls.stream)
                    .map_err(FtpError::Io)?;
            }
        } else {
            return Err(FtpError::Connect("not connected (TLS required)".into()));
        }

        let log_cmd = if cmd.starts_with("PASS ") { "PASS <redacted>" } else { cmd };
        log::debug!("FTPS > {}", log_cmd);
        Ok(())
    }

    /// Read an FTP response from the TLS connection.
    ///
    /// Handles multi-line FTP responses (RFC 959):
    /// - Intermediate lines start with "NNN-" (code + dash)
    /// - Final line starts with "NNN " (code + space)
    ///
    /// Accumulates decrypted plaintext from TLS records into a buffer and
    /// delegates to [`parse_complete_response`] to detect a full response.
    /// This avoids the previous bug where `data.find("\r\n")` always matched
    /// the first line, causing multi-line responses to hang indefinitely.
    fn read_response(&mut self) -> Result<FtpResponse, FtpError> {
        let mut data: Vec<u8> = Vec::new();

        let tls = self.ctrl_tls.as_mut()
            .ok_or_else(|| FtpError::Connect("not connected (TLS required)".into()))?;

        loop {
            // Read more ciphertext from the TCP stream into the TLS state machine.
            // `read_tls` blocks (blocking socket) until data or EOF.
            let n = tls.conn.read_tls(&mut tls.stream).map_err(FtpError::Io)?;
            tls.conn.process_new_packets()
                .map_err(|e| FtpError::Connect(format!("TLS error: {}", e)))?;

            // Drain newly produced plaintext into our buffer.
            let mut reader = tls.conn.reader();
            let mut buf = [0u8; 1024];
            loop {
                let rn = reader.read(&mut buf).map_err(FtpError::Io)?;
                if rn == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..rn]);
            }

            // Try to parse a complete FTP response from the accumulated bytes.
            if let Some((response, _consumed)) = parse_complete_response(&data) {
                log::debug!(
                    "FTPS < {} {}",
                    response.code,
                    response.lines.last().map(|s| s.as_str()).unwrap_or("")
                );
                return Ok(response);
            }

            // No complete response yet.
            if n == 0 {
                // TLS stream hit EOF without a complete response.
                return Err(FtpError::ParseError(format!(
                    "connection closed; partial response: {} bytes",
                    data.len()
                )));
            }
            // Otherwise loop to read more TLS records.
        }
    }

    /// Login to the FTPS server.
    ///
    /// # Arguments
    ///
    /// * `user` - The username for authentication.
    /// * `password` - The password for authentication.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::LoginRefused` if authentication fails.
    pub fn login(&mut self, user: &str, password: &str) -> Result<FtpResponse, FtpError> {
        validate_ftp_input(user)?;
        validate_ftp_input(password)?;
        self.send_cmd(&format!("USER {}", user))?;
        let resp = self.read_response()?;

        if resp.is_positive_completion {
            return Ok(resp);
        }

        if resp.is_positive_intermediate {
            self.send_cmd(&format!("PASS {}", password))?;
            let pass_resp = self.read_response()?;

            if pass_resp.is_positive_completion {
                return Ok(pass_resp);
            }

            if pass_resp.is_permanent_negative {
                return Err(FtpError::LoginRefused(pass_resp.text));
            }

            return Err(FtpError::CommandFailed {
                code: pass_resp.code,
                message: pass_resp.text,
            });
        }

        Err(FtpError::LoginRefused(resp.text))
    }

    /// Set binary (image) transfer mode.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the command fails.
    pub fn type_binary(&mut self) -> Result<FtpResponse, FtpError> {
        self.send_cmd("TYPE I")?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            self.binary = true;
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Change the current working directory.
    ///
    /// # Arguments
    ///
    /// * `path` - The directory path to change to.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the directory doesn't exist.
    pub fn cwd(&mut self, path: &str) -> Result<FtpResponse, FtpError> {
        validate_ftp_input(path)?;
        self.send_cmd(&format!("CWD {}", path))?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            self.current_dir = path.to_string();
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Get the size of a file on the server.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the file to query.
    ///
    /// # Returns
    ///
    /// `Some(size)` if the command succeeds, `None` if unsupported.
    pub fn size(&mut self, filename: &str) -> Result<Option<u64>, FtpError> {
        validate_ftp_input(filename)?;
        self.send_cmd(&format!("SIZE {}", filename))?;
        let resp = self.read_response()?;

        if resp.is_positive_completion {
            resp.text.trim().parse::<u64>().map(Some).map_err(|_| {
                FtpError::ParseError(format!("cannot parse SIZE response: {}", resp.text))
            })
        } else {
            Ok(None)
        }
    }

    /// Close the FTPS connection.
    ///
    /// Sends the QUIT command and closes the TLS connection.
    pub fn quit(&mut self) -> Result<(), FtpError> {
        if self.ctrl_tls.is_some() || self.raw_stream.is_some() {
            let _ = self.send_cmd("QUIT");
            let _ = self.read_response();
        }
        self.raw_stream = None;
        self.ctrl_tls = None;
        self.host = None;
        Ok(())
    }

    /// Get the modification time of a file.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the file to query.
    ///
    /// # Returns
    ///
    /// `Some(datetime)` if the command succeeds, `None` if unsupported.
    pub fn mdtm(&mut self, filename: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>, FtpError> {
        validate_ftp_input(filename)?;
        self.send_cmd(&format!("MDTM {}", filename))?;
        let resp = self.read_response()?;

        if resp.is_positive_completion {
            // Parse MDTM response: YYYYMMDDHHMMSS
            let timestamp = resp.text.trim();
            if timestamp.len() >= 14 {
                let year: i32 = timestamp[0..4].parse().unwrap_or(1970);
                let month: u32 = timestamp[4..6].parse().unwrap_or(1);
                let day: u32 = timestamp[6..8].parse().unwrap_or(1);
                let hour: u32 = timestamp[8..10].parse().unwrap_or(0);
                let min: u32 = timestamp[10..12].parse().unwrap_or(0);
                let sec: u32 = timestamp[12..14].parse().unwrap_or(0);

                return chrono::NaiveDate::from_ymd_opt(year, month, day)
                    .and_then(|d| d.and_hms_opt(hour, min, sec))
                    .map(|dt| Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc)))
                    .ok_or_else(|| FtpError::ParseError(format!("invalid MDTM date: {}", timestamp)));
            }
            Ok(None)
        } else {
            Ok(None)
        }
    }

    /// Enter passive mode and return the data connection address.
    fn enter_passive(&mut self) -> Result<(String, u16), FtpError> {
        self.send_cmd("PASV")?;
        let resp = self.read_response()?;

        if !resp.is_positive_completion {
            return Err(FtpError::DataConnectFailed(format!(
                "PASV failed: {} {}", resp.code, resp.text
            )));
        }

        // Parse PASV response: (h1,h2,h3,h4,p1,p2)
        let text = resp.text.trim();
        let start = text.find('(').ok_or_else(|| FtpError::ParseError(format!("invalid PASV: {}", text)))?;
        let end = text.find(')').ok_or_else(|| FtpError::ParseError(format!("invalid PASV: {}", text)))?;
        let nums: Vec<u8> = text[start+1..end]
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        if nums.len() != 6 {
            return Err(FtpError::ParseError(format!("invalid PASV: {}", text)));
        }

        let host = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);
        let port = ((nums[4] as u16) << 8) | (nums[5] as u16);

        Ok((host, port))
    }

    /// Retrieve a file from the server.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the file to retrieve.
    /// * `output` - A writer to receive the file data.
    /// * `resume_pos` - Optional byte offset to resume from.
    ///
    /// # Returns
    ///
    /// The total number of bytes transferred.
    pub fn retr<W: Write>(
        &mut self,
        filename: &str,
        output: &mut W,
        resume_pos: Option<u64>,
    ) -> Result<u64, FtpError> {
        // Enter passive mode
        let (data_host, data_port) = self.enter_passive()?;

        // Send REST if resuming
        if let Some(pos) = resume_pos {
            self.send_cmd(&format!("REST {}", pos))?;
            let resp = self.read_response()?;
            // RFC 959: REST is acknowledged with 350 (Ready for requested action).
            // Some servers reply 2xx instead; anything else means the server
            // does not support restart, so the transfer cannot resume.
            if !resp.is_positive_preliminary && !resp.is_positive_completion {
                return Err(FtpError::CommandFailed {
                    code: resp.code,
                    message: format!("REST {} failed: {}", pos, resp.text),
                });
            }
        }

        // Send RETR command
        validate_ftp_input(filename)?;
        self.send_cmd(&format!("RETR {}", filename))?;
        let transfer_resp = self.read_response()?;

        if !transfer_resp.is_positive_preliminary {
            return Err(FtpError::DataConnectFailed(format!(
                "expected 1xx for RETR, got {}: {}", transfer_resp.code, transfer_resp.text
            )));
        }

        // Connect to data port
        let mut data_tcp = TcpStream::connect(format!("{}:{}", data_host, data_port))
            .map_err(|e| FtpError::DataConnectFailed(e.to_string()))?;
        // Apply 60s read/write timeouts to the data connection, matching the
        // plain-FTP data_conn.rs behaviour. Without this, a server that stops
        // sending but keeps the socket open would block indefinitely.
        data_tcp
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(FtpError::Io)?;
        data_tcp
            .set_write_timeout(Some(Duration::from_secs(60)))
            .map_err(FtpError::Io)?;

        // Wrap with TLS if PROT P was negotiated
        if self.config.require_data_tls {
            let host = self.host.as_deref().unwrap_or("unknown");
            let mut data_tls = self.wrap_tls(data_tcp, host)?;

            // Read data over encrypted channel
            let start_pos = resume_pos.unwrap_or(0);
            let mut total_bytes = start_pos;
            let mut buf = [0u8; 64 * 1024];

            loop {
                let n = data_tls.read(&mut buf).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
                if n == 0 { break; }
                output.write_all(&buf[..n]).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
                total_bytes += n as u64;
            }

            // Read final response
            let done_resp = self.read_response()?;
            if !done_resp.is_positive_completion {
                return Err(FtpError::TransferFailed(format!(
                    "transfer not confirmed: {} {}", done_resp.code, done_resp.text
                )));
            }

            log::debug!("FTPS RETR {}: {} bytes (encrypted)", filename, total_bytes);
            return Ok(total_bytes);
        }

        // Fallback: unencrypted data channel (PROT P was refused)
        // Read data
        let start_pos = resume_pos.unwrap_or(0);
        let mut total_bytes = start_pos;
        let mut buf = [0u8; 64 * 1024];

        loop {
            let n = std::io::Read::read(&mut data_tcp, &mut buf).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
            if n == 0 { break; }
            output.write_all(&buf[..n]).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
            total_bytes += n as u64;
        }

        // Read final response
        let done_resp = self.read_response()?;
        if !done_resp.is_positive_completion {
            return Err(FtpError::TransferFailed(format!(
                "transfer not confirmed: {} {}", done_resp.code, done_resp.text
            )));
        }

        log::debug!("FTPS RETR {}: {} bytes", filename, total_bytes);
        Ok(total_bytes)
    }

    /// List the names of files in a directory via `NLST`.
    ///
    /// Sends the `NLST` command over a (possibly encrypted) data connection
    /// and returns the list of entry names (one per line). When `directory`
    /// is `None`, the current directory is listed.
    pub fn nlst(&mut self, directory: Option<&str>) -> Result<Vec<String>, FtpError> {
        if let Some(dir) = directory {
            validate_ftp_input(dir)?;
        }
        let (data_host, data_port) = self.enter_passive()?;
        let cmd = match directory {
            Some(dir) => format!("NLST {}", dir),
            None => "NLST".to_string(),
        };
        self.send_cmd(&cmd)?;
        let transfer_resp = self.read_response()?;
        if !transfer_resp.is_positive_preliminary {
            return Err(FtpError::DataConnectFailed(format!(
                "expected 1xx for NLST, got {}: {}", transfer_resp.code, transfer_resp.text
            )));
        }

        let mut data_tcp = TcpStream::connect(format!("{}:{}", data_host, data_port))
            .map_err(|e| FtpError::DataConnectFailed(e.to_string()))?;
        // Apply 60s read/write timeouts, matching plain-FTP data_conn.rs.
        data_tcp
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(FtpError::Io)?;
        data_tcp
            .set_write_timeout(Some(Duration::from_secs(60)))
            .map_err(FtpError::Io)?;

        let mut data = Vec::new();
        const MAX_NLST_SIZE: usize = 64 * 1024 * 1024; // 64MB limit
        if self.config.require_data_tls {
            let host = self.host.as_deref().unwrap_or("unknown");
            let mut data_tls = self.wrap_tls(data_tcp, host)?;
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = data_tls.read(&mut buf).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
                if n == 0 { break; }
                data.extend_from_slice(&buf[..n]);
                if data.len() > MAX_NLST_SIZE {
                    return Err(FtpError::TransferFailed("NLST response too large (exceeds 64MB)".into()));
                }
            }
        } else {
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = std::io::Read::read(&mut data_tcp, &mut buf).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
                if n == 0 { break; }
                data.extend_from_slice(&buf[..n]);
                if data.len() > MAX_NLST_SIZE {
                    return Err(FtpError::TransferFailed("NLST response too large (exceeds 64MB)".into()));
                }
            }
        }

        let done_resp = self.read_response()?;
        if !done_resp.is_positive_completion {
            return Err(FtpError::TransferFailed(format!(
                "transfer not confirmed: {} {}", done_resp.code, done_resp.text
            )));
        }

        let text = String::from_utf8_lossy(&data);
        Ok(text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
    }
}

impl Default for FtpsClient {
    /// Create a new FTPS client with default settings.
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FtpsClient {
    /// Automatically close the connection when dropped.
    fn drop(&mut self) {
        let _ = self.quit();
    }
}

/// Certificate verifier that skips all verification.
///
/// Used when `--no-check-certificate` is specified.
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
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

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

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

#[cfg(test)]
mod tests {
    use super::parse_complete_response;

    #[test]
    fn parses_single_line_response() {
        let data = b"220 Service ready\r\n";
        let (resp, consumed) = parse_complete_response(data).expect("single-line should parse");
        assert_eq!(resp.code, 220);
        assert_eq!(resp.text, "Service ready");
        assert_eq!(consumed, data.len());
        assert!(resp.is_positive_completion);
    }

    #[test]
    fn parses_multi_line_response() {
        // Classic multi-line FTP welcome: 220-Welcome\n220-Second line\n220 Ready
        let data = b"220-Welcome to the FTP server\r\n220-Second line of greeting\r\n220 Ready\r\n";
        let (resp, consumed) = parse_complete_response(data).expect("multi-line should parse");
        assert_eq!(resp.code, 220);
        assert_eq!(resp.lines.len(), 3);
        // First line: prefix "NNN-" stripped, content only
        assert_eq!(resp.lines[0], "Welcome to the FTP server");
        // Intermediate lines: original form retained (matches command.rs behavior)
        assert_eq!(resp.lines[1], "220-Second line of greeting");
        // Final line: prefix "NNN " stripped, content only
        assert_eq!(resp.lines[2], "Ready");
        assert_eq!(consumed, data.len());
        assert!(resp.is_positive_completion);
    }

    #[test]
    fn returns_none_for_incomplete_multi_line() {
        // No final "220 " line present → must return None (was the bug causing hang)
        let data = b"220-Welcome\r\n220-Still going\r\n";
        assert!(parse_complete_response(data).is_none(),
            "incomplete multi-line response must not parse (regression check for hang bug)");
    }

    #[test]
    fn returns_none_for_truncated_first_line() {
        // No newline yet → cannot determine first line
        let data = b"220 Ready";
        assert!(parse_complete_response(data).is_none());
    }

    #[test]
    fn parses_multi_line_with_blank_intermediate_line() {
        let data = b"220-First\r\n220-\r\n220 Final\r\n";
        let (resp, consumed) = parse_complete_response(data).expect("blank intermediate line should parse");
        assert_eq!(resp.code, 220);
        assert_eq!(resp.lines.len(), 3);
        assert_eq!(resp.lines[1], "220-");  // intermediate line kept as-is (blank content after dash)
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn parses_error_response() {
        let data = b"530 Not logged in\r\n";
        let (resp, _) = parse_complete_response(data).expect("error response should parse");
        assert_eq!(resp.code, 530);
        assert!(resp.is_permanent_negative);
        assert!(!resp.is_positive_completion);
    }

    #[test]
    fn handles_lf_only_line_endings() {
        // Some servers may use bare LF; we should still find the line via '\n'
        let data = b"331 User name okay, need password\n";
        let (resp, consumed) = parse_complete_response(data).expect("LF-only line should parse");
        assert_eq!(resp.code, 331);
        assert!(resp.is_positive_intermediate);
        assert_eq!(consumed, data.len());
    }
}
