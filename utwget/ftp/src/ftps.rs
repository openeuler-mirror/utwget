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
use crate::client::FtpError;

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
}

impl Default for FtpsConfig {
    fn default() -> Self {
        Self {
            verify_certificate: true,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            require_data_tls: false,
        }
    }
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

    /// Read FTP response from a plain TCP stream
    fn read_response_from_stream(&self, stream: &TcpStream) -> Result<FtpResponse, FtpError> {
        let mut line = String::new();
        let mut buf = [0u8; 1];

        loop {
            let n = (&*stream).read(&mut buf)
                .map_err(FtpError::Io)?;
            if n == 0 {
                return Err(FtpError::Connect("connection closed".into()));
            }
            line.push(buf[0] as char);
            if buf[0] == b'\n' {
                break;
            }
        }

        let line = line.trim();
        let code: u16 = line.get(..3)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| FtpError::ParseError(format!("invalid response: {}", line)))?;

        let text = line.get(4..).unwrap_or("").to_string();

        Ok(FtpResponse {
            code,
            text,
            lines: vec![],
            is_positive_preliminary: code >= 100 && code < 200,
            is_positive_completion: code >= 200 && code < 300,
            is_positive_intermediate: code >= 300 && code < 400,
            is_transient_negative: code >= 400 && code < 500,
            is_permanent_negative: code >= 500 && code < 600,
        })
    }

    /// Send command to plain TCP stream
    fn send_cmd_to_stream(&self, stream: &TcpStream, cmd: &str) -> Result<(), FtpError> {
        let cmd_bytes = format!("{}\r\n", cmd);
        (&*stream).write_all(cmd_bytes.as_bytes())
            .map_err(FtpError::Io)?;
        (&*stream).flush()
            .map_err(FtpError::Io)?;
        log::debug!("FTPS > {}", cmd);
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

            // Use system root certificates
            if root_store.is_empty() {
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }

            Ok(Arc::new(ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()))
        } else {
            // Skip certificate verification
            let verifier: Arc<dyn ServerCertVerifier> = Arc::new(SkipServerVerification);
            Ok(Arc::new(ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()))
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

        log::debug!("FTPS > {}", cmd);
        Ok(())
    }

    /// Read an FTP response from the TLS connection.
    fn read_response(&mut self) -> Result<FtpResponse, FtpError> {
        let mut line = String::new();

        if let Some(ref mut tls) = self.ctrl_tls {
            // Read TLS data
            tls.conn.read_tls(&mut tls.stream)
                .map_err(FtpError::Io)?;
            tls.conn.process_new_packets()
                .map_err(|e| FtpError::Connect(format!("TLS error: {}", e)))?;

            let mut reader = tls.conn.reader();
            let mut buf = [0u8; 1024];
            loop {
                let n = reader.read(&mut buf).map_err(FtpError::Io)?;
                if n == 0 { break; }
                line.push_str(&String::from_utf8_lossy(&buf[..n]));
                if line.contains("\r\n") { break; }
            }
        } else {
            return Err(FtpError::Connect("not connected (TLS required)".into()));
        }

        // Parse response
        let line = line.trim();
        log::debug!("FTPS < {}", line);

        let code: u16 = line.get(..3)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| FtpError::ParseError(format!("invalid response: {}", line)))?;

        let text = line.get(4..).unwrap_or("").to_string();

        Ok(FtpResponse {
            code,
            text,
            lines: vec![],
            is_positive_preliminary: code >= 100 && code < 200,
            is_positive_completion: code >= 200 && code < 300,
            is_positive_intermediate: code >= 300 && code < 400,
            is_transient_negative: code >= 400 && code < 500,
            is_permanent_negative: code >= 500 && code < 600,
        })
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
            let _ = self.read_response();
        }

        // Send RETR command
        self.send_cmd(&format!("RETR {}", filename))?;
        let transfer_resp = self.read_response()?;

        if !transfer_resp.is_positive_preliminary {
            return Err(FtpError::DataConnectFailed(format!(
                "expected 1xx for RETR, got {}: {}", transfer_resp.code, transfer_resp.text
            )));
        }

        // Connect to data port
        let mut data_stream = TcpStream::connect(format!("{}:{}", data_host, data_port))
            .map_err(|e| FtpError::DataConnectFailed(e.to_string()))?;

        // Read data
        let start_pos = resume_pos.unwrap_or(0);
        let mut total_bytes = start_pos;
        let mut buf = [0u8; 32768];

        loop {
            let n = std::io::Read::read(&mut data_stream, &mut buf).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
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
