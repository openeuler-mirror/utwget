//! FTP command and response handling.
//!
//! This module provides the low-level primitives for sending FTP commands
//! and parsing server responses. It includes the `Transport` trait for
//! abstracting over different connection types (plain TCP, TLS, etc.).

use std::io;

/// Trait for transport layers that can send and receive FTP commands.
///
/// This abstraction allows the FTP client to work with different
/// transport types such as plain TCP connections or TLS-wrapped
/// connections for FTPS.
pub trait Transport {
    /// The error type for transport operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Read data from the transport into the provided buffer.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Write all data from the provided buffer to the transport.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;

    /// Flush any buffered data to the transport.
    fn flush(&mut self) -> Result<(), Self::Error>;

    /// Return the remote peer address, if available.
    fn peer_addr(&self) -> Result<std::net::SocketAddr, Self::Error>;

    /// Return the local socket address, if available.
    ///
    /// Used by active-mode FTP to advertise the control connection's local
    /// IP in the PORT command (GNU wget uses getsockname, ftp-basic.c);
    /// binding to 0.0.0.0 and reading `local_addr()` from the listener
    /// would advertise 0.0.0.0, which compliant servers reject.
    ///
    /// Default: `None` (unknown) — callers fall back to the listener's own
    /// address (legacy behavior).
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }

    /// Provide a mutable reference as `Option<&mut dyn Any>` for downcasting.
    /// This allows `read_line_from` to detect and use `BufferedTransport`
    /// for line-aware reads that preserve leftover bytes.
    ///
    /// 默认返回 `None`，downcast 失败时 `read_line_from` 回退到普通 read。
    /// 之前是 `unimplemented!()` 会在非 `BufferedTransport` 的 Transport 上
    /// 调用 `read_line_from` 时 panic。
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }
}

/// A transport wrapper that retains leftover bytes from `read()` calls.
///
/// When a single `read()` returns data spanning multiple FTP response lines
/// (common when servers send multi-line 220/230/229 greetings in one TCP
/// segment), the raw `read_line_from` function discards everything after
/// the first `\n` because it uses a local buffer that is not retained across
/// calls. This wrapper keeps a persistent internal buffer so that leftover
/// bytes are preserved for the next `read()` call, matching the behavior of
/// `std::io::BufReader`.
pub struct BufferedTransport {
    inner: Box<dyn Transport<Error = io::Error>>,
    buf: Vec<u8>,
}

impl BufferedTransport {
    /// Wrap a transport in a buffered reader.
    pub fn new(inner: Box<dyn Transport<Error = io::Error>>) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }

    /// Read a complete line (up to and including `\n`) from the buffered
    /// transport, fetching more data from the underlying transport as needed.
    /// Leftover bytes after the line are retained in the internal buffer.
    fn read_line_buffered(&mut self) -> Result<Vec<u8>, FtpCommandError> {
        const MAX_FTP_LINE_LEN: usize = 8 * 1024;
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                return Ok(line);
            }
            if self.buf.len() > MAX_FTP_LINE_LEN {
                return Err(FtpCommandError::MalformedResponse(
                    format!("FTP response line too long (exceeds {} bytes)", MAX_FTP_LINE_LEN)
                ));
            }
            let mut tmp = [0u8; 256];
            let n = self.inner.read(&mut tmp).map_err(FtpCommandError::Io)?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Err(FtpCommandError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    )));
                }
                // EOF mid-line: return what we have
                return Ok(std::mem::take(&mut self.buf));
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
}

impl Transport for BufferedTransport {
    type Error = io::Error;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // Serve from the internal buffer first; if empty, read from inner.
        if !self.buf.is_empty() {
            let n = self.buf.len().min(buf.len());
            buf[..n].copy_from_slice(&self.buf[..n]);
            self.buf.drain(..n);
            return Ok(n);
        }
        self.inner.read(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.inner.write_all(buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush()
    }

    fn peer_addr(&self) -> Result<std::net::SocketAddr, Self::Error> {
        self.inner.peer_addr()
    }

    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}

/// Trait for transports that can be converted back to TcpStream.
///
/// This is used when upgrading a plain FTP connection to FTPS.
pub trait IntoTcpStream {
    /// Convert the transport back to a TcpStream.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport cannot be converted.
    fn into_tcp_stream(self: Box<Self>) -> Result<std::net::TcpStream, io::Error>;
}

impl IntoTcpStream for std::net::TcpStream {
    fn into_tcp_stream(self: Box<Self>) -> Result<std::net::TcpStream, io::Error> {
        Ok(*self)
    }
}

impl Transport for std::net::TcpStream {
    type Error = io::Error;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> { std::io::Read::read(self, buf) }
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> { std::io::Write::write_all(self, buf) }
    fn flush(&mut self) -> Result<(), Self::Error> { std::io::Write::flush(self) }
    fn peer_addr(&self) -> Result<std::net::SocketAddr, Self::Error> { std::net::TcpStream::peer_addr(self) }
    fn local_addr(&self) -> Option<std::net::SocketAddr> { std::net::TcpStream::local_addr(self).ok() }
}

/// FTP command sender.
///
/// This struct provides methods for sending FTP commands over a transport.
pub struct FtpCommand;

impl FtpCommand {
    /// Send an FTP command over the transport.
    ///
    /// The command is automatically terminated with CRLF if not already present.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to send the command over.
    /// * `cmd` - The FTP command string (without CRLF terminator).
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpCommandError::Io` if the write fails.
    pub fn send(transport: &mut dyn Transport<Error = io::Error>, cmd: &str) -> Result<(), FtpCommandError> {
        let mut full = String::from(cmd);
        if !full.ends_with("\r\n") {
            full.push_str("\r\n");
        }
        transport.write_all(full.as_bytes()).map_err(FtpCommandError::Io)?;
        transport.flush().map_err(FtpCommandError::Io)?;
        // Redact FTP password in debug logs to prevent credential exposure.
        let log_cmd = if cmd.starts_with("PASS ") {
            "PASS <redacted>"
        } else {
            cmd.trim_end()
        };
        log::debug!("FTP CMD: {}", log_cmd);
        Ok(())
    }
}

/// FTP server response.
///
/// Represents a complete FTP response including the numeric code,
/// response text, and classification flags based on the first digit
/// of the response code.
#[derive(Debug)]
pub struct FtpResponse {
    /// The three-digit FTP response code.
    pub code: u16,
    /// The response text (message part after the code).
    pub text: String,
    /// All lines of a multi-line response.
    pub lines: Vec<String>,
    /// True for 1xx codes (positive preliminary reply).
    pub is_positive_preliminary: bool,
    /// True for 2xx codes (positive completion reply).
    pub is_positive_completion: bool,
    /// True for 3xx codes (positive intermediate reply).
    pub is_positive_intermediate: bool,
    /// True for 4xx codes (transient negative completion reply).
    pub is_transient_negative: bool,
    /// True for 5xx codes (permanent negative completion reply).
    pub is_permanent_negative: bool,
}

impl FtpResponse {
    /// Classify a response code into its category flags.
    ///
    /// FTP response codes are classified by their first digit:
    /// - 1xx: Positive preliminary
    /// - 2xx: Positive completion
    /// - 3xx: Positive intermediate
    /// - 4xx: Transient negative
    /// - 5xx: Permanent negative
    fn classify(code: u16) -> (bool, bool, bool, bool, bool) {
        (
            (100..200).contains(&code),
            (200..300).contains(&code),
            (300..400).contains(&code),
            (400..500).contains(&code),
            (500..600).contains(&code),
        )
    }

    /// Read a single line from the transport.
    ///
    /// Reads until a newline character is encountered.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to read from.
    ///
    /// # Returns
    ///
    /// The line as a string (including the newline).
    ///
    /// # Errors
    ///
    /// Returns `FtpCommandError::Io` on read failure or unexpected EOF.
    pub fn read_line_from(transport: &mut dyn Transport<Error = io::Error>) -> Result<String, FtpCommandError> {
        // If the transport is a BufferedTransport, use its line-aware read
        // which preserves leftover bytes. Otherwise, fall back to the
        // direct read (which may lose bytes after \n on multi-line responses).
        if let Some(any) = transport.as_any_mut() {
            if let Some(buf) = any.downcast_mut::<BufferedTransport>() {
                let line_bytes = buf.read_line_buffered()?;
                return String::from_utf8(line_bytes)
                    .map_err(|e| FtpCommandError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string())));
            }
        }

        // Legacy path for non-buffered transports (e.g. in tests).
        const MAX_FTP_LINE_LEN: usize = 8 * 1024; // 8 KB per line (DoS guard)
        let mut line_bytes = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let n = transport.read(&mut buf).map_err(FtpCommandError::Io)?;
            if n == 0 {
                if line_bytes.is_empty() {
                    return Err(FtpCommandError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")));
                }
                break; // EOF mid-line: return what we have
            }
            // Append read bytes, check for newline
            let read = &buf[..n];
            if let Some(pos) = read.iter().position(|&b| b == b'\n') {
                line_bytes.extend_from_slice(&read[..=pos]);
                break;
            }
            line_bytes.extend_from_slice(read);
            // DoS guard: reject lines longer than MAX_FTP_LINE_LEN
            if line_bytes.len() > MAX_FTP_LINE_LEN {
                return Err(FtpCommandError::MalformedResponse(
                    format!("FTP response line too long (exceeds {} bytes)", MAX_FTP_LINE_LEN)
                ));
            }
        }
        String::from_utf8(line_bytes).map_err(|e| FtpCommandError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))
    }

    /// Read a complete FTP response from the transport.
    ///
    /// Handles both single-line and multi-line responses. Multi-line
    /// responses use the format `code-text` for continuation lines
    /// and `code text` for the final line.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to read from.
    ///
    /// # Returns
    ///
    /// The parsed `FtpResponse`.
    ///
    /// # Errors
    ///
    /// Returns `FtpCommandError::MalformedResponse` if the response
    /// cannot be parsed.
    pub fn read(transport: &mut dyn Transport<Error = io::Error>) -> Result<Self, FtpCommandError> {
        let first_line = Self::read_line_from(transport)?;
        let trimmed = first_line.trim_end();
        if trimmed.len() < 3 {
            return Err(FtpCommandError::MalformedResponse("response too short".into()));
        }

        let code: u16 = trimmed[..3].parse().map_err(|_| {
            FtpCommandError::MalformedResponse(format!("invalid code: {}", &trimmed[..3]))
        })?;

        if trimmed.len() >= 4 && trimmed.as_bytes()[3] == b'-' {
            let mut all_lines = vec![trimmed[4..].to_string()];
            let end_marker = format!("{} ", code);
            const MAX_FTP_RESPONSE_SIZE: usize = 64 * 1024; // 64 KB total (DoS guard)
            let mut total_size = first_line.len();
            loop {
                let line = Self::read_line_from(transport)?;
                total_size += line.len();
                if total_size > MAX_FTP_RESPONSE_SIZE {
                    return Err(FtpCommandError::MalformedResponse(
                        format!("FTP multi-line response too large (exceeds {} bytes)", MAX_FTP_RESPONSE_SIZE)
                    ));
                }
                let t = line.trim_end();
                if t.len() >= 4 && t[..4] == end_marker {
                    all_lines.push(t[4..].to_string());
                    break;
                }
                all_lines.push(t.to_string());
            }
            let text = all_lines.join("\n");
            let (ppc, pco, pi, tn, pn) = Self::classify(code);
            return Ok(FtpResponse {
                code,
                text,
                lines: all_lines,
                is_positive_preliminary: ppc,
                is_positive_completion: pco,
                is_positive_intermediate: pi,
                is_transient_negative: tn,
                is_permanent_negative: pn,
            });
        }

        let text = if trimmed.len() > 4 { trimmed[4..].trim().to_string() } else { String::new() };
        let text_clone = text.clone();
        let (ppc, pco, pi, tn, pn) = Self::classify(code);
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

    /// Read a response and verify it has the expected code.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to read from.
    /// * `expected_code` - The expected response code.
    ///
    /// # Returns
    ///
    /// The response text if the code matches.
    ///
    /// # Errors
    ///
    /// Returns `FtpCommandError::PermanentNegative` or `TransientNegative`
    /// for error responses, or `UnexpectedCode` for other mismatches.
    pub fn expect(transport: &mut dyn Transport<Error = io::Error>, expected_code: u16) -> Result<String, FtpCommandError> {
        let resp = Self::read(transport)?;
        if resp.code == expected_code {
            Ok(resp.text)
        } else if resp.is_permanent_negative {
            Err(FtpCommandError::PermanentNegative { code: resp.code, message: resp.text })
        } else if resp.is_transient_negative {
            Err(FtpCommandError::TransientNegative { code: resp.code, message: resp.text })
        } else {
            Err(FtpCommandError::UnexpectedCode { expected: expected_code, actual: resp.code, message: resp.text })
        }
    }

    /// Read a multi-line FTP response.
    ///
    /// This is an alias for `read()` which handles multi-line responses.
    pub fn read_multiline(transport: &mut dyn Transport<Error = io::Error>) -> Result<Self, FtpCommandError> {
        Self::read(transport)
    }
}

/// Errors that can occur during FTP command processing.
#[derive(Debug, thiserror::Error)]
pub enum FtpCommandError {
    /// An I/O error occurred.
    #[error("FTP I/O error: {0}")]
    Io(#[from] io::Error),
    /// The server response was malformed.
    #[error("malformed FTP response: {0}")]
    MalformedResponse(String),
    /// The response code did not match the expected value.
    #[error("FTP unexpected response code: expected {expected}, got {actual}: {message}")]
    UnexpectedCode { expected: u16, actual: u16, message: String },
    /// The server returned a permanent negative reply (5xx).
    #[error("FTP permanent negative reply {code}: {message}")]
    PermanentNegative { code: u16, message: String },
    /// The server returned a transient negative reply (4xx).
    #[error("FTP transient negative reply {code}: {message}")]
    TransientNegative { code: u16, message: String },
}
