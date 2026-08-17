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
        log::debug!("FTP CMD: {}", cmd.trim_end());
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
        let mut line_bytes = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            let n = transport.read(&mut buf).map_err(FtpCommandError::Io)?;
            if n == 0 {
                return Err(FtpCommandError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")));
            }
            line_bytes.push(buf[0]);
            if buf[0] == b'\n' {
                break;
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
            loop {
                let line = Self::read_line_from(transport)?;
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
