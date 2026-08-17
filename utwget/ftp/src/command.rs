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
