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
