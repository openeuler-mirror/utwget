//! Transport abstraction layer.
//!
//! This module provides a trait-based abstraction for network transports,
//! allowing the same interface to be used for both plain TCP and TLS
//! connections. It supports:
//!
//! - Read and write operations
//! - Readiness polling for async-like behavior
//! - Connection state checking
//! - Type erasure for dynamic dispatch
//!
//! # Example
//!
//! ```ignore
//! use utwget_net::transport::{Transport, TcpTransport, Interest};
//! use std::time::Duration;
//!
//! let mut transport = TcpTransport::new(tcp_stream);
//!
//! // Write data
//! transport.write(b"GET / HTTP/1.1\r\n\r\n")?;
//!
//! // Poll for readiness
//! let ready = transport.poll_ready(Interest::READABLE, Duration::from_secs(10))?;
//!
//! // Read response
//! let mut buf = vec![0u8; 1024];
//! let n = transport.read(&mut buf)?;
//! ```

use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::net::TcpStream;
use std::time::Duration;

/// Trait for network transport implementations.
///
/// This trait provides a common interface for both plain TCP and TLS
/// connections. Implementations must support reading, writing, polling
/// for readiness, and connection state checking.
///
/// # Type Parameter
///
/// * `Error` - The error type for operations. Must implement `Error + Send + Sync + 'static`.
///
/// # Implementors
///
/// - `TcpTransport` - Plain TCP connections (error: `io::Error`)
/// - TLS transports - Secure connections (error: `TlsError`)
pub trait Transport {
    /// The error type for transport operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Reads data from the transport.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read data into.
    ///
    /// # Returns
    ///
    /// The number of bytes read on success, or an error on failure.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Writes data to the transport.
    ///
    /// This method writes all data in the buffer, blocking if necessary.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data to write.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error on failure.
    fn write(&mut self, buf: &[u8]) -> Result<(), Self::Error>;

    /// Polls the transport for readiness.
    ///
    /// Checks whether the transport is ready for reading or writing
    /// within the specified timeout.
    ///
    /// # Arguments
    ///
    /// * `interest` - What operations to check for (readable/writable).
    /// * `timeout` - Maximum time to wait for readiness.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - The transport is ready for the requested operation(s).
    /// - `Ok(false)` - The timeout expired before the transport became ready.
    /// - `Err(_)` - An error occurred during polling.
    fn poll_ready(&mut self, interest: Interest, timeout: Duration) -> Result<bool, Self::Error>;

    /// Peeks data from the transport without consuming it.
    ///
    /// The peeked data will still be available for subsequent reads.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to peek data into.
    ///
    /// # Returns
    ///
    /// The number of bytes peeked on success, or an error on failure.
    fn peek(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Closes the transport.
    ///
    /// This shuts down both the read and write sides of the connection.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error on failure.
    fn close(&mut self) -> Result<(), Self::Error>;

    /// Checks if the transport is still alive.
    ///
    /// This performs a non-blocking check to see if the connection
    /// has been closed by the peer.
    ///
    /// # Returns
    ///
    /// `true` if the connection is alive, `false` otherwise.
    fn is_alive(&self) -> bool;

    /// Returns a reference to the transport as `Any`.
    ///
    /// This enables downcasting to concrete transport types.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Returns a mutable reference to the transport as `Any`.
    ///
    /// This enables downcasting to concrete transport types.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// Specifies what operations to poll for.
///
/// This is used with [`Transport::poll_ready`] to specify
/// which operations (readable, writable, or both) to wait for.
#[derive(Debug, Clone, Copy)]
pub struct Interest {
    /// Wait for the transport to be readable.
    pub readable: bool,
    /// Wait for the transport to be writable.
    pub writable: bool,
}

impl Interest {
    /// Interest in readable operations only.
    pub const READABLE: Interest = Interest { readable: true, writable: false };

    /// Interest in writable operations only.
    pub const WRITABLE: Interest = Interest { readable: false, writable: true };

    /// Interest in both readable and writable operations.
    pub const BOTH: Interest = Interest { readable: true, writable: true };
}

/// TCP transport implementation.
///
/// Wraps a `TcpStream` and implements the `Transport` trait for
/// plain TCP connections.
///
/// # Example
///
/// ```ignore
/// use std::net::TcpStream;
/// use utwget_net::transport::TcpTransport;
///
/// let stream = TcpStream::connect("example.com:80")?;
/// let transport = TcpTransport::new(stream);
/// ```
pub struct TcpTransport {
    /// The underlying TCP stream, or `None` if taken/closed.
    stream: Option<TcpStream>,
}

impl TcpTransport {
    /// Creates a new TCP transport from a `TcpStream`.
    ///
    /// # Arguments
    ///
    /// * `stream` - The TCP stream to wrap.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::net::TcpStream;
    /// use utwget_net::transport::TcpTransport;
    ///
    /// let stream = TcpStream::connect("example.com:80")?;
    /// let transport = TcpTransport::new(stream);
    /// ```
    pub fn new(stream: TcpStream) -> Self {
        Self { stream: Some(stream) }
    }

    /// Takes the underlying `TcpStream` out of the transport.
    ///
    /// After calling this method, the transport is no longer usable.
    ///
    /// # Returns
    ///
    /// The `TcpStream` on success, or an error if the stream was already taken.
    pub fn take_stream(&mut self) -> io::Result<TcpStream> {
        self.stream
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stream already taken"))
    }

    /// Returns a reference to the underlying `TcpStream`.
    ///
    /// # Returns
    ///
    /// A reference to the stream, or an error if the stream was taken.
    pub fn stream_ref(&self) -> io::Result<&TcpStream> {
        self.stream
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stream already taken"))
    }

    /// Returns a mutable reference to the underlying `TcpStream`.
    ///
    /// # Returns
    ///
    /// A mutable reference to the stream, or an error if the stream was taken.
    pub fn stream_mut(&mut self) -> io::Result<&mut TcpStream> {
        self.stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stream already taken"))
    }

    /// Sets the read timeout for the underlying stream.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The read timeout, or `None` to disable.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if the stream was taken.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream_mut()?.set_read_timeout(timeout)
    }

    /// Sets the write timeout for the underlying stream.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The write timeout, or `None` to disable.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if the stream was taken.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream_mut()?.set_write_timeout(timeout)
    }

    /// Sets the non-blocking mode for the underlying stream.
    ///
    /// # Arguments
    ///
    /// * `nonblocking` - `true` for non-blocking, `false` for blocking.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if the stream was taken.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.stream_mut()?.set_nonblocking(nonblocking)
    }
}
