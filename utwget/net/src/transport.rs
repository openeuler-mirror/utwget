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

impl Transport for TcpTransport {
    type Error = io::Error;

    /// Reads data from the TCP stream.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read data into.
    ///
    /// # Returns
    ///
    /// The number of bytes read on success, or an I/O error on failure.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream_mut()?.read(buf)
    }

    /// Writes all data to the TCP stream.
    ///
    /// This method writes all data in the buffer, blocking if necessary.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data to write.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an I/O error on failure.
    fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        let stream = self.stream_mut()?;
        stream.write_all(buf)?;
        stream.flush()?;
        Ok(())
    }

    /// Polls the TCP stream for readiness using `poll(2)`.
    ///
    /// # Arguments
    ///
    /// * `interest` - What operations to check for.
    /// * `timeout` - Maximum time to wait.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if ready, `Ok(false)` if timeout, or an I/O error.
    fn poll_ready(&mut self, interest: Interest, timeout: Duration) -> io::Result<bool> {
        let stream = self.stream_mut()?;
        let fd = stream.as_raw_fd();
        stream.set_nonblocking(true)?;

        let result = poll_fd(fd, interest, timeout);

        let _ = stream.set_nonblocking(false);
        result
    }

    /// Peeks data from the TCP stream without consuming it.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to peek data into.
    ///
    /// # Returns
    ///
    /// The number of bytes peeked on success, or an I/O error on failure.
    fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream_mut()?.peek(buf)
    }

    /// Closes the TCP stream.
    ///
    /// Shuts down both read and write sides of the connection.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an I/O error on failure.
    fn close(&mut self) -> io::Result<()> {
        if let Some(stream) = self.stream.take() {
            stream.shutdown(std::net::Shutdown::Both)?;
        }
        Ok(())
    }

    /// Checks if the TCP stream is still alive.
    ///
    /// This performs a non-blocking peek to check if the connection
    /// has been closed by the peer.
    ///
    /// # Returns
    ///
    /// `true` if the connection is alive, `false` otherwise.
    fn is_alive(&self) -> bool {
        self.stream.as_ref().map_or(false, |s| {
            s.set_nonblocking(true).is_ok()
                && match s.peek(&mut [0u8]) {
                    Ok(n) if n > 0 => {
                        let _ = s.set_nonblocking(false);
                        true
                    }
                    Ok(_) => {
                        let _ = s.set_nonblocking(false);
                        true
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        let _ = s.set_nonblocking(false);
                        true
                    }
                    Err(_) => false,
                }
        })
    }

    /// Returns a reference to the transport as `Any`.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Returns a mutable reference to the transport as `Any`.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Polls a file descriptor for readiness using `poll(2)`.
///
/// This is a Unix-specific implementation that uses the `poll` system call
/// to wait for the file descriptor to become ready for reading or writing.
///
/// # Arguments
///
/// * `fd` - The file descriptor to poll.
/// * `interest` - What operations to check for.
/// * `timeout` - Maximum time to wait. `Duration::MAX` means infinite wait.
///
/// # Returns
///
/// - `Ok(true)` - The file descriptor is ready.
/// - `Ok(false)` - The timeout expired.
/// - `Err(_)` - An error occurred during polling.
#[cfg(unix)]
pub(crate) fn poll_fd(fd: i32, interest: Interest, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    };

    if interest.readable {
        pfd.events |= libc::POLLIN;
    }
    if interest.writable {
        pfd.events |= libc::POLLOUT;
    }

    if pfd.events == 0 {
        return Ok(true);
    }

    let timeout_ms = if timeout == Duration::MAX {
        -1
    } else {
        timeout.as_millis().min(i32::MAX as u128) as i32
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };

    match ret {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(false),
        _ => Ok((pfd.revents & (libc::POLLIN | libc::POLLOUT | libc::POLLHUP | libc::POLLERR)) != 0),
    }
}

/// Polls a file descriptor for readiness (non-Unix fallback).
///
/// This is a simple fallback implementation for non-Unix platforms
/// that uses busy-waiting with sleep.
///
/// # Arguments
///
/// * `_fd` - The file descriptor (ignored).
/// * `interest` - What operations to check for.
/// * `timeout` - Maximum time to wait.
///
/// # Returns
///
/// `Ok(true)` if interested in readable/writable, `Ok(false)` on timeout.
#[cfg(not(unix))]
pub(crate) fn poll_fd(_fd: i32, interest: Interest, timeout: Duration) -> io::Result<bool> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if interest.readable {
            return Ok(true);
        }
        if interest.writable {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

impl std::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTransport")
            .field("alive", &self.stream.is_some())
            .finish()
    }
}
