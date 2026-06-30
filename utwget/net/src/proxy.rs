//! HTTP proxy connection support.
//!
//! This module provides functionality for establishing connections through
//! HTTP proxies using the CONNECT method. It supports:
//!
//! - HTTP CONNECT tunneling for HTTPS connections
//! - Basic authentication (username/password)
//! - Configurable connection and read timeouts
//!
//! # How It Works
//!
//! When connecting through an HTTP proxy to a target server:
//!
//! 1. A TCP connection is established to the proxy server
//! 2. A CONNECT request is sent: `CONNECT target:port HTTP/1.0`
//! 3. If authentication is required, a `Proxy-Authorization` header is included
//! 4. The proxy responds with `200 Connection Established` on success
//! 5. The TCP stream can then be used for TLS handshake or plain data

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Establishes a TCP connection through an HTTP proxy.
///
/// This function connects to an HTTP proxy and sends a CONNECT request
/// to establish a tunnel to the target host. The returned `TcpStream`
/// can be used for further communication (e.g., TLS handshake).
///
/// # Arguments
///
/// * `proxy_host` - The hostname or IP address of the proxy server.
/// * `proxy_port` - The port number of the proxy server.
/// * `target_host` - The hostname of the target server to connect to.
/// * `target_port` - The port number of the target server.
/// * `connect_timeout` - Timeout for establishing the initial connection to the proxy.
/// * `read_timeout` - Timeout for reading the proxy response.
/// * `proxy_user` - Optional username for proxy authentication.
/// * `proxy_password` - Optional password for proxy authentication.
///
/// # Returns
///
/// A `TcpStream` connected through the proxy on success.
///
/// # Errors
///
/// Returns a `ProxyError` if:
/// - DNS resolution of the proxy fails
/// - Connection to the proxy fails
/// - The proxy returns an invalid response
/// - The proxy rejects the CONNECT request (non-200 status)
/// - An I/O error occurs during the handshake
///
/// # Example
///
/// ```ignore
/// use std::time::Duration;
///
/// let stream = connect_via_proxy(
///     "proxy.example.com",
///     8080,
///     "target.example.com",
///     443,
///     Duration::from_secs(30),
///     Duration::from_secs(60),
///     Some("user"),
///     Some("pass"),
/// )?;
/// ```
pub fn connect_via_proxy(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    connect_timeout: Duration,
    read_timeout: Duration,
    proxy_user: Option<&str>,
    proxy_password: Option<&str>,
) -> Result<TcpStream, ProxyError> {
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);
    let mut stream = connect_with_timeout(&proxy_addr, connect_timeout)?;

    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(ProxyError::Io)?;

    // Build CONNECT request
    let target = format!("{}:{}", target_host, target_port);
    let mut request = format!("CONNECT {} HTTP/1.0\r\nHost: {}\r\n", target, target);

    // Add authentication if provided
    if let (Some(user), Some(pass)) = (proxy_user, proxy_password) {
        let credentials = format!("{}:{}", user, pass);
        let mut encoded = vec![0u8; base64_encode_len(credentials.len())];
        let n = simple_base64_encode(credentials.as_bytes(), &mut encoded);
        encoded.truncate(n);
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            String::from_utf8_lossy(&encoded)
        ));
    }

    request.push_str("\r\n");

    // Send CONNECT request
    stream
        .write_all(request.as_bytes())
        .map_err(ProxyError::Io)?;
    stream.flush().map_err(ProxyError::Io)?;

    // Read response
    let mut reader = BufReader::new(&mut stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(ProxyError::Io)?;

    let status_code = parse_proxy_status(&response_line)?;

    // Check for successful connection
    if status_code != 200 {
        let mut body = String::new();
        reader.read_line(&mut body).ok();
        reader.read_line(&mut body).ok();
        reader.read_to_string(&mut body).ok();
        return Err(ProxyError::ProxyRejected {
            status: status_code,
            response: response_line.trim().to_string(),
            body: body.trim().to_string(),
        });
    }

    // Consume remaining headers
    while {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(ProxyError::Io)?;
        line
    } != "\r\n"
    {}

    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(ProxyError::Io)?;

    Ok(stream)
}

/// Connects to a proxy server with a timeout.
///
/// # Arguments
///
/// * `addr` - The proxy address string (e.g., "proxy.example.com:8080").
/// * `timeout` - Connection timeout.
///
/// # Returns
///
/// A `TcpStream` connected to the proxy on success.
///
/// # Errors
///
/// Returns a `ProxyError` if DNS resolution or connection fails.
fn connect_with_timeout(addr: &str, timeout: Duration) -> Result<TcpStream, ProxyError> {
    let socket_addrs: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|e| ProxyError::DnsFailed(e.to_string()))?
        .collect();

    if socket_addrs.is_empty() {
        return Err(ProxyError::DnsFailed(format!("no addresses for {}", addr)));
    }

    let mut last_err = None;
    for sa in &socket_addrs {
        match TcpStream::connect_timeout(sa, timeout) {
            Ok(s) => {
                s.set_read_timeout(Some(timeout))
                    .map_err(ProxyError::Io)?;
                s.set_write_timeout(Some(timeout))
                    .map_err(ProxyError::Io)?;
                return Ok(s);
            }
            Err(e) => {
                log::debug!("proxy connect to {} failed: {}", sa, e);
                last_err = Some(e);
            }
        }
    }

    Err(ProxyError::ConnectFailed(
        last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "no proxy addresses")),
    ))
}

/// Parses the HTTP status code from a proxy response line.
///
/// # Arguments
///
/// * `line` - The HTTP response line (e.g., "HTTP/1.0 200 Connection Established").
///
/// # Returns
///
/// The HTTP status code (e.g., 200) on success.
///
/// # Errors
///
/// Returns `ProxyError::InvalidResponse` if the line cannot be parsed.
fn parse_proxy_status(line: &str) -> Result<u16, ProxyError> {
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(ProxyError::InvalidResponse(line.trim().to_string()));
    }

    let status = parts[1]
        .parse::<u16>()
        .map_err(|_| ProxyError::InvalidResponse(line.trim().to_string()))?;

    Ok(status)
}

/// Calculates the length of a base64-encoded string.
///
/// # Arguments
///
/// * `input_len` - The length of the input bytes.
///
/// # Returns
///
/// The required length of the output buffer for base64 encoding.
fn base64_encode_len(input_len: usize) -> usize {
    ((input_len + 2) / 3) * 4
}

/// Performs a simple base64 encoding.
///
/// This is a minimal implementation that does not require external dependencies.
///
/// # Arguments
///
/// * `input` - The bytes to encode.
/// * `output` - The output buffer (must be at least `base64_encode_len(input.len())` bytes).
///
/// # Returns
///
/// The number of bytes written to the output buffer.
fn simple_base64_encode(input: &[u8], output: &mut [u8]) -> usize {
    const ENTABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out_idx = 0;
    let chunks = input.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 {
            chunk[1] as u32
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as u32
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        output[out_idx] = ENTABLE[((triple >> 18) & 0x3F) as usize];
        output[out_idx + 1] = ENTABLE[((triple >> 12) & 0x3F) as usize];
        out_idx += 2;

        if chunk.len() > 1 {
            output[out_idx] = ENTABLE[((triple >> 6) & 0x3F) as usize];
            out_idx += 1;
        }
        if chunk.len() > 2 {
            output[out_idx] = ENTABLE[(triple & 0x3F) as usize];
            out_idx += 1;
        }
    }

    let rem = input.len() % 3;
    if rem == 1 {
        output[out_idx] = b'=';
        output[out_idx + 1] = b'=';
        out_idx += 2;
    } else if rem == 2 {
        output[out_idx] = b'=';
        out_idx += 1;
    }

    out_idx
}

/// Error type for proxy connection operations.
///
/// This enum covers all possible failure modes when connecting
/// through an HTTP proxy.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// DNS resolution of the proxy hostname failed.
    #[error("proxy DNS resolution failed: {0}")]
    DnsFailed(String),

    /// Failed to establish a TCP connection to the proxy.
    #[error("failed to connect to proxy: {0}")]
    ConnectFailed(#[source] io::Error),

    /// I/O error during proxy communication.
    #[error("proxy I/O error: {0}")]
    Io(#[source] io::Error),

    /// The proxy returned an invalid or malformed response.
    #[error("invalid proxy response: {0}")]
    InvalidResponse(String),

    /// The proxy rejected the CONNECT request.
    ///
    /// This typically occurs when authentication fails or the
    /// target host is not allowed by proxy policy.
    #[error("proxy rejected CONNECT (HTTP {status}): {response}")]
    ProxyRejected {
        /// The HTTP status code returned by the proxy.
        status: u16,
        /// The response line from the proxy.
        response: String,
        /// The response body (if any).
        body: String,
    },
}
