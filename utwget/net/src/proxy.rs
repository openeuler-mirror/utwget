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
