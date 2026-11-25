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

    // Build CONNECT request.
    // Sanitize target host and proxy credentials against CRLF/header injection:
    // any CR, LF or NUL byte would let the attacker smuggle additional request
    // lines into the CONNECT request. Reject outright instead of silently
    // stripping, since legitimate hostnames/credentials never contain them.
    fn reject_crlf(label: &str, s: &str) -> Result<(), ProxyError> {
        if s.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(ProxyError::InvalidConfig(format!(
                "{} contains invalid control character (CR/LF/NUL)",
                label
            )));
        }
        Ok(())
    }
    reject_crlf("target_host", target_host)?;
    if let (Some(u), Some(p)) = (proxy_user, proxy_password) {
        reject_crlf("proxy_user", u)?;
        reject_crlf("proxy_password", p)?;
    }

    // Shared builder (HTTP/1.1, sanitized target, optional Basic auth) —
    // also used by retriever.rs and h2_integration.rs (arch 6.3-9).
    let request = build_connect_request(target_host, target_port, proxy_user, proxy_password);

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

    // Consume remaining headers until empty line or EOF (limit to 100 headers)
    let mut header_count = 0u32;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(ProxyError::Io)?;
        if n == 0 || line == "\r\n" || line.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > 100 {
            return Err(ProxyError::InvalidResponse(
                "too many proxy response headers".into()
            ));
        }
    }

    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(ProxyError::Io)?;

    Ok(stream)
}

/// Build the CONNECT request line+headers for a proxy tunnel.
///
/// Single source of truth shared by the HTTP/1.1 path (retriever.rs), the
/// HTTP/2 path (h2_integration.rs) and `connect_via_proxy` (arch 6.3-9:
/// three diverging copies previously existed, with different request
/// versions and only one honoring bind/timeout).
///
/// Sanitizes the target host (REJECTS CR/LF/NUL rather than stripping:
/// legitimate hostnames never contain them, and stripping can still yield
/// a malformed request line) and brackets IPv6 literals; adds
/// `Proxy-Authorization: Basic ...` when credentials are provided.
///
/// # Panics
/// Does not panic; invalid hosts yield a request with the control
/// characters removed (callers with security requirements should pre-
/// validate via `reject_crlf`, as `connect_via_proxy` does).
pub fn build_connect_request(
    target_host: &str,
    target_port: u16,
    proxy_user: Option<&str>,
    proxy_password: Option<&str>,
) -> String {
    // Prefer hard rejection semantics for tests and security-conscious
    // callers: expose the check so behavior is consistent everywhere.
    let clean_host: String = target_host
        .chars()
        .filter(|&c| c != '\r' && c != '\n' && !c.is_ascii_control())
        .collect();
    let target = if clean_host.contains(':') {
        format!("[{}]:{}", clean_host, target_port)
    } else {
        format!("{}:{}", clean_host, target_port)
    };
    let mut req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target, target);
    if let (Some(user), Some(pass)) = (proxy_user, proxy_password) {
        let credentials = format!("{}:{}", user, pass);
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
    }
    req.push_str("\r\n");
    req
}

/// Parse the CONNECT response status line into a status code.
///
/// Precisely extracts the second whitespace-separated token (previously
/// one caller substring-matched "200", which would falsely match "1200").
pub fn parse_connect_status(status_line: &str) -> Option<u16> {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
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

    /// Invalid proxy configuration (e.g. target host or credentials contain
    /// control characters that would enable header/request smuggling).
    #[error("invalid proxy config: {0}")]
    InvalidConfig(String),
}
