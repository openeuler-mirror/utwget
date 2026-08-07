//! HTTP request building and serialization.
//!
//! This module provides types and functions for constructing HTTP requests,
//! including request line, headers, and body.

use std::fmt;
use std::io::{self, Write};

/// HTTP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// HTTP/1.0 - original version, no persistent connections by default.
    Http10,
    /// HTTP/1.1 - supports persistent connections and chunked encoding.
    Http11,
    /// HTTP/2 - binary protocol with multiplexing, header compression, and server push.
    Http2,
}

impl Default for HttpVersion {
    /// Returns HTTP/1.1 as the default version.
    fn default() -> Self {
        HttpVersion::Http11
    }
}

impl fmt::Display for HttpVersion {
    /// Formats the version as it appears in request/status lines.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpVersion::Http10 => f.write_str("HTTP/1.0"),
            HttpVersion::Http11 => f.write_str("HTTP/1.1"),
            HttpVersion::Http2 => f.write_str("HTTP/2"),
        }
    }
}

impl HttpVersion {
    /// Returns whether this version supports persistent connections.
    pub fn supports_keep_alive(&self) -> bool {
        matches!(self, HttpVersion::Http11 | HttpVersion::Http2)
    }

    /// Returns whether this version supports chunked transfer encoding.
    pub fn supports_chunked(&self) -> bool {
        matches!(self, HttpVersion::Http11)
    }

    /// Returns whether this is HTTP/2.
    pub fn is_http2(&self) -> bool {
        matches!(self, HttpVersion::Http2)
    }
}

/// Represents an HTTP request ready to be serialized and sent.
///
/// Contains the request line (method, path, host), headers, and optional body.
///
/// # Example
///
/// ```ignore
/// use utwget_http::request::{HttpRequest, HttpVersion, HttpMethod};
///
/// let mut req = HttpRequest::new(
///     HttpMethod::Get,
///     "/path".to_string(),
///     "example.com".to_string()
/// );
/// req.header("Accept", "*/*");
///
/// let bytes = req.serialize().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The HTTP method (GET, POST, etc.).
    pub method: crate::request::HttpMethod,
    /// The request path including query string.
    pub path: String,
    /// The host header value (may include port).
    pub host: String,
    /// The HTTP version to use.
    pub version: HttpVersion,
    /// The request headers.
    pub headers: Vec<(String, String)>,
    /// The request body, if any.
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// Creates a new HTTP request.
    ///
    /// # Arguments
    ///
    /// * `method` - The HTTP method.
    /// * `path` - The request path (e.g., `/path?query`).
    /// * `host` - The host header value.
    ///
    /// # Returns
    ///
    /// A new `HttpRequest` with no headers or body.
    pub fn new(method: crate::request::HttpMethod, path: String, host: String) -> Self {
        HttpRequest {
            method,
            path,
            host,
            version: HttpVersion::default(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Adds a header to the request.
    ///
    /// Headers are added in order; duplicate headers are allowed.
    ///
    /// # Arguments
    ///
    /// * `key` - The header name.
    /// * `value` - The header value.
    pub fn header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.headers.push((key.into(), value.into()));
    }

    /// Gets a header value by name (case-insensitive).
    ///
    /// Returns the first matching header if multiple exist.
    ///
    /// # Arguments
    ///
    /// * `key` - The header name to look up.
    ///
    /// # Returns
    ///
    /// The header value, or `None` if not found.
    pub fn get_header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// Removes all headers with the given name (case-insensitive).
    ///
    /// # Arguments
    ///
    /// * `key` - The header name to remove.
    pub fn remove_header(&mut self, key: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
    }

    /// Serializes the request to bytes ready to send over the network.
    ///
    /// The output includes the request line, all headers, a blank line,
    /// and the body if present.
    ///
    /// # Returns
    ///
    /// The serialized request bytes.
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);

        write!(buf, "{} {} {}\r\n", self.method, self.path, self.version)?;

        for (key, value) in &self.headers {
            write!(buf, "{}: {}\r\n", key, value)?;
        }

        buf.extend_from_slice(b"\r\n");

        if let Some(ref body) = self.body {
            buf.extend_from_slice(body);
        }

        Ok(buf)
    }

    /// Parses the Content-Length header value.
    ///
    /// # Returns
    ///
    /// The content length, or `None` if the header is missing or invalid.
    pub fn content_length(&self) -> Option<u64> {
        self.get_header("Content-Length")
            .and_then(|v| v.parse::<u64>().ok())
    }
}
