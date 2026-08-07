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
