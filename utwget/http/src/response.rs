//! HTTP response parsing and representation.
//!
//! This module provides types for representing HTTP responses and their headers,
//! along with functions for parsing response data from the network.

use crate::headers;

/// Represents a complete HTTP response.
///
/// Contains the status line (version, status code, reason phrase),
/// headers, and optionally the body.
///
/// # Example
///
/// ```ignore
/// use utwget_http::response::HttpResponse;
///
/// let resp = HttpResponse::new(
///     "HTTP/1.1".to_string(),
///     200,
///     "OK".to_string()
/// );
/// assert!(resp.is_success());
/// ```
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The HTTP version string (e.g., "HTTP/1.1").
    pub version: String,
    /// The HTTP status code (e.g., 200, 404).
    pub status_code: u16,
    /// The reason phrase (e.g., "OK", "Not Found").
    pub reason: String,
    /// The response headers.
    pub headers: HeaderMap,
    /// The response body, if loaded.
    pub body: Option<Vec<u8>>,
}

impl HttpResponse {
    /// Creates a new HTTP response with the given status line components.
    ///
    /// # Arguments
    ///
    /// * `version` - The HTTP version string.
    /// * `status_code` - The numeric status code.
    /// * `reason` - The reason phrase.
    ///
    /// # Returns
    ///
    /// A new `HttpResponse` with empty headers and no body.
    pub fn new(version: String, status_code: u16, reason: String) -> Self {
        HttpResponse {
            version,
            status_code,
            reason,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    /// Returns whether the response is informational (1xx).
    ///
    /// # Returns
    ///
    /// `true` if the status code is in the 100-199 range.
    pub fn is_informational(&self) -> bool {
        (200..600).contains(&self.status_code) && self.status_code < 200
    }

    /// Returns whether the response indicates success (2xx).
    ///
    /// # Returns
    ///
    /// `true` if the status code is in the 200-299 range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Returns whether the response is a redirect (3xx).
    ///
    /// # Returns
    ///
    /// `true` if the status code is in the 300-399 range.
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status_code)
    }

    /// Returns whether the response is a client error (4xx).
    ///
    /// # Returns
    ///
    /// `true` if the status code is in the 400-499 range.
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status_code)
    }

    /// Returns whether the response is a server error (5xx).
    ///
    /// # Returns
    ///
    /// `true` if the status code is in the 500-599 range.
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status_code)
    }

    /// Returns whether the response is "Not Modified" (304).
    ///
    /// This indicates a successful conditional request where the
    /// cached content is still valid.
    ///
    /// # Returns
    ///
    /// `true` if the status code is 304.
    pub fn not_modified(&self) -> bool {
        self.status_code == 304
    }

    /// Returns the Location header value for redirects.
    ///
    /// # Returns
    ///
    /// The redirect URL, or `None` if not present.
    pub fn location(&self) -> Option<&str> {
        self.headers.get(headers::LOCATION)
    }

    /// Returns the Content-Length header value.
    ///
    /// # Returns
    ///
    /// The content length in bytes, or `None` if not present or invalid.
    pub fn content_length(&self) -> Option<u64> {
        self.headers.content_length()
    }

    /// Returns whether the response uses chunked transfer encoding.
    ///
    /// # Returns
    ///
    /// `true` if the Transfer-Encoding header includes "chunked".
    pub fn is_chunked(&self) -> bool {
        self.headers.is_chunked()
    }

    /// Returns whether the connection should be kept alive.
    ///
    /// For HTTP/1.1, connections are keep-alive by default unless
    /// the Connection header specifies "close".
    ///
    /// # Returns
    ///
    /// `true` if the connection should be kept alive.
    pub fn keep_alive(&self) -> bool {
        let conn = self.headers.get(headers::CONNECTION);
        match conn {
            Some(v) => !v.eq_ignore_ascii_case("close"),
            None => self.version == "HTTP/1.1",
        }
    }
}
