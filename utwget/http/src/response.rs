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
