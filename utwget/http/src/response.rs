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

/// A case-insensitive map for HTTP headers.
///
/// Headers are stored in order and can be looked up case-insensitively.
/// Multiple values for the same header name are preserved.
#[derive(Debug, Clone)]
pub struct HeaderMap(Vec<(String, String)>);

impl HeaderMap {
    /// Creates an empty header map.
    ///
    /// # Returns
    ///
    /// A new `HeaderMap` with no headers.
    pub fn new() -> Self {
        HeaderMap(Vec::new())
    }

    /// Creates an empty header map with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The number of headers to pre-allocate space for.
    ///
    /// # Returns
    ///
    /// A new `HeaderMap` with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        HeaderMap(Vec::with_capacity(capacity))
    }

    /// Adds a header to the map.
    ///
    /// Unlike a standard map, this allows duplicate header names.
    ///
    /// # Arguments
    ///
    /// * `key` - The header name.
    /// * `value` - The header value.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.push((key.into(), value.into()));
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
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// Gets all values for a header name (case-insensitive).
    ///
    /// # Arguments
    ///
    /// * `key` - The header name to look up.
    ///
    /// # Returns
    ///
    /// A vector of all matching header values.
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Checks if a header exists (case-insensitive).
    ///
    /// # Arguments
    ///
    /// * `key` - The header name to check.
    ///
    /// # Returns
    ///
    /// `true` if the header exists.
    pub fn contains(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k.eq_ignore_ascii_case(key))
    }

    /// Removes all headers with the given name (case-insensitive).
    ///
    /// # Arguments
    ///
    /// * `key` - The header name to remove.
    pub fn remove(&mut self, key: &str) {
        self.0.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
    }

    /// Returns whether the Transfer-Encoding header includes "chunked".
    ///
    /// # Returns
    ///
    /// `true` if chunked encoding is specified.
    pub fn is_chunked(&self) -> bool {
        self.get(headers::TRANSFER_ENCODING)
            .map(|v| v.split(',').any(|s| s.trim().eq_ignore_ascii_case("chunked")))
            .unwrap_or(false)
    }

    /// Returns whether the Content-Encoding header includes "gzip".
    ///
    /// # Returns
    ///
    /// `true` if gzip encoding is specified.
    pub fn is_gzip(&self) -> bool {
        self.get(headers::CONTENT_ENCODING)
            .map(|v| {
                v.split(',')
                    .any(|s| s.trim().eq_ignore_ascii_case("gzip") || s.trim().eq_ignore_ascii_case("x-gzip"))
            })
            .unwrap_or(false)
    }

    /// Returns whether the Content-Encoding header includes "deflate".
    ///
    /// # Returns
    ///
    /// `true` if deflate encoding is specified.
    pub fn is_deflate(&self) -> bool {
        self.get(headers::CONTENT_ENCODING)
            .map(|v| v.split(',').any(|s| s.trim().eq_ignore_ascii_case("deflate")))
            .unwrap_or(false)
    }

    /// Returns the Content-Length header value as a number.
    ///
    /// # Returns
    ///
    /// The content length in bytes, or `None` if missing or invalid.
    pub fn content_length(&self) -> Option<u64> {
        self.get(headers::CONTENT_LENGTH).and_then(|v| v.parse::<u64>().ok())
    }

    /// Returns the Content-Type header value.
    ///
    /// # Returns
    ///
    /// The content type, or `None` if not present.
    pub fn content_type(&self) -> Option<&str> {
        self.get(headers::CONTENT_TYPE)
    }

    /// Returns the Last-Modified header value.
    ///
    /// # Returns
    ///
    /// The last modified date string, or `None` if not present.
    pub fn last_modified(&self) -> Option<&str> {
        self.get(headers::LAST_MODIFIED)
    }

    /// Returns the ETag header value.
    ///
    /// # Returns
    ///
    /// The entity tag, or `None` if not present.
    pub fn etag(&self) -> Option<&str> {
        self.get(headers::ETAG)
    }

    /// Returns the Server header value.
    ///
    /// # Returns
    ///
    /// The server identification string, or `None` if not present.
    pub fn server(&self) -> Option<&str> {
        self.get(headers::SERVER)
    }

    /// Returns whether the server accepts byte range requests.
    ///
    /// # Returns
    ///
    /// `true` if the Accept-Ranges header is "bytes".
    pub fn accept_ranges(&self) -> bool {
        self.get(headers::ACCEPT_RANGES)
            .map(|v| v.eq_ignore_ascii_case("bytes"))
            .unwrap_or(false)
    }

    /// Returns the Location header value.
    ///
    /// # Returns
    ///
    /// The redirect location URL, or `None` if not present.
    pub fn location(&self) -> Option<&str> {
        self.get(headers::LOCATION)
    }

    /// Returns the Content-Disposition header value.
    ///
    /// # Returns
    ///
    /// The content disposition string, or `None` if not present.
    pub fn content_disposition(&self) -> Option<&str> {
        self.get(headers::CONTENT_DISPOSITION)
    }

    /// Returns the Retry-After header value as seconds.
    ///
    /// # Returns
    ///
    /// The retry delay in seconds, or `None` if missing or invalid.
    pub fn retry_after(&self) -> Option<u64> {
        self.get(headers::RETRY_AFTER).and_then(|v| v.parse::<u64>().ok())
    }

    /// Returns all Set-Cookie header values.
    ///
    /// # Returns
    ///
    /// A vector of all cookie strings.
    pub fn set_cookies(&self) -> Vec<&str> {
        self.get_all(headers::SET_COOKIE)
    }

    /// Returns all WWW-Authenticate header values.
    ///
    /// # Returns
    ///
    /// A vector of all authentication challenge strings.
    pub fn www_authenticate(&self) -> Vec<&str> {
        self.get_all(headers::WWW_AUTHENTICATE)
    }

    /// Returns all Proxy-Authenticate header values.
    ///
    /// # Returns
    ///
    /// A vector of all proxy authentication challenge strings.
    pub fn proxy_authenticate(&self) -> Vec<&str> {
        self.get_all(headers::PROXY_AUTHENTICATE)
    }

    /// Returns the Content-Encoding header value.
    ///
    /// # Returns
    ///
    /// The content encoding string, or `None` if not present.
    pub fn content_encoding(&self) -> Option<&str> {
        self.get(headers::CONTENT_ENCODING)
    }

    /// Returns an iterator over all headers.
    ///
    /// # Returns
    ///
    /// An iterator yielding `(key, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = &(String, String)> {
        self.0.iter()
    }

    /// Consumes the map and returns the underlying vector.
    ///
    /// # Returns
    ///
    /// The vector of header pairs.
    pub fn into_inner(self) -> Vec<(String, String)> {
        self.0
    }
}

impl Default for HeaderMap {
    /// Creates an empty header map.
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<(String, String)>> for HeaderMap {
    /// Creates a header map from a vector of header pairs.
    fn from(v: Vec<(String, String)>) -> Self {
        HeaderMap(v)
    }
}

/// Parses an HTTP response from raw bytes.
///
/// The input should contain the status line and all headers,
/// terminated by a blank line. Any body data after the headers
/// is ignored.
///
/// # Arguments
///
/// * `data` - The raw response bytes.
///
/// # Returns
///
/// The parsed `HttpResponse`, or `None` if parsing fails.
///
/// # Example
///
/// ```
/// use ut_http::response::parse_response_head;
///
/// let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
/// let resp = parse_response_head(raw).unwrap();
/// assert_eq!(resp.status_code, 200);
/// ```
pub fn parse_response_head(data: &[u8]) -> Option<HttpResponse> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;

    let (version, status_code, reason) = headers::parse_status_line(status_line)?;

    let mut resp = HttpResponse::new(version, status_code, reason);

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = headers::parse_header_line(line) {
            resp.headers.insert(key, value);
        }
    }

    Some(resp)
}
