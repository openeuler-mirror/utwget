//! HTTP header constants and parsing utilities.
//!
//! This module provides constants for common HTTP header names and functions
//! for parsing and formatting header lines.

/// Content-Length header - indicates the size of the message body in bytes.
pub const CONTENT_LENGTH: &str = "Content-Length";

/// Content-Type header - indicates the media type of the resource.
pub const CONTENT_TYPE: &str = "Content-Type";

/// Content-Encoding header - indicates any encodings applied to the body.
pub const CONTENT_ENCODING: &str = "Content-Encoding";

/// Transfer-Encoding header - indicates the transformation applied to the body.
pub const TRANSFER_ENCODING: &str = "Transfer-Encoding";

/// Location header - used in redirects to specify the target URL.
pub const LOCATION: &str = "Location";

/// Set-Cookie header - used by servers to send cookies to the client.
pub const SET_COOKIE: &str = "Set-Cookie";

/// WWW-Authenticate header - indicates authentication scheme and parameters.
pub const WWW_AUTHENTICATE: &str = "WWW-Authenticate";

/// Proxy-Authenticate header - indicates proxy authentication requirements.
pub const PROXY_AUTHENTICATE: &str = "Proxy-Authenticate";

/// Last-Modified header - indicates the last modification date of the resource.
pub const LAST_MODIFIED: &str = "Last-Modified";

/// ETag header - provides an identifier for a specific version of a resource.
pub const ETAG: &str = "ETag";

/// Accept-Ranges header - indicates support for range requests.
pub const ACCEPT_RANGES: &str = "Accept-Ranges";

/// Connection header - controls connection behavior (keep-alive, close).
pub const CONNECTION: &str = "Connection";

/// Keep-Alive header - provides parameters for persistent connections.
pub const KEEP_ALIVE: &str = "Keep-Alive";

/// Server header - identifies the server software.
pub const SERVER: &str = "Server";

/// User-Agent header - identifies the client software.
pub const USER_AGENT: &str = "User-Agent";

/// Host header - specifies the domain name and port of the server.
pub const HOST: &str = "Host";

/// Accept header - specifies media types the client can process.
pub const ACCEPT: &str = "Accept";

/// Accept-Language header - specifies preferred natural languages.
pub const ACCEPT_LANGUAGE: &str = "Accept-Language";

/// Accept-Encoding header - specifies acceptable content encodings.
pub const ACCEPT_ENCODING: &str = "Accept-Encoding";

/// Range header - requests a specific range of bytes from the resource.
pub const RANGE: &str = "Range";

/// If-Modified-Since header - makes a request conditional on modification.
pub const IF_MODIFIED_SINCE: &str = "If-Modified-Since";

/// If-None-Match header - makes a request conditional on ETag.
pub const IF_NONE_MATCH: &str = "If-None-Match";

/// Authorization header - contains credentials for authentication.
pub const AUTHORIZATION: &str = "Authorization";

/// Cookie header - sends previously stored cookies to the server.
pub const COOKIE: &str = "Cookie";

/// Content-Disposition header - suggests how to display the content.
pub const CONTENT_DISPOSITION: &str = "Content-Disposition";

/// Retry-After header - indicates when to retry a failed request.
pub const RETRY_AFTER: &str = "Retry-After";

/// Date header - indicates the date and time the message was sent.
pub const DATE: &str = "Date";

/// Expires header - indicates when the response should be considered stale.
pub const EXPIRES: &str = "Expires";

/// Cache-Control header - specifies caching directives.
pub const CACHE_CONTROL: &str = "Cache-Control";

/// Proxy-Authorization header - contains credentials for proxy authentication.
pub const PROXY_AUTHORIZATION: &str = "Proxy-Authorization";

/// Referer header - indicates the previous page that linked to the resource.
pub const REFERER: &str = "Referer";

/// Content-Range header - specifies the range of bytes in a partial response.
pub const CONTENT_RANGE: &str = "Content-Range";

/// Vary header - indicates which headers affect the response representation.
pub const VARY: &str = "Vary";

/// X-Forwarded-For header - identifies the original client IP through proxies.
pub const X_FORWARDED_FOR: &str = "X-Forwarded-For";

/// Strict-Transport-Security header - enforces HTTPS connections.
pub const STRICT_TRANSPORT_SECURITY: &str = "Strict-Transport-Security";

/// Parses a single HTTP header line into key-value pair.
///
/// Header lines have the format `Key: Value`. Leading and trailing whitespace
/// around both key and value is trimmed.
///
/// # Arguments
///
/// * `line` - The header line to parse (may include trailing CRLF).
///
/// # Returns
///
/// `Some((key, value))` if the line is a valid header, `None` if no colon found.
///
/// # Example
///
/// ```
/// use ut_http::headers::parse_header_line;
///
/// let (key, value) = parse_header_line("Content-Type: text/html\r\n").unwrap();
/// assert_eq!(key, "Content-Type");
/// assert_eq!(value, "text/html");
/// ```
pub fn parse_header_line(line: &str) -> Option<(String, String)> {
    let line = line.trim_end_matches(|c| c == '\r' || c == '\n');
    let colon_idx = line.find(':')?;
    let key = line[..colon_idx].trim().to_string();
    let value = line[colon_idx + 1..].trim().to_string();
    Some((key, value))
}

/// Parses an HTTP status line into its components.
///
/// Status lines have the format `HTTP/1.1 200 OK`.
///
/// # Arguments
///
/// * `line` - The status line to parse (may include trailing CRLF).
///
/// # Returns
///
/// `Some((version, status_code, reason))` if the line is valid, `None` otherwise.
///
/// # Example
///
/// ```
/// use ut_http::headers::parse_status_line;
///
/// let (version, code, reason) = parse_status_line("HTTP/1.1 200 OK\r\n").unwrap();
/// assert_eq!(version, "HTTP/1.1");
/// assert_eq!(code, 200);
/// assert_eq!(reason, "OK");
/// ```
pub fn parse_status_line(line: &str) -> Option<(String, u16, String)> {
    let line = line.trim_end_matches(|c| c == '\r' || c == '\n');
    let space_idx = line.find(' ')?;
    let version = line[..space_idx].to_string();
    let rest = &line[space_idx + 1..];
    let next_space = rest.find(' ')?;
    let status_code: u16 = rest[..next_space].parse().ok()?;
    let reason = rest[next_space + 1..].to_string();
    Some((version, status_code, reason))
}

/// Formats a header key-value pair as an HTTP header line.
///
/// # Arguments
///
/// * `key` - The header name.
/// * `value` - The header value.
///
/// # Returns
///
/// A string in the format `Key: Value\r\n`.
///
/// # Example
///
/// ```
/// use ut_http::headers::format_header_line;
///
/// let line = format_header_line("Host", "example.com");
/// assert_eq!(line, "Host: example.com\r\n");
/// ```
pub fn format_header_line(key: &str, value: &str) -> String {
    format!("{}: {}\r\n", key, value)
}
