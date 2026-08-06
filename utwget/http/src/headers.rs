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
