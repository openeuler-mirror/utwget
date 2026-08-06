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
