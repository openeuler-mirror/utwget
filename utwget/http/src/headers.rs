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
