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
