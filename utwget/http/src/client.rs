//! HTTP Client implementation.
//!
//! This module provides the main HTTP client for making requests and handling
//! responses, including authentication, redirects, and content decoding.

use std::io::{self, Read, Write};
use std::sync::Arc;

use ut_core::config::Config;
use ut_core::types::{Credentials, HttpMethod, Scheme};
use ut_core::url::ParsedUrl;

use crate::auth::{self, AuthChallenge, AuthDispatcher};
use crate::chunked::ChunkedReader;
use crate::headers;
use crate::h1::H1Codec;
use crate::request::{self, HttpRequest};
use crate::response::HttpResponse;

/// Options for customizing an HTTP fetch request.
///
/// These options control how the request is built and sent, including
/// the HTTP method, body content, headers, and authentication behavior.
pub struct FetchOptions {
    /// The HTTP method to use (defaults to GET).
    pub method: Option<HttpMethod>,
    /// The request body for POST/PUT requests.
    pub body: Option<Vec<u8>>,
    /// Additional headers to include in the request.
    pub extra_headers: Vec<(String, String)>,
    /// Whether to route the request through a proxy.
    pub use_proxy: bool,
    /// Byte offset to resume from (for partial downloads).
    pub resume_from: Option<u64>,
    /// If-Modified-Since header value for conditional requests.
    pub if_modified_since: Option<chrono::DateTime<chrono::Utc>>,
    /// If-None-Match header value for conditional requests.
    pub if_none_match: Option<String>,
    /// Cookie header value.
    pub cookies: Option<String>,
}

impl Default for FetchOptions {
    /// Creates default fetch options for a simple GET request.
    fn default() -> Self {
        FetchOptions {
            method: None,
            body: None,
            extra_headers: Vec::new(),
            use_proxy: false,
            resume_from: None,
            if_modified_since: None,
            if_none_match: None,
            cookies: None,
        }
    }
}

/// Result of an HTTP fetch operation.
///
/// Contains the response status, headers, and an optional body reader.
pub struct FetchResult {
    /// The HTTP status code (e.g., 200, 404).
    pub status_code: u16,
    /// The complete HTTP response with headers.
    pub response: HttpResponse,
    /// A reader for the response body, if present.
    pub body_reader: Option<BodyReaderEnum>,
    /// Whether the response is a redirect.
    pub redirected: bool,
    /// Whether authentication was handled automatically.
    pub auth_handled: bool,
}

/// Enumeration of different body transfer modes.
///
/// HTTP response bodies can be transferred in different ways depending
/// on the headers present in the response.
pub enum BodyReaderEnum {
    /// Body with a known Content-Length.
    ContentLength {
        /// Number of bytes remaining to read.
        remaining: u64,
        /// The underlying transport.
        transport: Box<dyn Read + Send>,
        /// Optional decompressor for compressed content.
        #[cfg(feature = "compression")]
        decompressor: Option<crate::compression::Decompressor>,
    },
    /// Body using chunked transfer encoding.
    Chunked {
        /// The underlying transport.
        transport: Box<dyn Read + Send>,
        /// Optional decompressor for compressed content.
        #[cfg(feature = "compression")]
        decompressor: Option<crate::compression::Decompressor>,
    },
    /// Body with unknown length (read until connection close).
    ReadToEnd {
        /// The underlying transport.
        transport: Box<dyn Read + Send>,
        /// Optional decompressor for compressed content.
        #[cfg(feature = "compression")]
        decompressor: Option<crate::compression::Decompressor>,
    },
}

impl BodyReaderEnum {
    /// Reads the entire body and writes it to the output.
    ///
    /// Handles all three transfer modes transparently.
    ///
    /// # Arguments
    ///
    /// * `output` - The writer to receive the body data.
    ///
    /// # Returns
    ///
    /// The total number of bytes written.
    pub fn read_to_end(self, output: &mut dyn Write) -> io::Result<u64> {
        match self {
            BodyReaderEnum::ContentLength { remaining, transport, #[cfg(feature = "compression")] decompressor } => {
                read_exact(output, transport, remaining, decompressor)
            }
            BodyReaderEnum::Chunked { transport, #[cfg(feature = "compression")] decompressor } => {
                read_chunked(output, transport, decompressor)
            }
            BodyReaderEnum::ReadToEnd { transport, #[cfg(feature = "compression")] decompressor } => {
                read_until_eof(output, transport, decompressor)
            }
        }
    }
}
