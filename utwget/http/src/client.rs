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
