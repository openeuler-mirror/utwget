//! Type definitions for the retriever module.
//!
//! This module defines the core types used throughout the retriever,
//! including request options, response metadata, error types, and
//! document flags.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ut_core::types::HttpMethod;
use ut_core::WgetError;

bitflags::bitflags! {
    /// Flags describing document properties and retrieval behavior.
    ///
    /// These flags are used to track document characteristics and
    /// control how documents are processed during retrieval.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DocumentFlags: u16 {
        /// Document is HTML content.
        const TEXT_HTML = 0x0001;
        /// Document is ready for retrieval.
        const RETRIEVAL_OK = 0x0002;
        /// Only HEAD request needed.
        const HEAD_ONLY = 0x0004;
        /// Do not cache this document.
        const NO_CACHE = 0x0008;
        /// Server accepts range requests.
        const ACCEPT_RANGES = 0x0010;
        /// HTML extension was added to filename.
        const HTML_EXT_ADDED = 0x0020;
        /// Document is CSS content.
        const TEXT_CSS = 0x0040;
        /// Conditional request (If-Modified-Since).
        const IF_MODIFIED = 0x0080;
        /// Document contains Metalink metadata.
        const METALINK_META = 0x0100;
    }
}

/// Options for constructing an HTTP/FTP request.
///
/// This struct holds all configurable parameters for a single request,
/// including method, headers, authentication, and conditional request options.
#[derive(Debug, Clone)]
pub struct RequestOptions {
    /// Whether to use a proxy for this request.
    pub use_proxy: bool,
    /// HTTP method (GET, POST, HEAD, etc.).
    pub method: HttpMethod,
    /// Additional headers to include in the request.
    pub headers: Vec<(String, String)>,
    /// POST data for form submissions.
    pub post_data: Option<Vec<u8>>,
    /// Request body data for custom methods.
    pub body_data: Option<Vec<u8>>,
    /// Referer header value.
    pub referer: Option<String>,
    /// Start position for range requests (resume).
    pub range_start: Option<u64>,
    /// If-Modified-Since header for conditional requests.
    pub if_modified_since: Option<DateTime<Utc>>,
    /// If-None-Match header for ETag-based conditional requests.
    pub if_none_match: Option<String>,
    /// Send authentication without waiting for challenge.
    pub auth_without_challenge: bool,
    /// Save response headers to a separate file.
    pub save_headers: bool,
    /// Return content even for error responses.
    pub content_on_error: bool,
}

impl Default for RequestOptions {
    fn default() -> Self {
        RequestOptions {
            use_proxy: true,
            method: HttpMethod::Get,
            headers: Vec::new(),
            post_data: None,
            body_data: None,
            referer: None,
            range_start: None,
            if_modified_since: None,
            if_none_match: None,
            auth_without_challenge: false,
            save_headers: false,
            content_on_error: false,
        }
    }
}

/// Metadata extracted from an HTTP response.
///
/// Contains all relevant information from the response headers and status
/// that is needed for download processing and link extraction.
#[derive(Debug, Clone)]
pub struct ResponseMeta {
    /// HTTP status code (e.g., 200, 404).
    pub status_code: u16,
    /// Content-Length header value, if present.
    pub content_length: Option<u64>,
    /// Content-Type header value, if present.
    pub content_type: Option<String>,
    /// Last-Modified header parsed as UTC datetime.
    pub last_modified: Option<DateTime<Utc>>,
    /// Whether Accept-Ranges header indicates range support.
    pub accept_ranges: bool,
    /// Location header for redirects.
    pub location: Option<String>,
    /// ETag header value.
    pub etag: Option<String>,
    /// Server header value.
    pub server: Option<String>,
    /// Document flags indicating content type and properties.
    pub document_flags: DocumentFlags,
    /// Whether the connection can be kept alive.
    pub keep_alive: bool,
}

/// Result of downloading a response body.
///
/// Contains statistics about the download and the local file path.
#[derive(Debug, Clone)]
pub struct BodyResult {
    /// Number of bytes read from the response.
    pub bytes_read: u64,
    /// Time elapsed during the download.
    pub elapsed: Duration,
    /// Local file path where the content was saved, if not deleted.
    pub local_file: Option<PathBuf>,
}

/// State tracking for protocol operations.
///
/// Maintains counters and flags that persist across retries, redirects,
/// and authentication challenges during a single URL retrieval.
#[derive(Debug, Clone)]
pub struct ProtocolState {
    /// Number of retry attempts made so far.
    pub retry_count: u32,
    /// Number of redirects followed so far.
    pub redirect_count: u32,
    /// Byte position for resume downloads.
    pub resume_position: u64,
    /// Whether a HEAD request has been completed.
    pub head_done: bool,
    /// Content-Length from the last response.
    pub last_content_length: Option<u64>,
    /// Whether NTLM authentication has been seen.
    pub ntlm_seen: bool,
    /// Whether authentication has completed successfully.
    pub auth_finished: bool,
}

impl Default for ProtocolState {
    fn default() -> Self {
        ProtocolState {
            retry_count: 0,
            redirect_count: 0,
            resume_position: 0,
            head_done: false,
            last_content_length: None,
            ntlm_seen: false,
            auth_finished: false,
        }
    }
}

/// Outcome of a URL retrieval operation.
///
/// Indicates the result of attempting to download a URL,
/// distinguishing between success, redirects, and other conditions.
#[derive(Debug)]
pub enum RetrieveOutcome {
    /// Download completed successfully with body result.
    Success(BodyResult),
    /// Resource not modified since last download (304 response).
    NotModified,
    /// URL redirected to a new location.
    Redirected(String),
    /// Spider mode: URL checked but not downloaded.
    SpiderOnly,
}

/// Error type for retrieval operations.
///
/// Categorizes errors by their source: protocol-level errors,
/// response errors, I/O errors, or quota violations.
#[derive(Debug, thiserror::Error)]
pub enum RetrieveError {
    /// Protocol-level error (connection, TLS, etc.).
    #[error("protocol error: {0}")]
    Protocol(#[from] WgetError),
    /// Response-level error (HTTP status, parsing, etc.).
    #[error("response error: {0}")]
    Response(WgetError),
    /// I/O error (file operations, network read/write).
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Download quota exceeded.
    #[error("quota exceeded")]
    Quota,
    /// No URLs found to download.
    #[error("no URLs to download")]
    NoUrls,
}

/// Trait for protocol implementations (HTTP, FTP).
///
/// Defines the interface that protocol handlers must implement to
/// work with the retriever. This abstraction allows the retriever
/// to work with different protocols uniformly.
pub trait Protocol: Send + Sync {
    /// Make a request to the given URL.
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed URL to request.
    /// * `opts` - Request options.
    /// * `state` - Mutable protocol state.
    ///
    /// # Returns
    ///
    /// Response metadata on success, or an error.
    fn request(
        &self,
        url: &ut_core::url::ParsedUrl,
        opts: &RequestOptions,
        state: &mut ProtocolState,
    ) -> Result<ResponseMeta, RetrieveError>;

    /// Read the response body and write to output.
    ///
    /// # Arguments
    ///
    /// * `response` - Response metadata (modified with actual bytes read).
    /// * `output` - Writer for the response body.
    /// * `state` - Mutable protocol state.
    /// * `progress` - Optional progress display.
    ///
    /// # Returns
    ///
    /// Body result with statistics on success, or an error.
    fn read_body(
        &self,
        response: &mut ResponseMeta,
        output: &mut dyn io::Write,
        state: &mut ProtocolState,
        progress: Option<&mut dyn ut_progress::ProgressDisplay>,
    ) -> Result<BodyResult, RetrieveError>;

    /// Whether this protocol supports resume (range requests).
    fn supports_resume(&self) -> bool;

    /// Whether this protocol supports conditional requests.
    fn supports_conditional(&self) -> bool;

    /// Whether the connection can be reused for subsequent requests.
    fn connection_reusable(&self) -> bool;
}

/// Convert `RetrieveError` to `WgetError`.
///
/// This implementation allows `RetrieveError` to be converted to the
/// more general `WgetError` type for unified error handling.
impl From<RetrieveError> for WgetError {
    fn from(e: RetrieveError) -> Self {
        match e {
            RetrieveError::Protocol(err) => err,
            RetrieveError::Response(err) => err,
            RetrieveError::Io(err) => WgetError::SocketError(err),
            RetrieveError::Quota => WgetError::Other("quota exceeded".into()),
            RetrieveError::NoUrls => WgetError::Other("no URLs".into()),
        }
    }
}
