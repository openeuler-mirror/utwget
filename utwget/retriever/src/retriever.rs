//! File retriever implementation.
//!
//! This module provides the main `Retriever` struct for downloading files
//! from HTTP, HTTPS, FTP, and FTPS URLs.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use log::{debug, info, warn};
use rand::Rng;
use ut_core::url::ParsedUrl;
use ut_core::{
    CompositeFilter, Config, CookieJar, NetrcDb, Scheme, WgetError,
};
use ut_http::auth::{AuthChallenge, AuthDispatcher};
use ut_http::request::{build_request, HttpRequest};
use ut_http::response::{HeaderMap, HttpResponse};
use ut_net::TlsConnector;
use ut_progress::ProgressDisplay;

use crate::download_registry::DownloadRegistry;
use crate::protocol::apply_rate_limit;
use crate::tls_pool::TlsConnectionPool;
use crate::types::{
    determine_document_flags,
    parse_http_date, BodyResult, DocumentFlags, ProtocolState, RequestOptions,
    ResponseMeta, RetrieveError, RetrieveOutcome,
};
use crate::utils::{
    adjust_file_extension, apply_file_timestamp, build_proxy_request, is_retryable, is_url_proxied,
    parse_content_disposition, parse_raw_response, resolve_proxy, rotate_backups, serialize_headers,
};

#[cfg(feature = "warc")]
use ut_warc::{WarcWriterImpl, WarcWriter};

/// Main file retriever for downloading URLs.
///
/// The `Retriever` handles all aspects of downloading files including:
/// - HTTP/HTTPS/FTP/FTPS protocol support
/// - Cookie management
/// - Authentication (Basic, Digest, NTLM)
/// - Proxy support
/// - Rate limiting
/// - Resume support
/// - WARC archiving
///
/// # Example
///
/// ```
/// use ut_retriever::Retriever;
/// use ut_core::Config;
///
/// let config = Arc::new(Config::default());
/// let retriever = Retriever::new(config, progress);
/// let result = retriever.retrieve("https://example.com/file.txt");
/// ```
pub struct Retriever {
    /// Shared application configuration, containing all options.
    config: Arc<Config>,
    /// Progress display for reporting download progress to the user.
    progress: Box<dyn ProgressDisplay>,
    /// Cookie jar for managing received and sent cookies.
    cookie_jar: CookieJar,
    /// .netrc credentials database for automatic authentication.
    netrc: NetrcDb,
    /// Composite filter for URL inclusion/exclusion rules.
    url_filter: CompositeFilter,
    /// Registry tracking downloaded files and URL redirections.
    download_registry: DownloadRegistry,
    /// Dispatcher for handling HTTP authentication challenges (Basic, Digest, NTLM).
    auth_dispatcher: AuthDispatcher,
    /// Total bytes downloaded across all requests in this session.
    total_downloaded: u64,
    /// Timestamp when the retriever was created.
    #[allow(dead_code)]
    start_time: Instant,
    /// Optional WARC writer for archiving downloaded content.
    #[cfg(feature = "warc")]
    warc: Option<WarcWriterImpl>,
    /// Connection pool for reusing TCP and TLS connections.
    connection_pool: TlsConnectionPool,
}
