//! File retriever implementation.
//!
//! This module provides the main `Retriever` struct for downloading files
//! from HTTP, HTTPS, FTP, and FTPS URLs.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Local, Utc};
use log::{debug, info, warn};
use rand::Rng;
use ut_core::url::ParsedUrl;
use ut_core::{
    CompositeFilter, Config, CookieJar, NetrcDb, Scheme, WgetError,
};
#[cfg(feature = "hsts")]
use ut_core::HstsStore;
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
    adjust_file_extension, apply_file_timestamp, build_proxy_request, is_retryable,
    is_url_proxied, parse_content_disposition, resolve_proxy, rotate_backups, sanitize_filename,
    serialize_headers,
};

#[cfg(feature = "warc")]
use ut_warc::{WarcWriterImpl, WarcWriter};

/// Process-wide DNS cache, keyed by hostname.
///
/// Caches resolved socket addresses with a TTL to avoid repeated DNS lookups
/// for the same host. The cache is keyed by (host, port) because the resolved
/// SocketAddr values include the port — caching by host alone would cause a
/// request to port 443 to reuse addresses resolved for port 80 (or vice versa).
/// Disabled when `--no-dns-cache` is set (per-Retriever).
static DNS_CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<(String, u16), (Vec<std::net::SocketAddr>, Instant)>>> = std::sync::OnceLock::new();

/// DNS cache entry TTL (seconds).
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Counter for detached DNS resolver threads (threads that timed out and
/// are still running in the background). Used to warn about potential
/// unbounded thread growth during recursive crawls with DNS timeouts.
static DETACHED_DNS_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Decremented when a previously-detached DNS thread finishes. Since we
/// cannot actually track this (the thread is detached), this is a no-op
/// placeholder for future enhancement. The count only grows during a session.
/// In practice, DNS cache hits (60s TTL) prevent most repeated lookups, so
/// detached threads are bounded by the number of *distinct* hosts that time
/// out within a 60s window.

fn dns_cache() -> &'static std::sync::Mutex<std::collections::HashMap<(String, u16), (Vec<std::net::SocketAddr>, Instant)>> {
    DNS_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

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
/// use std::sync::Arc;
/// use ut_retriever::Retriever;
/// use ut_core::Config;
///
/// let config = Arc::new(Config::default());
/// let progress = ut_progress::create_progress_display(ut_core::ProgressStyle::Silent, true);
/// let mut retriever = Retriever::new(config, progress);
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
    /// HSTS (HTTP Strict Transport Security) cache for HTTPS upgrade policy.
    #[cfg(feature = "hsts")]
    hsts: HstsStore,
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
    /// Buffered leftover bytes and body reader from the last HTTP response head read.
    pending_body_reader: Option<(Vec<u8>, BodySource)>,
    /// Return info for the current pending body reader, used to return the
    /// connection to the TLS pool after the body is consumed (Keep-Alive).
    pending_return_info: Option<ReturnInfo>,
    /// Whether the current pending response allows keep-alive connection reuse.
    pending_keep_alive: bool,
    /// URLs that were redirected from a POST/非GET request with 301/302/303,
    /// and therefore must be fetched with GET (and without body), per RFC 9110.
    redirect_get_method_urls: std::collections::HashSet<String>,
}

impl Retriever {
    /// Create a new Retriever with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Shared configuration reference.
    /// * `progress` - Progress display for showing download progress.
    ///
    /// # Returns
    ///
    /// A new `Retriever` instance.
    pub fn new(config: Arc<Config>, progress: Box<dyn ProgressDisplay>) -> Self {
        let mut cookie_jar = CookieJar::new();
        if let Some(ref cookie_file) = config.cookie.input_file {
            if cookie_file.exists() {
                match File::open(cookie_file) {
                    Ok(file) => {
                        if let Err(e) = cookie_jar.load_from_reader(file) {
                            warn!("failed to load cookies: {}", e);
                        }
                    }
                    Err(e) => warn!("failed to open cookie file {}: {}", cookie_file.display(), e),
                }
            }
        }

        // Load .netrc if enabled (default: enabled, --no-netrc disables)
        let mut netrc = NetrcDb::new();
        if config.use_netrc {
            if let Some(home) = std::env::var_os("HOME") {
                let netrc_path = PathBuf::from(home).join(".netrc");
                if netrc_path.exists() {
                    let _ = netrc.load_from_file(&netrc_path);
                }
            }
        }

        // Load HSTS store from the configured file, or ~/.wget-hsts by default.
        #[cfg(feature = "hsts")]
        let hsts_store = {
            let mut store = HstsStore::new();
            if config.hsts.enabled {
                let hsts_path = config.hsts.file.clone().or_else(|| {
                    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".wget-hsts"))
                });
                if let Some(ref path) = hsts_path {
                    if let Err(e) = store.load_from_file(path) {
                        warn!("failed to load HSTS from {}: {}", path.display(), e);
                    }
                }
            }
            store
        };

        let mut url_filter = CompositeFilter::new();
        if !config.recursive.domains.is_empty() || !config.recursive.exclude_domains.is_empty() {
            url_filter.add(ut_core::regex_filter::DomainFilter::new(
                config.recursive.domains.clone(),
                config.recursive.exclude_domains.clone(),
            ));
        }
        // Accept/reject pattern filters (-A / -R / --accept-regex / --reject-regex)
        if !config.recursive.accept_patterns.is_empty() {
            url_filter.add(ut_core::regex_filter::PatternAcceptFilter::new(
                config.recursive.accept_patterns.clone(),
            ));
        }
        if !config.recursive.reject_patterns.is_empty() {
            url_filter.add(ut_core::regex_filter::PatternRejectFilter::new(
                config.recursive.reject_patterns.clone(),
            ));
        }
        if let Some(ref re) = config.recursive.accept_regex {
            if let Ok(filter) = ut_core::regex_filter::RegexAcceptFilter::new(re) {
                url_filter.add(filter);
            }
        }
        if let Some(ref re) = config.recursive.reject_regex {
            if let Ok(filter) = ut_core::regex_filter::RegexRejectFilter::new(re) {
                url_filter.add(filter);
            }
        }
        // Include/exclude directory filters (-I / -X)
        if !config.recursive.include_directories.is_empty() {
            url_filter.add(ut_core::regex_filter::IncludeDirectoryFilter::new(
                config.recursive.include_directories.clone(),
            ));
        }
        if !config.recursive.exclude_directories.is_empty() {
            url_filter.add(ut_core::regex_filter::ExcludeDirectoryFilter::new(
                config.recursive.exclude_directories.clone(),
            ));
        }

        let mut retriever = Retriever {
            config,
            progress,
            cookie_jar,
            netrc,
            #[cfg(feature = "hsts")]
            hsts: hsts_store,
            url_filter,
            download_registry: DownloadRegistry::new(),
            auth_dispatcher: AuthDispatcher::new(),
            total_downloaded: 0,
            start_time: Instant::now(),
            #[cfg(feature = "warc")]
            warc: None,
            connection_pool: TlsConnectionPool::new(5), // Max 5 connections per pool
            pending_body_reader: None,
            pending_return_info: None,
            pending_keep_alive: false,
            redirect_get_method_urls: std::collections::HashSet::new(),
        };

        #[cfg(feature = "warc")]
        {
            if retriever.config.warc.enabled {
                let warc_path = retriever.config.warc.filename.clone()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("wget-warc"));
                match WarcWriterImpl::with_options(
                    warc_path,
                    retriever.config.warc.compression,
                    retriever.config.warc.digests,
                    retriever.config.warc.max_size,
                    retriever.config.warc.cdx,
                    retriever.config.warc.tempdir.clone(),
                    retriever.config.warc.user_headers.clone(),
                ) {
                    Ok(w) => retriever.warc = Some(w),
                    Err(e) => warn!("failed to initialize WARC writer: {}", e),
                }
            }
        }

        retriever
    }

    /// Download a file from the given URL.
    ///
    /// This is the main entry point for single-URL downloads. It parses the URL
    /// and delegates to the internal retrieval logic.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to download.
    ///
    /// # Returns
    ///
    /// A `RetrieveOutcome` indicating success, redirection, or other result.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if the URL cannot be parsed or the download fails.
    pub fn retrieve(&mut self, url: &str) -> Result<RetrieveOutcome, RetrieveError> {
        // Clear redirect method-downgrade set to prevent cross-request state
        // contamination. A URL downgraded to GET in a previous download should
        // not affect an unrelated download that happens to target the same URL.
        self.redirect_get_method_urls.clear();
        let parsed = ParsedUrl::parse(url).map_err(RetrieveError::Protocol)?;
        self.retrieve_parsed(&parsed, None)
    }

    /// Download a file from the given URL with automatic retry on failure.
    ///
    /// Retries the download up to `config.tries` times, with exponential backoff
    /// between attempts. Only retryable errors (timeouts, connection refused, etc.)
    /// trigger a retry.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to download.
    ///
    /// # Returns
    ///
    /// A `RetrieveOutcome` on success.
    ///
    /// # Errors
    ///
    /// Returns the last `RetrieveError` encountered after all retries are exhausted.
    pub fn retrieve_with_retry(&mut self, url: &str) -> Result<RetrieveOutcome, RetrieveError> {
        // Clear redirect method-downgrade set to prevent cross-request state
        // contamination between independent downloads.
        self.redirect_get_method_urls.clear();
        let parsed = ParsedUrl::parse(url).map_err(RetrieveError::Protocol)?;
        let max_tries = self.config.tries;

        let mut last_error = None;

        for attempt in 0..max_tries {
            // Reset state for each retry attempt (redirect_count etc. should not persist)
            let mut state = ProtocolState::default();
            state.retry_count = attempt;

            match self.retrieve_inner(&parsed, &mut state, None) {
                Ok(outcome) => return Ok(outcome),
                Err(e) => {
                    let retryable = is_retryable(&e, &self.config);
                    if retryable && attempt + 1 < max_tries {
                        let wait = self.calculate_backoff(attempt);
                        info!("retry {} after {:?}: {}", attempt + 1, wait, e);
                        std::thread::sleep(wait);
                        last_error = Some(e);
                        continue;
                    }
                    last_error = Some(e);
                    break;
                }
            }
        }

        Err(last_error.unwrap_or(RetrieveError::Protocol(
            WgetError::Other("unknown error".into()),
        )))
    }

    /// Retrieve a URL that has already been parsed, with an optional referer.
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed URL to download.
    /// * `referer` - Optional referer URL string.
    ///
    /// # Returns
    ///
    /// A `RetrieveOutcome` on success.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if the download fails.
    fn retrieve_parsed(
        &mut self,
        url: &ParsedUrl,
        referer: Option<&str>,
    ) -> Result<RetrieveOutcome, RetrieveError> {
        let mut state = ProtocolState::default();
        self.retrieve_inner(url, &mut state, referer)
    }

    /// Core retrieval logic shared by all download entry points.
    ///
    /// Checks quota and wait settings, resolves the effective URL, determines
    /// the output path, checks for existing files, computes resume position,
    /// and dispatches to the appropriate protocol handler (HTTP or FTP).
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed URL to download.
    /// * `state` - Mutable protocol state tracking retries, redirects, and resume position.
    /// * `referer` - Optional referer URL string.
    ///
    /// # Returns
    ///
    /// A `RetrieveOutcome` on success.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if any step of the download fails.
    fn retrieve_inner(
        &mut self,
        url: &ParsedUrl,
        state: &mut ProtocolState,
        referer: Option<&str>,
    ) -> Result<RetrieveOutcome, RetrieveError> {
        self.check_quota()?;

        // Wait before download if --wait is set
        if let Some(wait_duration) = self.config.wait {
            if state.retry_count == 0 {
                // Only wait on first attempt, not on retries
                debug!("waiting {:?} before download", wait_duration);
                std::thread::sleep(wait_duration);
            }
        }

        info!("--{}", url.display_safe());

        let mut effective_url = match self.resolve_effective_url(url) {
            Some(u) => u,
            None => url.clone(),
        };

        // Apply HSTS policy: upgrade HTTP to HTTPS when the host has an
        // active HSTS entry (RFC 6797). This happens before any request is
        // sent, so the upgrade is transparent to the rest of the pipeline.
        #[cfg(feature = "hsts")]
        {
            if self.config.hsts.enabled {
                let upgraded = self.hsts.should_upgrade(&effective_url.host, effective_url.scheme);
                if upgraded != effective_url.scheme {
                    debug!("HSTS: upgrading {} to HTTPS", effective_url.display());
                    effective_url.scheme = upgraded;
                    if effective_url.port == Scheme::Http.default_port() {
                        effective_url.port = Scheme::Https.default_port();
                    }
                }
            }
        }

        let output_path = self.determine_output_path(&effective_url)?;

        // Debug: log output_path
        debug!("determine_output_path returned: {:?}", output_path);
        debug!("config.output_document: {:?}", self.config.output_document);

        if self.check_existing(&output_path, &effective_url)? {
            return Ok(RetrieveOutcome::SpiderOnly);
        }

        // When file exists and will be overwritten, rotate the old file into
        // backups (file -> file.1 -> file.2 -> ... -> file.N) while still
        // writing the new content to the original path — matches GNU wget
        // --backups behavior.
        if output_path.exists() {
            let n_backups = self.config.backups.unwrap_or(1);
            if n_backups > 0 {
                debug!("file exists, rotating backups for: {:?}", output_path);
                rotate_backups(&output_path, n_backups);
            }
        }

        let resume_pos = self.compute_resume_position(&output_path)?;
        state.resume_position = resume_pos;

        let mut opts = self.build_request_options(&effective_url, referer, Some(resume_pos));

        match effective_url.scheme {
            Scheme::Http | Scheme::Https => {
                self.retrieve_http(&effective_url, &mut opts, state, &output_path)
            }
            Scheme::Ftp | Scheme::Ftps => {
                // FTP glob expansion: when globbing is enabled and the URL's
                // filename contains wildcard characters, list the directory and
                // download each matching file individually.
                if self.config.ftp.glob && ftp_url_has_glob(&effective_url) {
                    self.retrieve_ftp_glob(&effective_url, referer)
                } else {
                    self.retrieve_ftp(&effective_url, &mut opts, state, &output_path)
                }
            }
        }
    }

    /// Perform an HTTP or HTTPS download.
    fn retrieve_http(
        &mut self,
        url: &ParsedUrl,
        opts: &mut RequestOptions,
        state: &mut ProtocolState,
        output_path: &Path,
    ) -> Result<RetrieveOutcome, RetrieveError> {
        // Remove expired cookies before each request
        self.cookie_jar.remove_expired();

        let start = Instant::now();
        let cookie_str = self.cookie_jar.serialize_for_header(&url.host, &url.path, url.scheme);
        let creds = self.resolve_credentials(&url);
        let auth_header = if opts.auth_without_challenge {
            if let Some(ref c) = creds {
                let method = opts.method.as_str();
                self.auth_dispatcher.preemptive_auth(c, &url.full_path(), method)
            } else {
                None
            }
        } else {
            None
        };

        let req = build_request(
            url,
            &self.config,
            &opts.headers,
            Some(opts.method),
            opts.post_data.clone().or(opts.body_data.clone()),
            opts.range_start,
            opts.if_modified_since.as_ref(),
            opts.if_none_match.as_deref(),
            cookie_str.as_deref(),
            auth_header.as_deref(),
        );

        debug!("HTTP request: {} {}", req.method, req.path);

        // Always show timestamp and URL (like wget does)
        if !self.config.quiet {
            let now = Local::now();
            let display_url = url.display().trim_end_matches('#').to_string();
            eprintln!("--{}--  {}", now.format("%Y-%m-%d %H:%M:%S"), display_url);
        }

        // Debug: show request headers (mask sensitive values)
        if self.config.debug {
            eprintln!("---请求头---");
            eprintln!("{} {} HTTP/1.1", req.method, req.path);
            eprintln!("Host: {}", url.host);
            for (key, value) in req.headers.iter() {
                let display_value = if key.eq_ignore_ascii_case("Authorization")
                    || key.eq_ignore_ascii_case("Proxy-Authorization")
                {
                    // Mask credentials: show scheme but hide the actual token
                    let parts: Vec<&str> = value.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        format!("{} ****", parts[0])
                    } else {
                        "****".to_string()
                    }
                } else {
                    value.clone()
                };
                eprintln!("{}: {}", key, display_value);
            }
            eprintln!("---请求头结束---");
        }

        // Always show DNS resolution and connection info
        if !self.config.quiet {
            let host = &url.host;
            let port = url.port;
            eprint!("正在解析主机 {} ({})... ", host, host);
            let first_ip = if let Ok(addrs) = (host.as_str(), port).to_socket_addrs() {
                let ip_list: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                let first = ip_list.first().cloned().unwrap_or_default();
                eprintln!("{}", ip_list.join(", "));
                first
            } else {
                eprintln!("（解析失败）");
                String::new()
            };

            eprint!("正在连接 {} ({})|{}|:{}... ", host, host, first_ip, port);
            eprintln!("已连接。");
        }

        // Try HTTP/2 if enabled and applicable. On success the real response
        // (status/headers/body) flows into the same handling as HTTP/1.1 below
        // (server-response, cookies, redirects, auth, file writing). Any failure
        // falls back to HTTP/1.1.
        #[cfg(feature = "http2")]
        let mut response: HttpResponse = {
            let mut h2_response: Option<HttpResponse> = None;
            if crate::h2_integration::should_use_http2(url, &self.config) {
                debug!("attempting HTTP/2 for {}", url.display());
                match crate::h2_integration::H2Retriever::connect(url, &self.config) {
                    Ok(mut h2_retriever) => match h2_retriever.send_request(&req) {
                        Ok(r) => {
                            info!("HTTP/2 response {} for {}", r.status_code, url.display());
                            h2_response = Some(r);
                        }
                        Err(e) => {
                            debug!("HTTP/2 failed, falling back to HTTP/1.1: {}", e);
                        }
                    },
                    Err(e) => {
                        debug!("HTTP/2 connection failed, falling back to HTTP/1.1: {}", e);
                    }
                }
            }
            match h2_response {
                Some(mut r) => {
                    // HTTP/2 responses already have the body in r.body.
                    // Use take() instead of clone() to avoid a third copy of
                    // the body (read_body_limited already copies into Vec,
                    // and h2_integration.rs copies Bytes→Vec).
                    let body_data = r.body.take().unwrap_or_default();
                    self.pending_body_reader = Some((body_data, BodySource::Plain(Box::new(io::Cursor::new(Vec::new())))));
                    self.pending_return_info = None;
                    self.pending_keep_alive = false;
                    r
                }
                None => {
                    let (r, leftover, source, return_info) = self.do_http_request(&req, url)?;
                    self.pending_keep_alive = r.keep_alive() && return_info.is_some();
                    self.pending_return_info = return_info;
                    self.pending_body_reader = Some((leftover, source));
                    r
                }
            }
        };
        #[cfg(not(feature = "http2"))]
        let mut response = {
            let (r, leftover, source, return_info) = self.do_http_request(&req, url)?;
            self.pending_keep_alive = r.keep_alive() && return_info.is_some();
            self.pending_return_info = return_info;
            self.pending_body_reader = Some((leftover, source));
            r
        };

        if self.config.debug {
            eprintln!("---响应头---");
            eprintln!("{} {} {}", response.version, response.status_code, response.reason);
            for (key, value) in response.headers.iter() {
                eprintln!("{}: {}", key, value);
            }
            eprintln!("---响应头结束---");
        }

        // Show server response headers if --server-response is enabled.
        // This must come BEFORE the spider early-return so that
        // `wget -S --spider` prints the headers (matching GNU wget).
        //
        // GNU wget prints the response via LOG_ALWAYS (http.c:881
        // print_response_line), so --server-response bypasses --quiet:
        // `wget -q -S` still shows the headers. All lines, including the
        // status line, are prefixed with two spaces (http.c:3491 passes
        // "  " as the prefix to print_server_response).
        if self.config.server_response {
            eprintln!("  {} {} {}", response.version, response.status_code, response.reason);
            for (key, value) in response.headers.iter() {
                eprintln!("  {}: {}", key, value);
            }
            eprintln!();
        }

        // Spider mode: if response is successful, report file exists and return
        // without downloading the body (matches wget --spider behavior).
        // Redirects are handled in the redirect block below so the spider does
        // follow the chain (wget --spider follows redirects too).
        if self.config.recursive.spider && !response.is_redirect() {
            if response.status_code >= 200 && response.status_code < 300 {
                eprintln!("存在远程文件。");
                return Ok(RetrieveOutcome::SpiderOnly);
            } else {
                return Err(RetrieveError::Response(WgetError::Http {
                    status: response.status_code,
                    message: response.reason.clone(),
                }));
            }
        }

        // Always show content length
        if !self.config.quiet {
            if let Some(len) = response.content_length() {
                let human = ut_progress::format_size(len);
                let ct = response.headers.content_type().unwrap_or("unknown");
                eprintln!("长度：{} ({}) [{}]", len, human, ct);
            }

            // Always show saving to
            eprintln!("正在保存至: \"{}\"", output_path.file_name().unwrap_or_default().to_string_lossy());
        }

        self.process_cookies(&url, &response.headers);

        // Process HSTS policy from the Strict-Transport-Security header.
        // Only HTTPS responses can establish HSTS policy (RFC 6797 §8.1).
        #[cfg(feature = "hsts")]
        {
            if self.config.hsts.enabled && url.scheme == Scheme::Https {
                if let Some(sts) = response.headers.get("strict-transport-security") {
                    self.hsts.add_from_header(&url.host, sts);
                }
            }
        }

        // Authentication retry loop. Supports multi-round-trip auth schemes
        // like NTLM which require 2 exchanges after the initial 401:
        //   1. client → Type 1, server → 401 Type 2 challenge
        //   2. client → Type 3, server → 200 (or another 401)
        // We loop up to 3 times to allow NTLM's extra round trip.
        let mut auth_round = 0u32;
        const MAX_AUTH_ROUNDS: u32 = 3;
        while response.status_code == 401 && creds.is_some() && auth_round < MAX_AUTH_ROUNDS {
            auth_round += 1;
            let www_auth = response.headers.www_authenticate();
            if www_auth.is_empty() {
                break;
            }
            let challenges = AuthChallenge::from_www_authenticate(&www_auth.join(", "));
            let mut auth_succeeded = false;
            for challenge in &challenges {
                // Log stale nonce — server says credentials are fine but nonce expired
                if challenge.stale == Some(true) {
                    debug!("nonce is stale for {}, retrying with new nonce", url.display());
                }
                if let Some(ref c) = creds {
                    if let Ok(Some(auth_val)) = self.auth_dispatcher.authenticate(
                        challenge,
                        c,
                        opts.method.as_str(),
                        &url.full_path(),
                        opts.post_data.as_deref(),
                    ) {
                        let retry_req = build_request(
                            url,
                            &self.config,
                            &opts.headers,
                            Some(opts.method),
                            opts.post_data.clone().or(opts.body_data.clone()),
                            opts.range_start,
                            opts.if_modified_since.as_ref(),
                            opts.if_none_match.as_deref(),
                            cookie_str.as_deref(),
                            Some(&auth_val),
                        );
                        response = {
                            let (r, leftover, source, return_info) = self.do_http_request(&retry_req, url)?;
                            self.pending_keep_alive = r.keep_alive() && return_info.is_some();
                            self.pending_return_info = return_info;
                            self.pending_body_reader = Some((leftover, source));
                            r
                        };
                        state.auth_finished = true;
                        self.process_cookies(&url, &response.headers);
                        #[cfg(feature = "hsts")]
                        {
                            if self.config.hsts.enabled && url.scheme == Scheme::Https {
                                if let Some(sts) = response.headers.get("strict-transport-security") {
                                    self.hsts.add_from_header(&url.host, sts);
                                }
                            }
                        }
                        auth_succeeded = true;
                        break; // try next auth round (may be another 401 for NTLM)
                    }
                }
            }
            if !auth_succeeded {
                break; // no challenge succeeded, give up
            }
        }

        let ct = response.headers.content_type().map(|s| s.to_string());
        let resp_meta = self.http_response_to_meta(&response, ct.as_deref());

        if response.is_redirect() {
            state.redirect_count += 1;
            if state.redirect_count > self.config.max_redirect {
                return Err(RetrieveError::Response(WgetError::TooManyRedirects {
                    max: self.config.max_redirect,
                }));
            }
            if let Some(location) = response.location() {
                let redirect_url = url.merge(location).map_err(RetrieveError::Protocol)?;

                // RFC 9110: when a POST is redirected with 301/302/303, the
                // follow-up request must be a GET without a body.  GNU wget
                // (http.c:3912-3933) only downgrades POST to GET for 301/302;
                // other custom methods (PUT, DELETE, etc.) are preserved.
                // 303 always downgrades to GET; 307/308 always preserve.
                let method_is_post = opts.method == ut_core::types::HttpMethod::Post;
                if method_is_post && (response.status_code == 301
                    || response.status_code == 302
                    || response.status_code == 303)
                {
                    debug!(
                        "{} redirect for POST: follow-up will use GET without body",
                        response.status_code
                    );
                    self.redirect_get_method_urls.insert(redirect_url.display());
                }
                // For non-POST methods with 303, also downgrade to GET.
                if opts.method != ut_core::types::HttpMethod::Get
                    && opts.method != ut_core::types::HttpMethod::Head
                    && response.status_code == 303
                {
                    self.redirect_get_method_urls.insert(redirect_url.display());
                }

                // Security: block HTTPS -> HTTP downgrade when --https-only is set
                if self.config.http.https_only && !redirect_url.scheme.is_secure() {
                    warn!("blocking HTTPS->HTTP downgrade (https_only): {} -> {}",
                        url.display(), redirect_url.display());
                    return Err(RetrieveError::Protocol(WgetError::Other(
                        format!("HTTPS->HTTP redirect blocked (--https-only): {}", redirect_url.display())
                    )));
                }

                // Warn about cross-scheme or cross-host redirects for security awareness
                if url.scheme != redirect_url.scheme {
                    warn!("Cross-scheme redirect: {} -> {}", url.scheme, redirect_url.scheme);
                }
                if url.host != redirect_url.host {
                    debug!("Cross-host redirect: {} -> {}", url.host, redirect_url.host);
                }

                // SSRF awareness: warn if redirect targets a private/loopback address.
                // We do NOT block by default (wget follows all redirects), but warn so
                // server-side users notice potential SSRF via redirect chains.
                if let Some(ref host) = std::net::IpAddr::from_str(&redirect_url.host).ok() {
                    if host.is_loopback() || is_private_ip(host) {
                        warn!("redirect to private/loopback IP {} (potential SSRF): {}",
                            host, redirect_url.display());
                    }
                }

                self.download_registry.register_redirection(&url.display(), &redirect_url.display());
                self.progress.set_redirected(&redirect_url.display());
                info!("redirected to {}", redirect_url.display());
                return Ok(RetrieveOutcome::Redirected(redirect_url.display()));
            }
        }

        if response.not_modified() {
            self.progress.finish(ut_progress::FinishStatus::NotModified);
            return Ok(RetrieveOutcome::NotModified);
        }

        // For 4xx errors (except 416 Range Not Satisfiable), never save the body
        // to match wget behavior: error responses are not written to disk.
        // --content-on-error overrides this and keeps the error body.
        if response.is_client_error()
            && response.status_code != 416
            && !opts.content_on_error
        {
            self.progress.finish(ut_progress::FinishStatus::Error(format!(
                "错误 {}：{}。",
                response.status_code,
                response.reason
            )));
            return Err(RetrieveError::Response(WgetError::Http {
                status: response.status_code,
                message: response.reason.clone(),
            }));
        }

        if response.is_server_error() {
            if !opts.content_on_error {
                return Err(RetrieveError::Response(WgetError::Http {
                    status: response.status_code,
                    message: response.reason.clone(),
                }));
            }
        }

        // Determine output path, considering Content-Disposition header
        let output_path = if self.config.content_disposition {
            // Try to get filename from Content-Disposition header
            let content_disp_filename = response.headers.get("Content-Disposition")
                .and_then(parse_content_disposition);

            if let Some(ref filename) = content_disp_filename {
                // Sanitize filename to prevent path traversal attacks
                let safe_filename = sanitize_filename(filename);
                debug!("using filename from Content-Disposition: {} (sanitized from: {})", safe_filename, filename);
                let mut new_path = output_path.parent().unwrap_or(Path::new(".")).to_path_buf();
                new_path.push(&safe_filename);
                new_path
            } else {
                output_path.to_path_buf()
            }
        } else {
            output_path.to_path_buf()
        };

        // Handle directory creation based on --no-directories / --force-directories
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                if self.config.no_directories {
                    // --no-directories: don't create directory hierarchy
                    // Only create if parent already exists
                    if !parent.exists() {
                        return Err(RetrieveError::Io(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("directory {} does not exist (--no-directories)", parent.display())
                        )));
                    }
                } else if self.config.force_directories {
                    // --force-directories: always create directory hierarchy
                    fs::create_dir_all(parent).map_err(|e| {
                        RetrieveError::Io(io::Error::new(e.kind(), format!("cannot create {:?}: {}", parent, e)))
                    })?;
                } else {
                    // Default: create directory hierarchy
                    fs::create_dir_all(parent).map_err(|e| {
                        RetrieveError::Io(io::Error::new(e.kind(), format!("cannot create {:?}: {}", parent, e)))
                    })?;
                }
            }
        }

        // Remove existing file if --unlink is set
        if self.config.unlink && output_path.exists() {
            fs::remove_file(&output_path).map_err(RetrieveError::Io)?;
        }

        // Handle --start-pos: use configured start position or computed resume position
        let mut effective_resume_pos = self.config.start_position.unwrap_or(state.resume_position);
        state.resume_position = effective_resume_pos;

        // Validate the resume offset against the actual response.
        //
        // - 416 Range Not Satisfiable: the local file already covers the
        //   requested range (wget treats this as "file already fully
        //   retrieved; nothing to do"). Never write the 416 body to the file.
        if response.status_code == 416 {
            self.progress.finish(ut_progress::FinishStatus::NotModified);
            let result = BodyResult {
                bytes_read: 0,
                elapsed: start.elapsed(),
                local_file: (!self.config.delete_after).then(|| output_path.to_path_buf()),
            };
            return Ok(RetrieveOutcome::Success(result));
        }
        // - 200 (server ignored our Range): the response is the full entity.
        //   If the local file already has that many bytes it is complete;
        //   otherwise restart from scratch instead of appending the full
        //   body to the partial file (which would corrupt it).
        else if effective_resume_pos > 0 && response.status_code == 200 {
            let remote_len = response.content_length();
            let complete = remote_len.map(|len| len == effective_resume_pos).unwrap_or(false);
            if !complete {
                warn!(
                    "server ignored Range request, restarting download of {} from scratch",
                    output_path.display()
                );
                effective_resume_pos = 0;
                state.resume_position = 0;
            } else {
                self.progress.finish(ut_progress::FinishStatus::AlreadyExists);
                let result = BodyResult {
                    bytes_read: 0,
                    elapsed: start.elapsed(),
                    local_file: if self.config.delete_after { None } else { Some(output_path.to_path_buf()) },
                };
                return Ok(RetrieveOutcome::Success(result));
            }
        }
        // - 206 (Partial Content): verify the server honored our exact offset.
        //   If Content-Range does not start where we asked, restart from scratch.
        else if effective_resume_pos > 0 && response.status_code == 206 {
            let server_start = response.content_range_start();
            if server_start != Some(effective_resume_pos) {
                warn!(
                    "server returned Content-Range {:?}, requested resume from {}; restarting from scratch",
                    server_start, effective_resume_pos
                );
                effective_resume_pos = 0;
                state.resume_position = 0;
            }
        }

        let resume_for_open = effective_resume_pos;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(resume_for_open == 0)
            .append(resume_for_open > 0)
            .open(&output_path)
            .map_err(RetrieveError::Io)?;

        // Wrap file in BufWriter to reduce write system calls.
        // 64KB capacity matches our I/O buffer size for efficient batching.
        let file = io::BufWriter::with_capacity(IO_BUFFER_SIZE, file);

        // Use Content-Length for progress, unless ignore_length is set
        let total_size = if self.config.ignore_length {
            None
        } else {
            resp_meta.content_length.and_then(|cl| cl.checked_add(effective_resume_pos))
        };

        self.progress.reset();
        self.progress.begin_with_output_path(&url.display(), &output_path.to_string_lossy(), total_size, Some(effective_resume_pos));

        if self.config.http.save_headers {
            let mut header_file = File::create(output_path.with_extension("headers"))
                .map_err(RetrieveError::Io)?;
            for (k, v) in response.headers.iter() {
                let _ = writeln!(header_file, "{}: {}", k, v);
            }
        }

        let mut body_bytes_read = 0u64;
        if let Some((leftover, mut source)) = self.pending_body_reader.take() {
            // Determine if the response body is compressed (Content-Encoding).
            // If so, wrap the writer in a flate2 decompressor so that compressed
            // bytes read from the transport are decompressed before hitting disk.
            // This must happen AFTER de-chunking (handled inside stream_response_body),
            // since Content-Encoding applies to the entity body, not the transfer.
            let encoding = response.headers.get("Content-Encoding");
            let mut writer: Box<dyn io::Write> = match encoding {
                #[cfg(feature = "compression")]
                Some(e) if e.eq_ignore_ascii_case("gzip") || e.eq_ignore_ascii_case("x-gzip") => {
                    debug!("decompressing gzip response body");
                    Box::new(flate2::write::GzDecoder::new(file))
                }
                #[cfg(feature = "compression")]
                Some(e) if e.eq_ignore_ascii_case("deflate") => {
                    debug!("decompressing deflate response body");
                    Box::new(flate2::write::ZlibDecoder::new(file))
                }
                _ => Box::new(file),
            };

            let stream_result = stream_response_body(
                &mut io::Cursor::new(leftover).chain(&mut source),
                &mut writer,
                &response,
                &mut *self.progress,
                state.resume_position,
                self.config.ignore_length,
            );
            // Flush the (possibly decompressing) writer before dropping, so all
            // pending decompressed bytes are written to the underlying file.
            // A flush failure (e.g. disk full) means the file on disk is
            // truncated. Propagate this as an error so the caller doesn't
            // report a "successful" download with a truncated file.
            if let Err(e) = writer.flush() {
                log::warn!("flush error after body write: {}", e);
                self.pending_return_info = None;
                self.pending_keep_alive = false;
                return Err(RetrieveError::Io(e));
            }
            // On success, try to return the connection to the pool for Keep-Alive.
            // On error, drop the connection (do not reuse potentially-broken connections).
            match stream_result {
                Ok(result) => {
                    body_bytes_read = result.bytes;
                    // Only reuse the connection if the body was fully drained
                    // (Content-Length complete or chunked terminator). EOF-delimited
                    // or truncated bodies mean the server closed the connection;
                    // attempting to reuse it would yield stale bytes or immediate EOF.
                    if self.pending_keep_alive && result.connection_reusable {
                        if let Some((host, port)) = self.pending_return_info.take() {
                            match source {
                                BodySource::Tls(mut t) => {
                                    if let Some(conn) = t.take_inner() {
                                        debug!("returning TLS connection to pool for {}:{}", host, port);
                                        self.connection_pool.put_tls(&host, port, conn);
                                    }
                                }
                                BodySource::Tcp(tcp) => {
                                    debug!("returning TCP connection to pool for {}:{}", host, port);
                                    self.connection_pool.put_tcp(&host, port, tcp);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(err) => {
                    // Body read failed: connection may be in an inconsistent state.
                    // Discard it (do not return to pool) and propagate the error.
                    self.pending_return_info = None;
                    self.pending_keep_alive = false;
                    return Err(err);
                }
            }
        }
        // Note: file (wrapped in BufWriter, possibly in a decompressor) was
        // flushed and dropped inside the if-let above. If pending_body_reader
        // was None, file is dropped at end of function with no data to write.

        let elapsed = start.elapsed();
        self.progress.finish(ut_progress::FinishStatus::Success {
            downloaded: body_bytes_read,
            elapsed,
        });

        self.total_downloaded += body_bytes_read;
        state.last_content_length = Some(body_bytes_read);
        state.head_done = true;

        self.apply_server_timestamp(&output_path, &resp_meta);

        #[cfg(feature = "warc")]
        self.write_warc_record(&url.display(), &response, &resp_meta, &output_path);

        // Set extended attributes if enabled
        if self.config.xattr {
            let metadata = crate::xattr::FileMetadata {
                url: url.display(),
                content_type: resp_meta.content_type.clone(),
                last_modified: resp_meta.last_modified.as_ref().map(|dt| dt.to_rfc2822()),
                etag: resp_meta.etag.clone(),
            };
            if let Err(e) = crate::xattr::set_xattr(&output_path, &metadata) {
                log::warn!("failed to set xattr on {}: {}", output_path.display(), e);
            }
        }

        // Adjust file extension based on Content-Type if --adjust-extension is set.
        // This renames the file on disk, so it must happen before the registry
        // records the local path (used later by --convert-links).
        let final_output_path = if self.config.adjust_extension {
            adjust_file_extension(&output_path, resp_meta.content_type.as_deref())
        } else {
            output_path.clone()
        };

        // Register the *final* local path so link conversion resolves to it.
        self.download_registry.register_download(&url.display(), &final_output_path);

        // Preserve permissions if enabled
        if self.config.preserve_permissions {
            // For HTTP, we don't have direct permission info, use default
            let perms = crate::xattr::RemotePermissions::default();
            if let Err(e) = crate::xattr::apply_permissions(&final_output_path, &perms) {
                log::warn!("failed to set permissions on {}: {}", final_output_path.display(), e);
            }
        }

        // Delete file after download if --delete-after is set
        if self.config.delete_after {
            if let Err(e) = fs::remove_file(&final_output_path) {
                warn!("failed to delete file after download: {}", e);
            }
        }

        let result = BodyResult {
            bytes_read: body_bytes_read,
            elapsed,
            local_file: if self.config.delete_after { None } else { Some(final_output_path) },
        };

        Ok(RetrieveOutcome::Success(result))
    }

    /// Perform an FTP or FTPS download.
    ///
    /// Handles both plain FTP and FTPS (explicit and implicit) connections,
    /// including login, binary transfer mode, directory navigation, file retrieval,
    /// and post-download processing such as timestamps, extended attributes,
    /// permissions, and cleanup.
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed FTP/FTPS URL.
    /// * `_opts` - Request options (currently unused for FTP).
    /// * `state` - Mutable protocol state.
    /// * `output_path` - Local filesystem path for the downloaded file.
    ///
    /// # Returns
    ///
    /// A `RetrieveOutcome` on success.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if connection, login, transfer, or post-processing fails.
    fn retrieve_ftp(
        &mut self,
        url: &ParsedUrl,
        _opts: &RequestOptions,
        state: &mut ProtocolState,
        output_path: &Path,
    ) -> Result<RetrieveOutcome, RetrieveError> {
        let start = Instant::now();

        let user = url.user.clone()
            .or(self.config.ftp.user.clone())
            .unwrap_or_else(|| "anonymous".to_string());
        let password = url.password.clone()
            .or(self.config.ftp.password.clone())
            .unwrap_or_else(|| "wget-rs@".to_string());

        // Determine if we should use FTPS
        let use_ftps = url.scheme == Scheme::Ftps || self.config.ftp.ftps_implicit;

        // Determine the port
        let port = if url.scheme == Scheme::Ftps && url.port == 21 {
            // Default FTPS port is 990 for implicit, 21 for explicit
            if self.config.ftp.ftps_implicit { 990 } else { 21 }
        } else {
            url.port
        };

        if use_ftps {
            // Use FTPS client. Propagate --secure-protocol and --no-check-certificate
            // from the TLS config so FTPS honors them like the HTTPS path.
            let ftps_cfg = ut_ftp::FtpsConfig {
                verify_certificate: self.config.tls.check_certificate != ut_core::types::CheckCertMode::Off,
                ca_cert: self.config.tls.ca_cert.clone(),
                client_cert: self.config.tls.cert_file.clone(),
                client_key: self.config.tls.private_key.clone(),
                require_data_tls: !self.config.ftp.ftps_clear_data,
                secure_protocol: self.config.tls.secure_protocol,
                clear_data_connection: self.config.ftp.ftps_clear_data,
                resume_ssl: self.config.ftp.ftps_resume_ssl,
            };
            let mut ftps_client = ut_ftp::FtpsClient::with_config(ftps_cfg);

            if self.config.ftp.ftps_implicit {
                // Implicit FTPS: connect with TLS from the start
                ftps_client.connect_implicit(&url.host, port)
                    .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTPS connect error: {}", e))))?;
            } else {
                // Explicit FTPS: connect plain, then upgrade with AUTH TLS
                ftps_client.connect_explicit(&url.host, port)
                    .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTPS connect error: {}", e))))?;
            }

            ftps_client.login(&user, &password)
                .map_err(|_| RetrieveError::Protocol(WgetError::FtpLoginRefused))?;
            ftps_client.type_binary()
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP type error: {}", e))))?;

            let path_segments: Vec<&str> = url.path.trim_start_matches('/')
                .split('/').filter(|s| !s.is_empty()).collect();
            if path_segments.len() > 1 {
                for dir in &path_segments[..path_segments.len() - 1] {
                    if let Err(e) = ftps_client.cwd(dir) {
                        debug!("FTP CWD {} failed (continuing anyway): {}", dir, e);
                    }
                }
            }

            let filename = path_segments.last().map(|s| *s).unwrap_or("index.html");
            let file_size = ftps_client.size(filename).ok().flatten();

            // Handle directory creation
            if let Some(parent) = output_path.parent() {
                if !parent.as_os_str().is_empty() {
                    if self.config.no_directories {
                        if !parent.exists() {
                            return Err(RetrieveError::Io(io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("directory {} does not exist (--no-directories)", parent.display())
                            )));
                        }
                    } else {
                        fs::create_dir_all(parent).map_err(RetrieveError::Io)?;
                    }
                }
            }

            // Remove existing file if --unlink is set
            if self.config.unlink && output_path.exists() {
                fs::remove_file(output_path).map_err(RetrieveError::Io)?;
            }

        let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(state.resume_position == 0)
                .append(state.resume_position > 0)
                .open(output_path)
                .map_err(RetrieveError::Io)?;

            self.progress.begin(&url.display(), file_size, Some(state.resume_position));
            self.progress.reset();

            let mut rate_writer = apply_rate_limit(file, self.config.limit_rate);
            let total_bytes = ftps_client.retr(filename, &mut rate_writer, Some(state.resume_position))
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTPS transfer error: {}", e))))?;

            // Apply server timestamp (MDTM) before closing the connection
            if let Some(mdtm) = ftps_client.mdtm(filename).ok().flatten() {
                apply_file_timestamp(output_path, mdtm);
            }

            ftps_client.quit()
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTPS quit error: {}", e))))?;

            let elapsed = start.elapsed();
            self.progress.finish(ut_progress::FinishStatus::Success {
                downloaded: total_bytes,
                elapsed,
            });

            self.total_downloaded += total_bytes;

            self.download_registry.register_download(&url.display(), output_path);

            let result = BodyResult {
                bytes_read: total_bytes,
                elapsed,
                local_file: Some(output_path.to_path_buf()),
            };

            return Ok(RetrieveOutcome::Success(result));
        }

        // Regular FTP
        log::debug!("FTP passive mode: {}", self.config.ftp.passive);
        let mut ftp_client = ut_ftp::FtpClient::new().with_passive(self.config.ftp.passive);
        ftp_client.connect(&url.host, url.port)
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP connect error: {}", e))))?;
        ftp_client.login(&user, &password)
            .map_err(|_| RetrieveError::Protocol(WgetError::FtpLoginRefused))?;
        ftp_client.type_binary()
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP type error: {}", e))))?;

        let path_segments: Vec<&str> = url.path.trim_start_matches('/')
            .split('/').filter(|s| !s.is_empty()).collect();
        if path_segments.len() > 1 {
            for dir in &path_segments[..path_segments.len() - 1] {
                if let Err(e) = ftp_client.cwd(dir) {
                    debug!("FTP CWD {} failed (continuing anyway): {}", dir, e);
                }
            }
        }

        let filename = path_segments.last().map(|s| *s).unwrap_or("index.html");
        let file_size = ftp_client.size(filename).ok().flatten();

        // Handle directory creation based on --no-directories / --force-directories
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                if self.config.no_directories {
                    if !parent.exists() {
                        return Err(RetrieveError::Io(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("directory {} does not exist (--no-directories)", parent.display())
                        )));
                    }
                } else {
                    fs::create_dir_all(parent).map_err(RetrieveError::Io)?;
                }
            }
        }

        // Remove existing file if --unlink is set
        if self.config.unlink && output_path.exists() {
            fs::remove_file(output_path).map_err(RetrieveError::Io)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(state.resume_position == 0)
            .append(state.resume_position > 0)
            .open(output_path)
            .map_err(RetrieveError::Io)?;

        self.progress.begin(&url.display(), file_size, Some(state.resume_position));
        self.progress.reset();

        let mut rate_writer = apply_rate_limit(file, self.config.limit_rate);
        let total_bytes = ftp_client.retr(filename, &mut rate_writer, Some(state.resume_position))
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP transfer error: {}", e))))?;

        // Get server timestamp before closing connection
        let mdtm = ftp_client.mdtm(filename).ok().flatten();

        ftp_client.quit()
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP quit error: {}", e))))?;

        let elapsed = start.elapsed();
        self.progress.finish(ut_progress::FinishStatus::Success {
            downloaded: total_bytes,
            elapsed,
        });

        self.total_downloaded += total_bytes;

        if let Some(mdtm) = mdtm {
            apply_file_timestamp(output_path, mdtm);
        }

        self.download_registry.register_download(&url.display(), output_path);

        // Set extended attributes if enabled
        if self.config.xattr {
            let metadata = crate::xattr::FileMetadata {
                url: url.display(),
                content_type: None, // FTP doesn't provide content-type
                last_modified: None,
                etag: None,
            };
            if let Err(e) = crate::xattr::set_xattr(output_path, &metadata) {
                log::warn!("failed to set xattr on {}: {}", output_path.display(), e);
            }
        }

        // Preserve permissions if enabled
        if self.config.preserve_permissions {
            // For FTP, we could potentially get permissions from LIST output
            // For now, use default permissions
            let perms = crate::xattr::RemotePermissions::default();
            if let Err(e) = crate::xattr::apply_permissions(output_path, &perms) {
                log::warn!("failed to set permissions on {}: {}", output_path.display(), e);
            }
        }

        // Delete file after download if --delete-after is set
        if self.config.delete_after {
            if let Err(e) = fs::remove_file(output_path) {
                warn!("failed to delete file after download: {}", e);
            }
        }

        let result = BodyResult {
            bytes_read: total_bytes,
            elapsed,
            local_file: if self.config.delete_after { None } else { Some(output_path.to_path_buf()) },
        };

        Ok(RetrieveOutcome::Success(result))
    }

    /// Download every file matching an FTP glob pattern.
    ///
    /// Connects (optionally via FTPS), CWDs to the directory portion of the
    /// URL, lists it, and downloads each entry whose name matches the glob
    /// pattern in the URL's filename component. `--no-glob` disables this.
    fn retrieve_ftp_glob(
        &mut self,
        url: &ParsedUrl,
        referer: Option<&str>,
    ) -> Result<RetrieveOutcome, RetrieveError> {
        let user = url.user.clone()
            .or(self.config.ftp.user.clone())
            .unwrap_or_else(|| "anonymous".to_string());
        let password = url.password.clone()
            .or(self.config.ftp.password.clone())
            .unwrap_or_else(|| "wget-rs@".to_string());

        let use_ftps = url.scheme == Scheme::Ftps || self.config.ftp.ftps_implicit;
        let port = if url.scheme == Scheme::Ftps && url.port == 21 {
            if self.config.ftp.ftps_implicit { 990 } else { 21 }
        } else {
            url.port
        };

        // Directory components (everything except the last segment, which is
        // the glob pattern). CWD into each in turn.
        let path_segments: Vec<&str> = url.path.trim_start_matches('/')
            .split('/').filter(|s| !s.is_empty()).collect();
        let glob_pattern = path_segments.last().map(|s| *s).unwrap_or("*");

        // Collect matching filenames via a directory listing.
        let matches: Vec<String> = if use_ftps {
            let ftps_cfg = ut_ftp::FtpsConfig {
                verify_certificate: self.config.tls.check_certificate != ut_core::types::CheckCertMode::Off,
                ca_cert: self.config.tls.ca_cert.clone(),
                client_cert: self.config.tls.cert_file.clone(),
                client_key: self.config.tls.private_key.clone(),
                require_data_tls: !self.config.ftp.ftps_clear_data,
                secure_protocol: self.config.tls.secure_protocol,
                clear_data_connection: self.config.ftp.ftps_clear_data,
                resume_ssl: self.config.ftp.ftps_resume_ssl,
            };
            let mut ftps = ut_ftp::FtpsClient::with_config(ftps_cfg);
            if self.config.ftp.ftps_implicit {
                ftps.connect_implicit(&url.host, port)
                    .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTPS connect error: {}", e))))?;
            } else {
                ftps.connect_explicit(&url.host, port)
                    .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTPS connect error: {}", e))))?;
            }
            ftps.login(&user, &password)
                .map_err(|_| RetrieveError::Protocol(WgetError::FtpLoginRefused))?;
            ftps.type_binary()
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP type error: {}", e))))?;
            for dir in &path_segments[..path_segments.len().saturating_sub(1)] {
                let _ = ftps.cwd(dir);
            }
            let entries = ftps.nlst(None)
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP NLST error: {}", e))))?;
            let _ = ftps.quit();
            filter_glob_entries(&entries, glob_pattern, self.config.ignore_case)
        } else {
            let mut ftp = ut_ftp::FtpClient::new().with_passive(self.config.ftp.passive);
            ftp.connect(&url.host, url.port)
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP connect error: {}", e))))?;
            ftp.login(&user, &password)
                .map_err(|_| RetrieveError::Protocol(WgetError::FtpLoginRefused))?;
            ftp.type_binary()
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP type error: {}", e))))?;
            for dir in &path_segments[..path_segments.len().saturating_sub(1)] {
                let _ = ftp.cwd(dir);
            }
            let entries = ftp.nlst(None)
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP NLST error: {}", e))))?;
            let _ = ftp.quit();
            filter_glob_entries(&entries, glob_pattern, self.config.ignore_case)
        };

        if matches.is_empty() {
            warn!("no files matched FTP glob pattern '{}'", glob_pattern);
            return Ok(RetrieveOutcome::SpiderOnly);
        }

        info!("FTP glob '{}' matched {} file(s)", glob_pattern, matches.len());

        // Download each matched file by re-running the single-file retrieval
        // path with a concrete URL (no glob characters).
        let dir_part = if path_segments.len() > 1 {
            format!("/{}", path_segments[..path_segments.len() - 1].join("/"))
        } else {
            String::new()
        };
        let mut worst: Option<RetrieveError> = None;
        let mut last_outcome = RetrieveOutcome::SpiderOnly;
        for name in matches {
            let concrete = format!("{}://{}:{}{}{}",
                url.scheme.as_str(), url.host, url.port, dir_part, name);
            let parsed = match ParsedUrl::parse(&concrete) {
                Ok(p) => p,
                Err(e) => {
                    warn!("skipping malformed expanded FTP URL '{}': {}", concrete, e);
                    continue;
                }
            };
            let mut state = ProtocolState::default();
            match self.retrieve_inner(&parsed, &mut state, referer) {
                Ok(o) => last_outcome = o,
                Err(e) => {
                    warn!("failed to download '{}': {}", name, e);
                    worst = worst.or(Some(e));
                }
            }
        }
        match worst {
            Some(e) => Err(e),
            None => Ok(last_outcome),
        }
    }

    /// Create a TCP connection with optional timeout, bind address, and address family restrictions.
    ///
    /// Resolves the hostname (with optional DNS timeout), filters addresses by
    /// IPv4/IPv6 preferences (`--inet4-only`, `--inet6-only`, `--prefer-family`),
    /// and attempts to connect to each resolved address until one succeeds.
    ///
    /// # Arguments
    ///
    /// * `host` - The target hostname.
    /// * `port` - The target TCP port.
    ///
    /// # Returns
    ///
    /// A connected `TcpStream`.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if DNS resolution fails, no suitable address is found,
    /// or all connection attempts fail.
    /// Connect to a remote address, binding the local socket to a specific
    /// source address first. Used by `--bind-address`.
    ///
    /// Uses `libc` syscalls to create a socket, bind, then connect with
    /// an optional timeout.
    fn connect_with_bind(
        remote: &std::net::SocketAddr,
        bind_addr: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<std::net::TcpStream, std::io::Error> {
        // Parse the bind address. If no port is given, use port 0 (OS picks).
        let bind: std::net::SocketAddr = match bind_addr.parse() {
            Ok(a) => a,
            Err(_) => {
                // Try as host:port or just host (port 0)
                let addr = format!("{}:0", bind_addr);
                addr.parse().map_err(|e: std::net::AddrParseError| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid bind address: {}", e))
                })?
            }
        };

        // Use a SocketAddr in the same family as the remote.
        let bind = match remote {
            std::net::SocketAddr::V4(_) => {
                match bind {
                    std::net::SocketAddr::V4(_) => bind,
                    std::net::SocketAddr::V6(_) => {
                        // Fall back to 0.0.0.0:0
                        "0.0.0.0:0".parse().unwrap()
                    }
                }
            }
            std::net::SocketAddr::V6(_) => {
                match bind {
                    std::net::SocketAddr::V6(_) => bind,
                    std::net::SocketAddr::V4(_) => {
                        // Fall back to [::]:0
                        "[::]:0".parse().unwrap()
                    }
                }
            }
        };

        // Create socket via libc, bind, connect, then wrap as TcpStream.
        unsafe {
            let domain = if remote.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
            let fd = libc::socket(domain, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Bind
            let (bind_ptr, bind_len) = match &bind {
                std::net::SocketAddr::V4(v4) => {
                    let mut sa: libc::sockaddr_in = std::mem::zeroed();
                    sa.sin_family = libc::AF_INET as u16;
                    sa.sin_port = v4.port().to_be();
                    sa.sin_addr = libc::in_addr { s_addr: u32::from(*v4.ip()).to_be() };
                    let sa_ptr = &sa as *const libc::sockaddr_in as *const libc::sockaddr;
                    let sa_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                    (sa_ptr, sa_len)
                }
                std::net::SocketAddr::V6(v6) => {
                    let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                    sa.sin6_family = libc::AF_INET6 as u16;
                    sa.sin6_port = v6.port().to_be();
                    sa.sin6_addr.s6_addr = v6.ip().octets();
                    let sa_ptr = &sa as *const libc::sockaddr_in6 as *const libc::sockaddr;
                    let sa_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                    (sa_ptr, sa_len)
                }
            };

            // Allocate storage for the bind address
            let sa_storage: [u8; 128] = [0u8; 128];
            std::ptr::copy_nonoverlapping(
                bind_ptr as *const u8,
                sa_storage.as_ptr() as *mut u8,
                bind_len as usize,
            );

            if libc::bind(fd, sa_storage.as_ptr() as *const libc::sockaddr, bind_len) < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            // Connect
            let (remote_ptr, remote_len) = match remote {
                std::net::SocketAddr::V4(v4) => {
                    let mut sa: libc::sockaddr_in = std::mem::zeroed();
                    sa.sin_family = libc::AF_INET as u16;
                    sa.sin_port = v4.port().to_be();
                    sa.sin_addr = libc::in_addr { s_addr: u32::from(*v4.ip()).to_be() };
                    let sa_ptr = &sa as *const libc::sockaddr_in as *const libc::sockaddr;
                    let sa_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                    (sa_ptr, sa_len)
                }
                std::net::SocketAddr::V6(v6) => {
                    let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                    sa.sin6_family = libc::AF_INET6 as u16;
                    sa.sin6_port = v6.port().to_be();
                    sa.sin6_addr.s6_addr = v6.ip().octets();
                    let sa_ptr = &sa as *const libc::sockaddr_in6 as *const libc::sockaddr;
                    let sa_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                    (sa_ptr, sa_len)
                }
            };

            let remote_storage: [u8; 128] = [0u8; 128];
            std::ptr::copy_nonoverlapping(
                remote_ptr as *const u8,
                remote_storage.as_ptr() as *mut u8,
                remote_len as usize,
            );

            // Set non-blocking if timeout is set
            if timeout.is_some() {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            let conn_ret = libc::connect(
                fd,
                remote_storage.as_ptr() as *const libc::sockaddr,
                remote_len,
            );

            if conn_ret < 0 {
                let errno = *libc::__errno_location();
                if timeout.is_some() && (errno == libc::EINPROGRESS || errno == libc::EWOULDBLOCK) {
                    // Wait for connect with poll
                    let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                    let timeout_ms = timeout.unwrap().as_millis() as libc::c_int;
                    let poll_ret = libc::poll(&mut pfd, 1, timeout_ms);
                    if poll_ret <= 0 {
                        libc::close(fd);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "connect with bind timed out",
                        ));
                    }
                    // Check for errors
                    let mut soerr: libc::c_int = 0;
                    let mut soerr_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut soerr as *mut _ as *mut libc::c_void,
                        &mut soerr_len,
                    );
                    if soerr != 0 {
                        libc::close(fd);
                        return Err(std::io::Error::from_raw_os_error(soerr));
                    }
                } else {
                    let err = std::io::Error::last_os_error();
                    libc::close(fd);
                    return Err(err);
                }
            }

            // Restore blocking mode
            if timeout.is_some() {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
            }

            // Convert fd to TcpStream
            use std::os::unix::io::FromRawFd;
            Ok(std::net::TcpStream::from_raw_fd(fd))
        }
    }

    fn create_tcp_stream(&self, host: &str, port: u16) -> Result<std::net::TcpStream, RetrieveError> {
        // Try to get a connection from the pool first
        if let Some(conn) = self.connection_pool.get_tcp(host, port) {
            debug!("reusing pooled TCP connection to {}:{}", host, port);
            return Ok(conn);
        }

        use std::net::ToSocketAddrs;

        let _addr_str = format!("{}:{}", host, port);

        // Resolve addresses with optional DNS timeout.
        // A process-wide DNS cache (TTL 60s) avoids repeated lookups for the
        // same host. Disabled when --no-dns-cache is set.
        let addresses: Vec<std::net::SocketAddr> = {
            // Check DNS cache first (unless disabled)
            if !self.config.no_dns_cache {
                if let Ok(cache) = dns_cache().lock() {
                    if let Some((cached_addrs, cached_at)) = cache.get(&(host.to_string(), port)) {
                        if cached_at.elapsed() < DNS_CACHE_TTL {
                            debug!("DNS cache hit for {}:{}", host, port);
                            cached_addrs.clone()
                        } else {
                            // Stale; fall through to resolve and refresh below.
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        };
        let addresses: Vec<std::net::SocketAddr> = if !addresses.is_empty() {
            addresses
        } else {
            let addrs = if let Some(dns_timeout) = self.config.dns_timeout.or(self.config.timeout) {
                // Use a background thread with channel-based timeout for DNS resolution
                let host_owned = host.to_string();
                let (tx, rx) = std::sync::mpsc::channel();

                // Spawn thread and track handle for cleanup
                let handle = std::thread::Builder::new()
                    .name(format!("dns-resolve-{}", host))
                    .spawn(move || {
                        let result = (host_owned.as_str(), port).to_socket_addrs();
                        let _ = tx.send(result);
                    })
                    .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                        format!("failed to spawn DNS thread: {}", e)
                    )))?;

                match rx.recv_timeout(dns_timeout) {
                    Ok(Ok(addrs)) => {
                        // DNS resolved successfully, thread will exit naturally
                        let _ = handle.join(); // Wait for thread to clean up
                        addrs
                    }
                    Ok(Err(e)) => {
                        let _ = handle.join(); // Wait for thread to clean up
                        return Err(RetrieveError::Protocol(WgetError::Other(
                            format!("DNS resolution error: {}", e)
                        )));
                    }
                    Err(_) => {
                        // Timeout: thread may still be running. We cannot
                        // force-terminate it, so we detach it. To prevent
                        // unbounded thread growth, track the count of detached
                        // threads and warn if it exceeds a limit.
                        let count = DETACHED_DNS_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if count > 100 {
                            log::warn!(
                                "DNS resolution timeout for {}, detaching resolver thread ({} detached threads active)",
                                host, count
                            );
                        } else {
                            log::debug!("DNS resolution timeout for {}, detaching resolver thread", host);
                        }
                        return Err(RetrieveError::Protocol(WgetError::Other(
                            "DNS resolution timeout".to_string()
                        )));
                    }
                }
            } else {
                (host, port).to_socket_addrs()
                    .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                        format!("DNS resolution error: {}", e)
                    )))?
            };
            let collected: Vec<std::net::SocketAddr> = addrs.collect();

            // Store in cache (unless disabled)
            if !self.config.no_dns_cache && !collected.is_empty() {
                if let Ok(mut cache) = dns_cache().lock() {
                    cache.insert((host.to_string(), port), (collected.clone(), Instant::now()));
                }
            }

            collected
        };

        if addresses.is_empty() {
            return Err(RetrieveError::Protocol(WgetError::HostNotFound(host.to_string())));
        }

        // Filter addresses based on address family settings
        log::debug!("IPv4 filter: {}, IPv6 filter: {}", self.config.force_ipv4, self.config.force_ipv6);
        log::debug!("Before filter: {:?}", addresses);
        let filtered_addresses: Vec<std::net::SocketAddr> = addresses.into_iter()
            .filter(|addr| {
                if self.config.force_ipv4 {
                    matches!(addr, std::net::SocketAddr::V4(_))
                } else if self.config.force_ipv6 {
                    matches!(addr, std::net::SocketAddr::V6(_))
                } else {
                    true
                }
            })
            .collect();
        log::debug!("After filter: {:?}", filtered_addresses);

        // Apply prefer_family ordering
        let mut sorted_addresses = filtered_addresses;
        match self.config.prefer_family {
            ut_core::AddressFamily::Ipv4 | ut_core::AddressFamily::PreferIpv4 => {
                sorted_addresses.sort_by(|a, b| {
                    let a_is_v4 = matches!(a, std::net::SocketAddr::V4(_));
                    let b_is_v4 = matches!(b, std::net::SocketAddr::V4(_));
                    b_is_v4.cmp(&a_is_v4) // IPv4 first
                });
            }
            ut_core::AddressFamily::Ipv6 | ut_core::AddressFamily::PreferIpv6 => {
                sorted_addresses.sort_by(|a, b| {
                    let a_is_v6 = matches!(a, std::net::SocketAddr::V6(_));
                    let b_is_v6 = matches!(b, std::net::SocketAddr::V6(_));
                    b_is_v6.cmp(&a_is_v6) // IPv6 first
                });
            }
            ut_core::AddressFamily::Unspecified => {}
        }

        if sorted_addresses.is_empty() {
            return Err(RetrieveError::Protocol(WgetError::Other(
                if self.config.force_ipv4 {
                    format!("no IPv4 addresses found for {}", host)
                } else if self.config.force_ipv6 {
                    format!("no IPv6 addresses found for {}", host)
                } else {
                    format!("no addresses found for {}", host)
                }
            )));
        }

        // Try to connect to each address
        let connect_timeout = self.config.connect_timeout.or(self.config.timeout);
        let mut last_error = None;

        for addr in sorted_addresses {
            debug!("trying to connect to {}", addr);

            // Apply bind address if set: create a socket, bind to the
            // specified local address, then connect to the remote.
            let stream_result = if let Some(ref bind_addr) = self.config.bind_address {
                debug!("--bind-address={} requested for connection to {}", bind_addr, addr);
                match Self::connect_with_bind(&addr, bind_addr, connect_timeout) {
                    Ok(s) => Ok(s),
                    Err(e) => Err(e),
                }
            } else if let Some(timeout) = connect_timeout {
                std::net::TcpStream::connect_timeout(&addr, timeout)
            } else {
                std::net::TcpStream::connect(&addr)
            };

            match stream_result {
                Ok(stream) => {
                    // Apply read timeout if set
                    if let Some(timeout) = self.config.read_timeout.or(self.config.timeout) {
                        stream.set_read_timeout(Some(timeout))
                            .map_err(RetrieveError::Io)?;
                    }

                    // Apply write timeout (using same timeout value)
                    if let Some(timeout) = self.config.timeout {
                        stream.set_write_timeout(Some(timeout))
                            .map_err(RetrieveError::Io)?;
                    }

                    return Ok(stream);
                }
                Err(e) => {
                    last_error = Some(e);
                    debug!("failed to connect to {}: {}", addr, last_error.as_ref().unwrap());
                }
            }
        }

        Err(RetrieveError::Protocol(WgetError::SocketError(
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused, "connection failed"))
        )))
    }

    /// Send an HTTP request and receive the response.
    ///
    /// Handles direct connections and proxy connections (including CONNECT tunneling
    /// for HTTPS over proxy). Wraps connections with TLS when the URL scheme is HTTPS.
    ///
    /// # Arguments
    ///
    /// * `request` - The constructed HTTP request to send.
    /// * `url` - The target URL (used to determine scheme, host, and port).
    ///
    /// # Returns
    ///
    /// An `HttpResponse` containing the server's response.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if connection, TLS handshake, or request/response I/O fails.
    fn do_http_request(
        &mut self,
        request: &HttpRequest,
        url: &ParsedUrl,
    ) -> Result<(HttpResponse, Vec<u8>, BodySource, Option<ReturnInfo>), RetrieveError> {
        let host = &url.host;
        let port = url.port;

        let use_proxy = self.config.proxy.use_proxy && is_url_proxied(url, &self.config);

        if use_proxy {
            let proxy = resolve_proxy(url, &self.config);
            let proxy_host = proxy.host.clone();
            let proxy_port = proxy.port;
            debug!("connecting via proxy {}:{}", proxy_host, proxy_port);

            let mut stream = self.create_tcp_stream(&proxy_host, proxy_port)?;

            if url.scheme.is_secure() {
                // Use HTTP CONNECT method to establish tunnel for HTTPS
                let (tunneled_stream, leftover) = self.establish_connect_tunnel(&mut stream, host, port)?;
                debug!("CONNECT tunnel established for {}:{} ({} leftover bytes)", host, port, leftover.len());

                // Now wrap with TLS, injecting leftover bytes so the TLS layer sees them first
                let tls_config = ut_net::tls::TlsConfig::from_core(&self.config.tls);
                let tls_connector = ut_net::tls::RustlsConnector::new();
                let mut tls_stream = tls_connector.connect(
                    Box::new(ut_net::transport::TcpTransport::with_prefix(tunneled_stream, leftover)),
                    host,
                    port,
                    &tls_config,
                ).map_err(|e| RetrieveError::Protocol(WgetError::Tls(ut_core::error::TlsError::HandshakeFailed(e.to_string()))))?;

                // Send request over TLS
                let serialized = request.serialize().map_err(RetrieveError::Io)?;
                debug!("HTTPS request over proxy tunnel:\n{}", crate::utils::redact_sensitive_headers(&String::from_utf8_lossy(&serialized)));
                tls_stream.write(&serialized).map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("write error: {}", e))))?;

                let (response, leftover) = {
                    let mut reader = TransportRead::new(&mut tls_stream);
                    read_response_head(&mut reader)?
                };
                // Proxy tunnel: not returned to the direct-host TLS pool.
                let source = BodySource::Tls(OwnedTransportRead::new(tls_stream));
                Ok((response, leftover, source, None))
            } else {
                // Plain HTTP over proxy
                let proxy_req = build_proxy_request(
                    request,
                    &url.host,
                    url.port,
                    self.config.proxy.proxy_user.as_deref(),
                    self.config.proxy.proxy_password.as_deref(),
                );
                let serialized = proxy_req.serialize().map_err(RetrieveError::Io)?;
                stream.write_all(&serialized).map_err(RetrieveError::Io)?;
                stream.flush().map_err(RetrieveError::Io)?;

                let (response, leftover) = read_response_head(&mut stream)?;
                let source = BodySource::Plain(Box::new(stream));
                Ok((response, leftover, source, None))
            }
        } else {
            debug!("connecting to {}:{}", host, port);

            if url.scheme.is_secure() {
                // Try to reuse a pooled TLS connection (Keep-Alive)
                let mut tls_stream = if let Some(pooled) = self.connection_pool.get_tls(host, port) {
                    debug!("reusing pooled TLS connection to {}:{}", host, port);
                    pooled
                } else {
                    let stream = self.create_tcp_stream(host, port)?;
                    let tls_config = ut_net::tls::TlsConfig::from_core(&self.config.tls);
                    let tls_connector = ut_net::tls::RustlsConnector::new();
                    tls_connector.connect(
                        Box::new(ut_net::transport::TcpTransport::new(stream)),
                        host,
                        port,
                        &tls_config,
                    ).map_err(|e| RetrieveError::Protocol(WgetError::Tls(ut_core::error::TlsError::HandshakeFailed(e.to_string()))))?
                };

                let serialized = request.serialize().map_err(RetrieveError::Io)?;
                debug!("HTTPS request:\n{}", crate::utils::redact_sensitive_headers(&String::from_utf8_lossy(&serialized)));
                tls_stream.write(&serialized).map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("write error: {}", e))))?;

                let (response, leftover) = {
                    let mut reader = TransportRead::new(&mut tls_stream);
                    read_response_head(&mut reader)?
                };
                // Direct HTTPS: connection can be returned to the (host, port) TLS pool
                // after the body is consumed, if the server allows keep-alive.
                let source = BodySource::Tls(OwnedTransportRead::new(tls_stream));
                Ok((response, leftover, source, Some((host.clone(), port))))
            } else {
                let mut stream = self.create_tcp_stream(host, port)?;
                let serialized = request.serialize().map_err(RetrieveError::Io)?;
                debug!("HTTP request:\n{}", crate::utils::redact_sensitive_headers(&String::from_utf8_lossy(&serialized)));
                stream.write_all(&serialized).map_err(RetrieveError::Io)?;
                stream.flush().map_err(RetrieveError::Io)?;

                let (response, leftover) = read_response_head(&mut stream)?;
                let source = BodySource::Tcp(stream);
                // Direct HTTP: connection can be returned to the TCP pool
                // after the body is consumed, if the server allows keep-alive.
                Ok((response, leftover, source, Some((host.clone(), port))))
            }
        }
    }

    /// Establish an HTTP CONNECT tunnel through a proxy for HTTPS connections.
    ///
    /// Sends a CONNECT request to the proxy, reads the response, and returns
    /// a cloned stream ready for TLS wrapping.
    ///
    /// # Arguments
    ///
    /// * `stream` - The TCP stream connected to the proxy.
    /// * `host` - The target hostname for the tunnel.
    /// * `port` - The target port for the tunnel.
    ///
    /// # Returns
    ///
    /// A cloned `TcpStream` with the tunnel established.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if the proxy returns a non-200 status or if I/O fails.
    fn establish_connect_tunnel(
        &self,
        stream: &mut std::net::TcpStream,
        host: &str,
        port: u16,
    ) -> Result<(std::net::TcpStream, Vec<u8>), RetrieveError> {
        // Send CONNECT request. Sanitize the host (strip CR/LF/control chars)
        // and bracket IPv6 literals so the request line cannot be split and
        // IPv6 targets are well-formed.
        let clean_host: String = host.chars()
            .filter(|&c| c != '\r' && c != '\n' && !c.is_ascii_control())
            .collect();
        let target = if clean_host.contains(':') {
            format!("[{}]:{}", clean_host, port)
        } else {
            format!("{}:{}", clean_host, port)
        };
        let connect_req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            target, target
        );
        let mut connect_req = connect_req;
        // Send proxy credentials when configured (--proxy-user/--proxy-password);
        // some proxies require Basic auth before they accept the CONNECT tunnel.
        if let (Some(user), Some(pass)) =
            (&self.config.proxy.proxy_user, &self.config.proxy.proxy_password)
        {
            let credentials = format!("{}:{}", user, pass);
            let encoded = crate::utils::base64_encode(&credentials);
            connect_req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        connect_req.push_str("\r\n");
        debug!("CONNECT request: {}", crate::utils::redact_sensitive_headers(&connect_req));
        stream.write_all(connect_req.as_bytes()).map_err(RetrieveError::Io)?;
        stream.flush().map_err(RetrieveError::Io)?;

        // Use read_response_head to properly parse the CONNECT response and
        // preserve any leftover bytes read beyond the header boundary.
        let (response, leftover) = read_response_head(stream)?;
        let status_line = format!("{} {} {}", response.version, response.status_code, response.reason);
        debug!("CONNECT response: {}", status_line);

        let status_ok = response.status_code == 200;

        if !status_ok {
            return Err(RetrieveError::Protocol(WgetError::Other(format!(
                "proxy CONNECT failed: {}",
                status_line
            ))));
        }

        // Validate leftover bytes: a well-formed CONNECT 200 response has no body.
        // Leftover data could be from a malicious proxy injecting data into the
        // TLS handshake. Log a warning if unexpected data is present.
        if !leftover.is_empty() {
            warn!(
                "proxy CONNECT response contained {} unexpected bytes after header; \
                 this may indicate a misconfigured or malicious proxy",
                leftover.len()
            );
        }

        // Return the stream and any leftover bytes for TLS wrapping
        let cloned = stream.try_clone().map_err(RetrieveError::Io)?;
        Ok((cloned, leftover))
    }
}

/// Read all data from a Transport trait object until EOF.
///
/// # Arguments
///
/// * `transport` - A boxed transport (e.g. TLS-wrapped stream).
///
/// # Returns
///
/// All bytes read from the transport.
///
/// # Errors
///
/// Returns `RetrieveError` if a read operation fails.
/// Adapter that exposes a `ut_net::Transport` (TLS transport) as a blocking
/// `std::io::Read`, mapping its error type into an `io::Error`.
///
/// This lets the binary-safe response reader work
/// uniformly over both plain `TcpStream` and TLS transports.
struct TransportRead<'a> {
    inner: &'a mut Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>,
}

impl<'a> TransportRead<'a> {
    fn new(inner: &'a mut Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>) -> Self {
        TransportRead { inner }
    }
}

impl<'a> Read for TransportRead<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner
            .read(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

/// Owned adapter that wraps a boxed `Transport` and exposes `std::io::Read`.
///
/// The inner transport is stored as an `Option` so it can be extracted after
/// the response body is fully read, allowing the connection to be returned to
/// the TLS connection pool for Keep-Alive reuse.
struct OwnedTransportRead {
    inner: Option<Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>>,
}

impl OwnedTransportRead {
    fn new(inner: Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>) -> Self {
        OwnedTransportRead { inner: Some(inner) }
    }

    /// Extract the underlying transport, if still present.
    ///
    /// Returns `None` if the transport was already taken (e.g. after a
    /// previous return-to-pool). This is used after the response body is
    /// fully consumed to return the connection to the pool for Keep-Alive.
    fn take_inner(&mut self) -> Option<Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>> {
        self.inner.take()
    }
}

impl Read for OwnedTransportRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.as_mut() {
            Some(t) => t.read(buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())),
            None => Ok(0), // transport already taken; behave as EOF
        }
    }
}

/// The source of a response body reader.
///
/// Distinguishes between a non-poolable reader (plain HTTP, proxy, or
/// in-memory HTTP/2 buffer) and a poolable TLS transport (direct HTTPS).
/// The `Tcp` variant (direct HTTP) can be returned to the TCP pool, and
/// the `Tls` variant (direct HTTPS) can be returned to the TLS pool for
/// Keep-Alive reuse after the body is fully consumed.
enum BodySource {
    /// Non-poolable reader: proxy tunnel, or HTTP/2 in-memory buffer.
    /// Cannot be returned to any connection pool.
    Plain(Box<dyn Read + Send>),
    /// Poolable plain TCP transport (direct HTTP only).
    Tcp(std::net::TcpStream),
    /// Poolable TLS transport (direct HTTPS only).
    Tls(OwnedTransportRead),
}

impl Read for BodySource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            BodySource::Plain(p) => p.read(buf),
            BodySource::Tcp(s) => s.read(buf),
            BodySource::Tls(t) => t.read(buf),
        }
    }
}

/// Information needed to return a connection to the TLS connection pool
/// after the response body is fully consumed.
///
/// `None` means the connection should not be reused (e.g. proxy tunnel where
/// the pool key differs, or a non-reusable response).
type ReturnInfo = (String, u16); // (host, port)

/// I/O buffer size for streaming response bodies (64KB).
///
/// Larger buffers reduce the number of system calls for read/write operations,
/// significantly improving throughput for large file downloads.
/// 64KB is a good balance between memory usage and syscall reduction.
const IO_BUFFER_SIZE: usize = 64 * 1024;

/// Returns true if the URL's filename component contains glob wildcard
/// characters (`*`, `?`, `[`), indicating FTP glob expansion is needed.
fn ftp_url_has_glob(url: &ParsedUrl) -> bool {
    url.file.contains('*') || url.file.contains('?') || url.file.contains('[')
}

/// Filter a list of directory entry names against a glob pattern, honoring
/// `--ignore-case`. Sorted for deterministic download order.
fn filter_glob_entries(entries: &[String], pattern: &str, ignore_case: bool) -> Vec<String> {
    let mut matched: Vec<String> = entries.iter()
        .filter(|name| {
            if ignore_case {
                ut_core::regex_filter::glob_match(&name.to_ascii_lowercase(), &pattern.to_ascii_lowercase())
            } else {
                ut_core::regex_filter::glob_match(name, pattern)
            }
        })
        .cloned()
        .collect();
    matched.sort();
    matched
}

/// Returns true if the IP address is in a private (RFC 1918) or link-local
/// range, used for SSRF awareness on redirects.
fn is_private_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private()      // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local() // 169.254.0.0/16 (cloud metadata)
                || v4.is_unspecified() // 0.0.0.0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()
        }
    }
}

/// Result of streaming a response body to disk.
struct BodyReadResult {
    /// Number of bytes written (after de-chunking / decompression where applicable).
    bytes: u64,
    /// Whether the connection was fully drained and is safe to reuse.
    ///
    /// This is `false` for close-delimited bodies (EOF terminated), where the
    /// server has already closed the connection, and for truncated bodies.
    connection_reusable: bool,
}

fn stream_response_body<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    response: &HttpResponse,
    progress: &mut dyn ProgressDisplay,
    resume_from: u64,
    ignore_length: bool,
) -> Result<BodyReadResult, RetrieveError> {
    if response.is_chunked() {
        let mut received = 0u64;
        let mut chunked = ut_http::chunked::ChunkedReader::new(reader);
        while let Some(chunk) = chunked
            .read_next_chunk()
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("chunked body read error: {}", e))))?
        {
            writer.write_all(&chunk).map_err(RetrieveError::Io)?;
            received += chunk.len() as u64;
            progress.update(resume_from + received, Duration::ZERO);
        }
        // Chunked bodies are terminated by a 0-length chunk (and optional
        // trailers), so the connection is fully drained and reusable.
        Ok(BodyReadResult {
            bytes: received,
            connection_reusable: true,
        })
    } else if !ignore_length {
        if let Some(len) = response.content_length() {
        let mut received = 0u64;
        let mut tmp = [0u8; IO_BUFFER_SIZE];
        while received < len {
            let want = ((len - received) as usize).min(tmp.len());
            let n = reader
                .read(&mut tmp[..want])
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("body read error: {}", e))))?;
            if n == 0 {
                // Truncated body: the server closed the connection before
                // delivering all promised bytes. Return an error so the caller
                // discards the connection (never returns it to the pool) and
                // may retry with a Range request, matching wget's behavior.
                return Err(RetrieveError::Protocol(WgetError::BodyTruncated {
                    received,
                    expected: len,
                }));
            }
            writer.write_all(&tmp[..n]).map_err(RetrieveError::Io)?;
            received += n as u64;
            progress.update(resume_from + received, Duration::ZERO);
        }
        Ok(BodyReadResult {
            bytes: received,
            connection_reusable: true,
        })
        } else {
            read_until_eof(reader, writer, progress, resume_from)
        }
    } else {
        read_until_eof(reader, writer, progress, resume_from)
    }
}

/// Read the response body until EOF, writing each chunk to `writer`.
///
/// The body is terminated by the connection closing (close-delimited body),
/// so the connection can never be reused afterwards.
fn read_until_eof<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    progress: &mut dyn ProgressDisplay,
    resume_from: u64,
) -> Result<BodyReadResult, RetrieveError> {
    let mut received = 0u64;
    let mut tmp = [0u8; IO_BUFFER_SIZE];
    loop {
        let n = reader
            .read(&mut tmp)
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("body read error: {}", e))))?;
        if n == 0 {
            break;
        }
        writer.write_all(&tmp[..n]).map_err(RetrieveError::Io)?;
        received += n as u64;
        progress.update(resume_from + received, Duration::ZERO);
    }
    Ok(BodyReadResult {
        bytes: received,
        // EOF-terminated bodies mean the server closed the connection.
        connection_reusable: false,
    })
}

/// Reads only the HTTP response head (status line + headers), returning any
/// leftover body bytes that were read together with the headers.
///
/// Informational (1xx) interim responses such as `100 Continue` are skipped,
/// matching wget's behavior, so the caller only ever sees a final response.
fn read_response_head<R: Read>(
    reader: &mut R,
) -> Result<(HttpResponse, Vec<u8>), RetrieveError> {
    loop {
        let (response, leftover) = read_one_response_head(reader)?;
        if response.is_informational() {
            debug!(
                "skipping informational response: {} {}",
                response.status_code, response.reason
            );
            continue;
        }
        return Ok((response, leftover));
    }
}

/// Reads a single response head (status line + headers), returning any
/// leftover body bytes that were read together with the headers.
fn read_one_response_head<R: Read>(
    reader: &mut R,
) -> Result<(HttpResponse, Vec<u8>), RetrieveError> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let header_end = loop {
        if let Some(end) = ut_http::response::find_header_end(&buf) {
            break end;
        }
        if buf.len() > 64 * 1024 {
            return Err(RetrieveError::Protocol(WgetError::Other(
                "HTTP response headers too large (>64KB)".into(),
            )));
        }
        let n = reader
            .read(&mut tmp)
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("read response head: {}", e))))?;
        if n == 0 {
            return Err(RetrieveError::Protocol(WgetError::Other(
                "connection closed before response headers received".into(),
            )));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let response = ut_http::response::parse_response_head(&buf[..header_end + 4])
        .ok_or_else(|| RetrieveError::Protocol(WgetError::Other("failed to parse HTTP response".into())))?;
    let leftover: Vec<u8> = buf[header_end + 4..].to_vec();
    Ok((response, leftover))
}

impl Retriever {
    /// Build the set of request options for a given URL.
    ///
    /// Configures method, proxy usage, authentication, headers, range start,
    /// and If-Modified-Since based on the current configuration and state.
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed target URL.
    /// * `referer` - Optional referer URL.
    /// * `resume_pos` - Optional byte position for resume.
    ///
    /// # Returns
    ///
    /// A populated `RequestOptions` struct.
    fn build_request_options(
        &self,
        url: &ParsedUrl,
        referer: Option<&str>,
        resume_pos: Option<u64>,
    ) -> RequestOptions {
        let mut opts = RequestOptions::default();
        opts.method = self.config.http.method.unwrap_or(ut_core::types::HttpMethod::Get);
        // RFC 9110: after a 301/302/303 redirect of a POST (or other unsafe
        // method), the client must follow up with GET and no body. Such target
        // URLs are recorded in redirect_get_method_urls when the redirect is
        // processed, and enforced here for the follow-up request.
        if self.redirect_get_method_urls.contains(&url.display()) {
            opts.method = ut_core::types::HttpMethod::Get;
            opts.post_data = None;
            opts.body_data = None;
        }
        opts.use_proxy = self.config.proxy.use_proxy;
        opts.auth_without_challenge = self.config.auth_without_challenge;
        opts.save_headers = self.config.http.save_headers;
        opts.content_on_error = self.config.http.content_on_error;

        if let Some(r) = referer.or(self.config.http.referer.as_deref()) {
            opts.referer = Some(r.to_string());
        }

        // Only set range_start if resume_pos > 0 (actual resume, not initial download)
        if let Some(pos) = resume_pos {
            if pos > 0 {
                opts.range_start = Some(pos);
            }
        }

        // GNU wget sends If-Modified-Since only when BOTH timestamping (-N)
        // AND if_modified_since are true (http.c:4319-4323). Without -N,
        // timestamping is false so no conditional GET is sent — the default
        // "always re-download" behavior is preserved.
        if self.config.timestamping && self.config.if_modified_since {
            if let Ok(metadata) = fs::metadata(self.determine_output_path(url).unwrap_or_default()) {
                if let Ok(mtime) = metadata.modified() {
                    opts.if_modified_since = Some(mtime.into());
                }
            }
        }

        // Populate request body from config.
        // --post-data/--post-file auto-set method=POST in the CLI layer
        // (see app.rs); --body-data/--body-file require --method.
        // Both feed into opts.post_data/opts.body_data which build_request
        // passes to the wire (see http/src/request.rs).
        if let Some(ref data) = self.config.http.post_data {
            opts.post_data = Some(data.clone());
        } else if let Some(ref path) = self.config.http.post_file {
            match fs::read(path) {
                Ok(data) => opts.post_data = Some(data),
                Err(e) => log::warn!("post-file {:?} read error: {}", path, e),
            }
        }

        if let Some(ref data) = self.config.http.body_data {
            opts.body_data = Some(data.clone());
        } else if let Some(ref path) = self.config.http.body_file {
            match fs::read(path) {
                Ok(data) => opts.body_data = Some(data),
                Err(e) => log::warn!("body-file {:?} read error: {}", path, e),
            }
        }

        opts
    }

    /// Determine the local filesystem path for a downloaded URL.
    ///
    /// Applies `--output-document`, protocol directory prefix,
    /// directory cut count, and `--directory-prefix` rules.
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed URL to generate a filename for.
    ///
    /// # Returns
    ///
    /// A `PathBuf` pointing to the local output path.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if the URL cannot be converted to a filename.
    fn determine_output_path(&self, url: &ParsedUrl) -> Result<PathBuf, RetrieveError> {
        if let Some(ref doc) = self.config.output_document {
            return Ok(doc.clone());
        }

        // Build the local path from the URL's directory and filename.
        // GNU wget creates the directory structure when recursive (-r) or
        // --force-directories (-x) is active; otherwise it saves flat with
        // just the filename. --no-host-directories (-nH) suppresses the
        // leading host directory.
        //
        // --no-directories (-nd) forces a flat layout (just the filename)
        // and takes precedence over both -r and -x, matching GNU wget's
        // `opt.ftp_dirstruct` / dirstruct handling (init.c, utils.c).
        let create_dirs = (self.config.recursive.enabled || self.config.force_directories)
            && !self.config.no_directories;

        let file_name = if url.file.is_empty() { "index.html".to_string() } else { url.file.clone() };
        let safe_file = ut_core::utils::safe_filename(&file_name);

        // Directory components from url.dir, sanitized and with --cut-dirs applied.
        let dir_parts: Vec<String> = url.dir.split('/')
            .filter(|s| !s.is_empty())
            .map(|s| ut_core::utils::safe_filename(s))
            // Final guard: never allow a ".." component into the path, even
            // if it somehow survived normalization (e.g. from a malformed dir).
            .filter(|s| s != ".." && s != ".")
            .collect();
        let cut = if self.config.cut_dirs > 0 {
            (self.config.cut_dirs as usize).min(dir_parts.len())
        } else {
            0
        };
        let kept_dirs = &dir_parts[cut..];

        let mut path = PathBuf::new();

        // Host directory (unless -nH or saving flat without -r/-x)
        if !self.config.no_host_directories && create_dirs {
            path.push(ut_core::utils::safe_filename(&url.host));
        }

        // Protocol directory (--protocol-directories)
        if self.config.protocol_directories {
            path.push(url.scheme.as_str());
        }

        // URL directory components (only when creating directory structure)
        if create_dirs {
            for dir in kept_dirs {
                path.push(dir);
            }
        }

        path.push(&safe_file);

        // --directory-prefix (-P)
        if let Some(ref prefix) = self.config.dir_prefix {
            path = prefix.join(path);
        }

        Ok(path)
    }

    /// Check whether a file already exists and whether it should be skipped.
    ///
    /// Returns `true` if the file exists and should not be overwritten
    /// (e.g., `--noclobber` is set), `false` otherwise.
    ///
    /// # Arguments
    ///
    /// * `path` - The local file path to check.
    /// * `_url` - The parsed URL (currently unused).
    ///
    /// # Returns
    ///
    /// `true` if the download should be skipped.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if filesystem metadata reading fails.
    fn check_existing(&mut self, path: &Path, _url: &ParsedUrl) -> Result<bool, RetrieveError> {
        if !path.exists() {
            return Ok(false);
        }

        if self.config.noclobber {
            info!("file already exists; not clobbering: {}", path.display());
            self.progress.finish(ut_progress::FinishStatus::AlreadyExists);
            return Ok(true);
        }

        if !self.config.continue_download && !self.config.timestamping {
            return Ok(false);
        }

        Ok(false)
    }

    /// Compute the byte position from which to resume a download.
    ///
    /// Returns the size of the existing file if `--continue` is set and
    /// the file exists, or `0` otherwise.
    ///
    /// # Arguments
    ///
    /// * `path` - The local file path to check.
    ///
    /// # Returns
    ///
    /// The byte position for resume.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if filesystem metadata cannot be read.
    fn compute_resume_position(&self, path: &Path) -> Result<u64, RetrieveError> {
        if !self.config.continue_download || !path.exists() {
            return Ok(0);
        }
        let metadata = fs::metadata(path).map_err(RetrieveError::Io)?;
        if metadata.len() > 0 {
            debug!("resuming from position {}", metadata.len());
            Ok(metadata.len())
        } else {
            Ok(0)
        }
    }

    /// Resolve the effective URL by following any previously registered redirects.
    ///
    /// # Arguments
    ///
    /// * `url` - The original parsed URL.
    ///
    /// # Returns
    ///
    /// `Some(ParsedUrl)` if a redirect target is found, `None` otherwise.
    fn resolve_effective_url(&self, url: &ParsedUrl) -> Option<ParsedUrl> {
        self.download_registry.resolve_redirect(&url.display())
            .and_then(|s| ParsedUrl::parse(&s).ok())
    }

    /// Check whether the download quota has been exceeded.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError::Quota` if `--quota` is set and the total
    /// downloaded bytes meets or exceeds the quota.
    fn check_quota(&self) -> Result<(), RetrieveError> {
        if let Some(quota) = self.config.quota {
            if self.total_downloaded >= quota {
                return Err(RetrieveError::Quota);
            }
        }
        Ok(())
    }

    /// Resolve authentication credentials for the given URL.
    ///
    /// Checks, in order: `--http-user`/`--http-password`, URL-embedded credentials,
    /// and the `.netrc` database.
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed URL.
    ///
    /// # Returns
    ///
    /// `Some(Credentials)` if credentials are found, `None` otherwise.
    fn resolve_credentials(&self, url: &ParsedUrl) -> Option<ut_core::types::Credentials> {
        if let (Some(ref u), Some(ref p)) = (&self.config.http.user, &self.config.http.password) {
            return Some(ut_core::types::Credentials {
                username: u.clone(),
                password: p.clone(),
            });
        }
        if let (Some(ref u), Some(ref p)) = (&url.user, &url.password) {
            return Some(ut_core::types::Credentials {
                username: u.clone(),
                password: p.clone(),
            });
        }
        self.netrc.lookup(&url.host)
    }

    /// Process Set-Cookie headers from an HTTP response and update the cookie jar.
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed URL that returned the response.
    /// * `headers` - The HTTP response headers.
    fn process_cookies(&mut self, url: &ParsedUrl, headers: &HeaderMap) {
        if !self.config.cookie.enabled {
            return;
        }
        for cookie_header in headers.set_cookies() {
            self.cookie_jar.parse_set_cookie(cookie_header, &url.host, &url.path);
        }
    }

    /// Convert an HTTP response into a `ResponseMeta` struct for further processing.
    ///
    /// Extracts status code, content length, content type, timestamps,
    /// etag, location, server, accept-ranges, and document flags.
    ///
    /// # Arguments
    ///
    /// * `response` - The HTTP response.
    /// * `ct` - Optional content-type string.
    ///
    /// # Returns
    ///
    /// A `ResponseMeta` with parsed metadata.
    fn http_response_to_meta(&self, response: &HttpResponse, ct: Option<&str>) -> ResponseMeta {
        let mut flags = determine_document_flags(ct, response.status_code);

        if response.headers.accept_ranges() {
            flags |= DocumentFlags::ACCEPT_RANGES;
        }

        let last_modified = response.headers.last_modified()
            .and_then(parse_http_date);

        let etag = response.headers.etag().map(|s| s.to_string());

        let location = response.location().map(|s| s.to_string());

        let server = response.headers.server().map(|s| s.to_string());

        let content_length = response.content_length();

        ResponseMeta {
            status_code: response.status_code,
            content_length,
            content_type: ct.map(|s| s.to_string()),
            last_modified,
            accept_ranges: response.headers.accept_ranges(),
            location,
            etag,
            server,
            document_flags: flags,
            keep_alive: response.keep_alive(),
        }
    }

    /// Apply the server-provided Last-Modified timestamp to the local file.
    ///
    /// Only applies when `--use-server-timestamps` is enabled (the default).
    ///
    /// # Arguments
    ///
    /// * `path` - The local file path.
    /// * `meta` - The response metadata containing the timestamp.
    fn apply_server_timestamp(&self, path: &Path, meta: &ResponseMeta) {
        if !self.config.use_server_timestamps {
            return;
        }
        if let Some(lm) = meta.last_modified {
            apply_file_timestamp(path, lm);
        }
    }

    /// Write a WARC record for the downloaded response.
    ///
    /// Only active when the `warc` feature is enabled and a WARC writer
    /// has been initialized.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL string.
    /// * `response` - The HTTP response.
    /// * `meta` - The response metadata.
    #[cfg(feature = "warc")]
    fn write_warc_record(
        &mut self,
        url: &str,
        response: &HttpResponse,
        meta: &ResponseMeta,
        output_path: &std::path::Path,
    ) {
        if let Some(ref mut warc) = self.warc {
            let date = Utc::now();
            let header_bytes = serialize_headers(&response.headers);
            // Read the response body from the downloaded file so the WARC
            // record contains the full response (GNU wget writes the full
            // response body to WARC).  If the file is not available or too
            // large, record an empty payload with the headers preserved.
            let body_bytes = if output_path.exists() {
                match std::fs::read(output_path) {
                    Ok(data) => data,
                    Err(e) => {
                        warn!("WARC: failed to read body from {}: {}", output_path.display(), e);
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };
            let ct = meta.content_type.as_deref().unwrap_or("application/octet-stream");
            if let Err(e) = warc.write_response(url, response.status_code, &header_bytes, &body_bytes, ct, date) {
                warn!("WARC write failed: {}", e);
            }
        }
    }

    /// Get a reference to the download registry.
    pub fn download_registry(&self) -> &DownloadRegistry {
        &self.download_registry
    }

    /// Get a mutable reference to the download registry.
    pub fn download_registry_mut(&mut self) -> &mut DownloadRegistry {
        &mut self.download_registry
    }

    /// Get the total number of bytes downloaded so far.
    pub fn total_downloaded(&self) -> u64 {
        self.total_downloaded
    }

    /// Get a reference to the cookie jar.
    pub fn cookie_jar(&self) -> &CookieJar {
        &self.cookie_jar
    }

    /// Get a reference to the URL filter.
    pub fn url_filter(&self) -> &CompositeFilter {
        &self.url_filter
    }

    /// Get a reference to the application configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Persist session state to disk.
    ///
    /// Saves cookies to `--save-cookies` file (if configured) and the HSTS
    /// cache to `--hsts-file` (or `~/.wget-hsts` by default) when HSTS is
    /// enabled. Errors are logged as warnings rather than propagated, so a
    /// save failure never masks the download result.
    pub fn save_state(&self) {
        // Save cookies
        if let Some(ref cookie_file) = self.config.cookie.output_file {
            match fs::OpenOptions::new().create(true).write(true).truncate(true).open(cookie_file) {
                Ok(mut file) => {
                    // Restrict permissions to 0600 (owner-only) to protect
                    // session auth tokens, matching GNU wget behavior.
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
                    }
                    if let Err(e) = self.cookie_jar.save_to_writer(file) {
                        warn!("failed to save cookies to {}: {}", cookie_file.display(), e);
                    }
                }
                Err(e) => warn!("failed to create cookie file {}: {}", cookie_file.display(), e),
            }
        }

        // Save HSTS store
        #[cfg(feature = "hsts")]
        {
            if self.config.hsts.enabled {
                let hsts_path = self.config.hsts.file.clone().or_else(|| {
                    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".wget-hsts"))
                });
                if let Some(ref path) = hsts_path {
                    if let Err(e) = self.hsts.save_to_file(path) {
                        warn!("failed to save HSTS to {}: {}", path.display(), e);
                    }
                }
            }
        }
    }

    /// Calculate the backoff duration for retry attempts.
    ///
    /// Uses exponential backoff with an optional random jitter
    /// (when `--random-wait` is enabled), capped at 60 seconds.
    ///
    /// # Arguments
    ///
    /// * `attempt` - The zero-based retry attempt number.
    ///
    /// # Returns
    ///
    /// The duration to wait before the next retry.
    fn calculate_backoff(&self, attempt: u32) -> Duration {
        let base = self.config.wait_retry.unwrap_or(Duration::from_secs(1));
        let max_wait = Duration::from_secs(60);
        let exponential = base.saturating_mul(2u32.saturating_pow(attempt));

        let jitter = if self.config.random_wait {
            let mut rng = rand::thread_rng();
            let ms = rng.gen_range(0..=500);
            Duration::from_millis(ms)
        } else {
            Duration::ZERO
        };

        (exponential + jitter).min(max_wait)
    }
}
