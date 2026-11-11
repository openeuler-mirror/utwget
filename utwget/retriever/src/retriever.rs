//! File retriever implementation.
//!
//! This module provides the main `Retriever` struct for downloading files
//! from HTTP, HTTPS, FTP, and FTPS URLs.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Local, Utc};
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
    parse_content_disposition, resolve_proxy, rotate_backups, serialize_headers,
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
    /// Buffered leftover bytes and body reader from the last HTTP response head read.
    pending_body_reader: Option<(Vec<u8>, Box<dyn Read>)>,
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

        let mut url_filter = CompositeFilter::new();
        if !config.recursive.domains.is_empty() || !config.recursive.exclude_domains.is_empty() {
            url_filter.add(ut_core::regex_filter::DomainFilter::new(
                config.recursive.domains.clone(),
                config.recursive.exclude_domains.clone(),
            ));
        }

        let mut retriever = Retriever {
            config,
            progress,
            cookie_jar,
            netrc,
            url_filter,
            download_registry: DownloadRegistry::new(),
            auth_dispatcher: AuthDispatcher::new(),
            total_downloaded: 0,
            start_time: Instant::now(),
            #[cfg(feature = "warc")]
            warc: None,
            connection_pool: TlsConnectionPool::new(5), // Max 5 connections per pool
            pending_body_reader: None,
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
        let parsed = ParsedUrl::parse(url).map_err(RetrieveError::Protocol)?;
        let max_tries = self.config.tries;

        let mut state = ProtocolState::default();
        let mut last_error = None;

        for attempt in 0..max_tries {
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

        let display_url = url.display();
        info!("--{}", display_url);

        let effective_url = match self.resolve_effective_url(url) {
            Some(u) => u,
            None => url.clone(),
        };

        let output_path = self.determine_output_path(&effective_url)?;

        // Debug: log output_path
        debug!("determine_output_path returned: {:?}", output_path);
        debug!("config.output_document: {:?}", self.config.output_document);

        if self.check_existing(&output_path, &effective_url)? {
            return Ok(RetrieveOutcome::SpiderOnly);
        }

        let resume_pos = self.compute_resume_position(&output_path)?;
        state.resume_position = resume_pos;

        let mut opts = self.build_request_options(&effective_url, referer, Some(resume_pos));

        match effective_url.scheme {
            Scheme::Http | Scheme::Https => {
                self.retrieve_http(&effective_url, &mut opts, state, &output_path)
            }
            Scheme::Ftp | Scheme::Ftps => {
                self.retrieve_ftp(&effective_url, &mut opts, state, &output_path)
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
                self.auth_dispatcher.preemptive_auth(c, &url.full_path())
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

        // Debug: show request headers
        if self.config.debug {
            eprintln!("---请求头---");
            eprintln!("{} {} HTTP/1.1", req.method, req.path);
            eprintln!("Host: {}", url.host);
            for (key, value) in req.headers.iter() {
                eprintln!("{}: {}", key, value);
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
                Some(r) => r,
                None => {
                    let (r, leftover, reader) = self.do_http_request(&req, url)?;
                    self.pending_body_reader = Some((leftover, reader));
                    r
                }
            }
        };
        #[cfg(not(feature = "http2"))]
        let mut response = {
            let (r, leftover, reader) = self.do_http_request(&req, url)?;
            self.pending_body_reader = Some((leftover, reader));
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

        // Spider mode: if response is successful, report file exists and return
        // without downloading the body (matches wget --spider behavior).
        if self.config.recursive.spider {
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

        // Only show full HTTP headers if --server-response is enabled
        if self.config.server_response && !self.config.quiet {
            eprintln!("{} {} {}", response.version, response.status_code, response.reason);
            for (key, value) in response.headers.iter() {
                eprintln!("  {}: {}", key, value);
            }
            eprintln!();
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

        if response.status_code == 401 && creds.is_some() {
            let www_auth = response.headers.www_authenticate();
            if !www_auth.is_empty() {
                let challenges = AuthChallenge::from_www_authenticate(&www_auth.join(", "));
                for challenge in &challenges {
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
                                let (r, leftover, reader) = self.do_http_request(&retry_req, url)?;
                                self.pending_body_reader = Some((leftover, reader));
                                r
                            };
                            state.auth_finished = true;
                            self.process_cookies(&url, &response.headers);
                            break;
                        }
                    }
                }
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
        if response.is_client_error() && response.status_code != 416 {
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
                debug!("using filename from Content-Disposition: {}", filename);
                let mut new_path = output_path.parent().unwrap_or(Path::new(".")).to_path_buf();
                new_path.push(filename);
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

        // Rotate backup files if --backups is set
        if let Some(n_backups) = self.config.backups {
            if n_backups > 0 {
                rotate_backups(&output_path, n_backups);
            }
        }

        // Remove existing file if --unlink is set
        if self.config.unlink && output_path.exists() {
            fs::remove_file(&output_path).map_err(RetrieveError::Io)?;
        }

        // Handle --start-pos: use configured start position or computed resume position
        let effective_resume_pos = self.config.start_position.unwrap_or(state.resume_position);
        state.resume_position = effective_resume_pos;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(effective_resume_pos == 0)
            .append(effective_resume_pos > 0)
            .open(&output_path)
            .map_err(RetrieveError::Io)?;

        // Use Content-Length for progress, unless ignore_length is set
        let total_size = if self.config.ignore_length {
            None
        } else {
            resp_meta.content_length.and_then(|cl| cl.checked_add(effective_resume_pos))
            })
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
        if let Some((leftover, mut reader)) = self.pending_body_reader.take() {
            body_bytes_read = stream_response_body(
                &mut io::Cursor::new(leftover).chain(&mut reader),
                &mut file,
                &response,
                &mut *self.progress,
                state.resume_position,
            )?;
        }

        let elapsed = start.elapsed();
        self.progress.finish(ut_progress::FinishStatus::Success {
            downloaded: body_bytes_read,
            elapsed,
        });

        self.total_downloaded += body_bytes_read;
        state.last_content_length = Some(body_bytes_read);
        state.head_done = true;

        self.apply_server_timestamp(&output_path, &resp_meta);
        self.download_registry.register_download(&url.display(), &output_path);

        #[cfg(feature = "warc")]
        self.write_warc_record(&url.display(), &response, &resp_meta);

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

        // Adjust file extension based on Content-Type if --adjust-extension is set
        let final_output_path = if self.config.adjust_extension {
            adjust_file_extension(&output_path, resp_meta.content_type.as_deref())
        } else {
            output_path.clone()
        };

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
            // Use FTPS client
            let mut ftps_client = ut_ftp::FtpsClient::new();

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
                    let _ = ftps_client.cwd(dir);
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
        let mut ftp_client = ut_ftp::FtpClient::new();
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
                let _ = ftp_client.cwd(dir);
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

        ftp_client.quit()
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("FTP quit error: {}", e))))?;

        let elapsed = start.elapsed();
        self.progress.finish(ut_progress::FinishStatus::Success {
            downloaded: total_bytes,
            elapsed,
        });

        self.total_downloaded += total_bytes;

        if let Some(mdtm) = ftp_client.mdtm(filename).ok().flatten() {
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
    fn create_tcp_stream(&self, host: &str, port: u16) -> Result<std::net::TcpStream, RetrieveError> {
        // Try to get a connection from the pool first
        if let Some(conn) = self.connection_pool.get_tcp(host, port) {
            debug!("reusing pooled TCP connection to {}:{}", host, port);
            return Ok(conn);
        }

        use std::net::ToSocketAddrs;

        let _addr_str = format!("{}:{}", host, port);

        // Resolve addresses with optional DNS timeout
        let addresses: Vec<std::net::SocketAddr> = {
            let addrs = if let Some(dns_timeout) = self.config.dns_timeout.or(self.config.timeout) {
                // Use a thread with timeout for DNS resolution
                let host_owned = host.to_string();
                let result = std::thread::scope(|s| {
                    let handle = s.spawn(move || {
                        (host_owned.as_str(), port).to_socket_addrs()
                    });
                    // Wait with timeout
                    let start = Instant::now();
                    loop {
                        if handle.is_finished() {
                            break handle.join().unwrap();
                        }
                        if start.elapsed() > dns_timeout {
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS resolution timeout"));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                });
                result.map_err(|e| RetrieveError::Protocol(WgetError::Other(
                    format!("DNS resolution error: {}", e)
                )))?
            } else {
                (host, port).to_socket_addrs()
                    .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                        format!("DNS resolution error: {}", e)
                    )))?
            };
            addrs.collect()
        };

        if addresses.is_empty() {
            return Err(RetrieveError::Protocol(WgetError::HostNotFound(host.to_string())));
        }

        // Filter addresses based on address family settings
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

            // Apply bind address if set (requires socket2 crate for proper implementation)
            if let Some(ref bind_addr) = self.config.bind_address {
                debug!("--bind-address={} requested for connection to {}", bind_addr, addr);
            }

            let stream_result = if let Some(timeout) = connect_timeout {
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
    ) -> Result<(HttpResponse, Vec<u8>, Box<dyn Read>), RetrieveError> {
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
                stream = self.establish_connect_tunnel(&mut stream, host, port)?;
                debug!("CONNECT tunnel established for {}:{}", host, port);

                // Now wrap with TLS
                let tls_config = ut_net::tls::TlsConfig::from_core(&self.config.tls);
                let tls_connector = ut_net::tls::RustlsConnector::new();
                let mut tls_stream = tls_connector.connect(
                    Box::new(ut_net::transport::TcpTransport::new(stream)),
                    host,
                    port,
                    &tls_config,
                ).map_err(|e| RetrieveError::Protocol(WgetError::Tls(ut_core::error::TlsError::HandshakeFailed(e.to_string()))))?;

                // Send request over TLS
                let serialized = request.serialize().map_err(RetrieveError::Io)?;
                debug!("HTTPS request over proxy tunnel:\n{}", String::from_utf8_lossy(&serialized));
                tls_stream.write_all(&serialized).map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("write error: {}", e))))?;

                let (response, leftover) = {
                    let mut reader = TransportRead::new(&mut tls_stream);
                    read_response_head(&mut reader)?
                };
                let boxed_reader: Box<dyn Read> = Box::new(OwnedTransportRead::new(tls_stream));
                Ok((response, leftover, boxed_reader))
            } else {
                // Plain HTTP over proxy
                let proxy_req = build_proxy_request(request, &url.host, url.port);
                let serialized = proxy_req.serialize().map_err(RetrieveError::Io)?;
                stream.write_all(&serialized).map_err(RetrieveError::Io)?;
                stream.flush().map_err(RetrieveError::Io)?;

                let (response, leftover) = read_response_head(&mut stream)?;
                let boxed_reader: Box<dyn Read> = Box::new(stream);
                Ok((response, leftover, boxed_reader))
            }
        } else {
            debug!("connecting to {}:{}", host, port);
            let mut stream = self.create_tcp_stream(host, port)?;

            if url.scheme.is_secure() {
                // Wrap with TLS
                let tls_config = ut_net::tls::TlsConfig::from_core(&self.config.tls);
                let tls_connector = ut_net::tls::RustlsConnector::new();
                let mut tls_stream = tls_connector.connect(
                    Box::new(ut_net::transport::TcpTransport::new(stream)),
                    host,
                    port,
                    &tls_config,
                ).map_err(|e| RetrieveError::Protocol(WgetError::Tls(ut_core::error::TlsError::HandshakeFailed(e.to_string()))))?;

                let serialized = request.serialize().map_err(RetrieveError::Io)?;
                debug!("HTTPS request:\n{}", String::from_utf8_lossy(&serialized));
                tls_stream.write_all(&serialized).map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("write error: {}", e))))?;

                let (response, leftover) = {
                    let mut reader = TransportRead::new(&mut tls_stream);
                    read_response_head(&mut reader)?
                };
                let boxed_reader: Box<dyn Read> = Box::new(OwnedTransportRead::new(tls_stream));
                Ok((response, leftover, boxed_reader))
            } else {
                let serialized = request.serialize().map_err(RetrieveError::Io)?;
                debug!("HTTP request:\n{}", String::from_utf8_lossy(&serialized));
                stream.write_all(&serialized).map_err(RetrieveError::Io)?;
                stream.flush().map_err(RetrieveError::Io)?;

                let (response, leftover) = read_response_head(&mut stream)?;
                let boxed_reader: Box<dyn Read> = Box::new(stream);
                Ok((response, leftover, boxed_reader))
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
    ) -> Result<std::net::TcpStream, RetrieveError> {
        // Send CONNECT request
        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            host, port, host, port
        );
        debug!("CONNECT request: {}", connect_req);
        stream.write_all(connect_req.as_bytes()).map_err(RetrieveError::Io)?;
        stream.flush().map_err(RetrieveError::Io)?;

        // Read CONNECT response
        let mut response_line = String::new();
        let mut buf = [0u8; 1];
        loop {
            let n = stream.read(&mut buf).map_err(RetrieveError::Io)?;
            if n == 0 {
                return Err(RetrieveError::Protocol(WgetError::Other(
                    "proxy connection closed".into(),
                )));
            }
            response_line.push(buf[0] as char);
            if response_line.ends_with("\r\n\r\n") {
                break;
            }
        }

        // Parse response status line
        let status_line = response_line.lines().next().unwrap_or("");
        debug!("CONNECT response: {}", status_line);

        // Parse the numeric status code properly
        let status_ok = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .map_or(false, |code| code == 200);

        if !status_ok {
            return Err(RetrieveError::Protocol(W.getError::Other(format!(
                "proxy CONNECT failed: {}",
                status_line
            ))));
        }

        // Return the stream for TLS wrapping
        Ok(stream.try_clone().map_err(RetrieveError::Io)?)
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
struct OwnedTransportRead {
    inner: Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>,
}

impl OwnedTransportRead {
    fn new(inner: Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>) -> Self {
        OwnedTransportRead { inner }
    }
}

impl Read for OwnedTransportRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner
            .read(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

fn stream_response_body<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    response: &HttpResponse,
    progress: &mut dyn ProgressDisplay,
    resume_from: u64,
) -> Result<u64, RetrieveError> {
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
        Ok(received)
    } else if let Some(len) = response.content_length() {
        let mut received = 0u64;
        let mut tmp = [0u8; 8192];
        while received < len {
            let want = ((len - received) as usize).min(tmp.len());
            let n = reader
                .read(&mut tmp[..want])
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("body read error: {}", e))))?;
            if n == 0 {
                debug!("response body truncated: got {} of {} bytes", received, len);
                break;
            }
            writer.write_all(&tmp[..n]).map_err(RetrieveError::Io)?;
            received += n as u64;
            progress.update(resume_from + received, Duration::ZERO);
        }
        Ok(received)
    } else {
        let mut received = 0u64;
        let mut tmp = [0u8; 8192];
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
        Ok(received)
    }
}

/// Reads only the HTTP response head (status line + headers), returning any
/// leftover body bytes that were read together with the headers.
fn read_response_head<R: Read>(
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

        if self.config.timestamping || self.config.if_modified_since {
            if let Ok(metadata) = fs::metadata(self.determine_output_path(url).unwrap_or_default()) {
                if let Ok(mtime) = metadata.modified() {
                    opts.if_modified_since = Some(mtime.into());
                }
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

        let mut path = url.to_filename(self.config.no_host_directories);

        if self.config.protocol_directories {
            let scheme_dir = PathBuf::from(url.scheme.as_str());
            path = scheme_dir.join(path);
        }

        if self.config.cut_dirs > 0 {
            let components: Vec<_> = path.components().collect();
            let skip = (self.config.cut_dirs as usize).min(components.len());
            let remaining: PathBuf = components[skip..].iter().collect();
            path = remaining;
        }

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
    ) {
        if let Some(ref mut warc) = self.warc {
            let date = Utc::now();
            let header_bytes = serialize_headers(&response.headers);
            let body_bytes = response.body.as_deref().unwrap_or(&[]);
            let ct = meta.content_type.as_deref().unwrap_or("application/octet-stream");
            let _ = warc.write_response(url, response.status_code, &header_bytes, body_bytes, ct, date);
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
        let exponential = base * 2u32.saturating_pow(attempt);

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
