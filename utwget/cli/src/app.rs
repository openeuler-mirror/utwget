use std::fs;
use std::io::{self, BufRead, BufReader, Cursor, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use ut_core::error::WgetError;
use ut_core::url::ParsedUrl;
use ut_retriever::{AsyncRetriever, Retriever, RetrieveOutcome, RecursiveRetriever};
use ut_html::converter::{LinkConverter, ConvertOptions};
use std::collections::HashMap;

#[cfg(feature = "metalink")]
use ut_metalink::{MetalinkParser, MetalinkDownloader};

use crate::args::Args;

/// Represents the exit status of the application, returned to the operating system.
///
/// Maps to the standard wget exit codes (see `exits.h` in original wget):
///
/// | Code | Name              | Meaning                                     |
/// |------|-------------------|---------------------------------------------|
/// |  0   | SUCCESS           | All URLs downloaded successfully            |
/// |  1   | GENERIC_ERROR     | Generic error                               |
/// |  2   | PARSE_ERROR       | Command-line or config parse error          |
/// |  3   | IO_FAIL           | File I/O error                              |
/// |  4   | NETWORK_FAIL      | Network/connectivity failure                |
/// |  5   | SSL_AUTH_FAIL     | SSL/TLS certificate verification failure    |
/// |  6   | SERVER_AUTH_FAIL  | Server authentication failure               |
/// |  7   | PROTOCOL_ERROR    | Remote server returned invalid response     |
/// |  8   | SERVER_ERROR      | Remote server returned error                |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExitStatus {
    /// All URLs completed successfully (exit code 0).
    Success,
    /// Generic error (exit code 1).
    Error,
    /// File I/O error: cannot open, write, or close a local file (exit code 3).
    IoFail,
    /// Network failure: DNS, connection, timeout (exit code 4).
    NetworkFail,
    /// SSL/TLS certificate verification failed (exit code 5).
    SslAuthFail,
    /// Server authentication failed: bad credentials (exit code 6).
    ServerAuthFail,
    /// Protocol error: malformed response from server (exit code 7).
    ProtocolError,
    /// Server returned an error response (exit code 8).
    ServerError,
}

impl ExitStatus {
    /// Maps a `WgetError` to the corresponding exit status code.
    ///
    /// Mirrors GNU wget's exit-code mapping from `exits.c` and `http.c`:
    /// - HTTP 4xx/5xx → `ServerError` (8)
    /// - FTP file not found → `ServerError` (8) (FTPNSFOD)
    /// - Retry limit exceeded → `NetworkFail` (4) (TRYLIMEXC)
    /// - TLS init failed → `Error` (1) (SSLINITFAILED → UNKNOWN)
    /// - URL parse / unsupported scheme → `Error` (1) (URLERROR → UNKNOWN)
    pub fn from_error(err: &ut_core::error::WgetError) -> Self {
        use ut_core::error::TlsError;
        match err {
            WgetError::FileNotFound(_)
            | WgetError::FileExists(_)
            | WgetError::CannotCreateDir(_)
            | WgetError::WriteError(_) => ExitStatus::IoFail,

            WgetError::HostNotFound(_)
            | WgetError::ConnectionRefused
            | WgetError::ConnectionTimeout(_)
            | WgetError::SocketError(_) => ExitStatus::NetworkFail,

            WgetError::Tls(TlsError::HandshakeFailed(_))
            | WgetError::Tls(TlsError::CertError(_))
            | WgetError::Tls(TlsError::HostnameMismatch { .. })
            | WgetError::Tls(TlsError::CertExpired)
            | WgetError::Tls(TlsError::CertNotYetValid)
            | WgetError::Tls(TlsError::SelfSigned)
            | WgetError::Tls(TlsError::UnknownAuthority(_))
            | WgetError::CertVerificationFailed { .. }
            | WgetError::TlsInitFailed => ExitStatus::SslAuthFail,

            WgetError::AuthFailed(_)
            | WgetError::FtpLoginRefused => ExitStatus::ServerAuthFail,

            WgetError::Http { status: 400..=599, .. }
            | WgetError::FtpServerError(_)
            | WgetError::FtpFileNotFound(_)
            | WgetError::TooManyRedirects { .. } => ExitStatus::ServerError,

            WgetError::UnsupportedMethod(_)
            | WgetError::UrlParse(_)
            | WgetError::UnsupportedScheme(_) => ExitStatus::Error,

            WgetError::RetryLimitExceeded { .. } => ExitStatus::NetworkFail,

            WgetError::QuotaExceeded { .. }
            | WgetError::MetalinkParse(_)
            | WgetError::MetalinkDownload(_)
            | WgetError::MetalinkChecksum { .. }
            | WgetError::Warc(_)
            | WgetError::Config(_) => ExitStatus::Error,

            WgetError::Other(msg) => {
                if msg.contains("DNS") || msg.contains("resolve") || msg.contains("lookup") {
                    ExitStatus::NetworkFail
                } else {
                    ExitStatus::Error
                }
            }

            _ => ExitStatus::Error,
        }
    }

    /// Converts the exit status to the numeric exit code.
    pub fn to_exit_code(self) -> u8 {
        match self {
            ExitStatus::Success => 0,
            ExitStatus::Error => 1,
            ExitStatus::IoFail => 3,
            ExitStatus::NetworkFail => 4,
            ExitStatus::SslAuthFail => 5,
            ExitStatus::ServerAuthFail => 6,
            ExitStatus::ProtocolError => 7,
            ExitStatus::ServerError => 8,
        }
    }

    /// Update `current` with `new` using GNU wget's aggregation logic
    /// (exits.c:74-84): the first non-zero status wins, but a lower
    /// non-zero status replaces a higher one.
    ///
    /// ```text
    /// if new != 0 && (current == 0 || new < current)
    ///     current = new
    /// ```
    pub fn aggregate(current: ExitStatus, new: ExitStatus) -> ExitStatus {
        if new != ExitStatus::Success
            && (current == ExitStatus::Success || new < current)
        {
            new
        } else {
            current
        }
    }

    /// Converts a `u8` discriminant back to an `ExitStatus`.
    ///
    /// This is the inverse of `as u8` for use with atomic counters.
    /// Returns `ExitStatus::Error` for invalid values.
    fn from_u8(v: u8) -> Self {
        match v {
            0 => ExitStatus::Success,
            1 => ExitStatus::Error,
            3 => ExitStatus::IoFail,
            4 => ExitStatus::NetworkFail,
            5 => ExitStatus::SslAuthFail,
            6 => ExitStatus::ServerAuthFail,
            7 => ExitStatus::ProtocolError,
            8 => ExitStatus::ServerError,
            _ => ExitStatus::Error,
        }
    }
}

/// The main application harness that orchestrates the download process.
///
/// `App` ties together a retriever, the user configuration, and performance
/// bookkeeping. It supports single-shot download, recursive crawling, and
/// Metalink-based download (when the `metalink` feature is enabled).
pub struct App {
    /// The fully-resolved configuration, shared across the retriever and sub-components.
    config: Arc<ut_core::Config>,
    /// The core download engine.
    retriever: Retriever,
    /// Timestamp captured at construction time, used for the final summary.
    start_time: Instant,
    /// Total number of URLs that were attempted (parsed and sent to the retriever).
    urls_attempted: u32,
    /// Total number of URLs that completed downloading successfully.
    urls_downloaded: u32,
    /// Tracks the worst (highest numeric) exit status across all URLs.
    worst_status: ExitStatus,
}

impl App {
    /// Constructs a new `App` from the given configuration.
    ///
    /// This initializes the progress display (bar, dot, or silent depending on
    /// the config and whether stdout is a terminal) and creates the underlying
    /// `Retriever`.
    ///
    /// # Arguments
    /// * `config` — The user-provided configuration.
    ///
    /// # Returns
    /// A configured `App` instance, or a `WgetError` if construction fails.
    pub fn new(config: ut_core::Config) -> Result<Self, WgetError> {
        // --crl-file and --pinnedpubkey are accepted for wget compatibility,
        // but the current TLS backend (rustls) does not implement CRL
        // verification or public-key pinning. Fail closed: refuse to start so
        // that scripts cannot silently run without the requested protection
        // (security-by-warning is unsafe — stderr is often ignored/captured
        // away). Exit code 2 mirrors wget's "syntax/argument error".
        if config.tls.crl_file.is_some() {
            return Err(WgetError::Other(
                "--crl-file is not implemented in this build; refusing to start to avoid running without the requested CRL verification".into(),
            ));
        }
        if config.tls.pinned_pubkey.is_some() {
            return Err(WgetError::Other(
                "--pinnedpubkey is not implemented in this build; refusing to start to avoid running without the requested public-key pinning".into(),
            ));
        }

        let config = Arc::new(config);

        let is_interactive = io::stdout().is_terminal();
        let progress = if !config.quiet && !config.recursive.spider {
            let style = config.progress.style;
            let force_noscroll = !is_interactive;
            ut_progress::create_progress_display(style, force_noscroll)
        } else {
            ut_progress::create_progress_display(ut_core::ProgressStyle::Silent, true)
        };

        let retriever = Retriever::new(config.clone(), progress);

        Ok(App {
            config,
            retriever,
            start_time: Instant::now(),
            urls_attempted: 0,
            urls_downloaded: 0,
            worst_status: ExitStatus::Success,
        })
    }

    /// Runs the main download loop for the provided URLs.
    ///
    /// The method performs the following steps:
    /// 1. If `--force-html` was given, reads local HTML files to extract URLs.
    /// 2. If an `--input-file` was specified, reads URLs from that file (one per
    ///    line, skipping comments starting with `#`).
    /// 3. Delegates to Metalink mode, recursive mode, or the simple single-shot
    ///    loop depending on configuration.
    /// 4. Prints a final summary and returns the appropriate `ExitStatus`.
    ///
    /// # Arguments
    /// * `urls` — The slice of URL strings directly provided by the user.
    ///
    /// # Returns
    /// * `Ok(ExitStatus::Success)` — all URLs succeeded.
    /// * `Ok(ExitStatus::Error)` — some URLs failed.
    pub fn run(&mut self, urls: &[String]) -> Result<ExitStatus, WgetError> {
        let mut all_urls: Vec<String> = urls.to_vec();

        if self.config.force_html {
            let mut force_html_urls = Vec::new();
            for url in &all_urls {
                if !url.contains("://") {
                    let path = PathBuf::from(url.as_str());
                    if path.is_file() {
                        match self.read_html_file_urls(&path) {
                            Ok(file_urls) => force_html_urls.push((url.clone(), file_urls)),
                            Err(_) => return Err(WgetError::ProtocolIo(format!("failed to read HTML input file: {}", url))),
                        }
                    }
                }
            }
            for (original, replacements) in force_html_urls {
                let idx = all_urls.iter().position(|u| u == &original);
                if let Some(idx) = idx {
                    all_urls[idx] = replacements.join("\n");
                }
            }
        }

        if let Some(ref input_file) = self.config.input_filename {
            match fs::File::open(input_file) {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    for line in reader.lines() {
                        match line {
                            Ok(line) => {
                                let trimmed = line.trim();
                                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                                    all_urls.push(trimmed.to_string());
                                }
                            }
                            Err(e) => return Err(WgetError::ProtocolIo(format!("error reading input file: {}", e))),
                        }
                    }
                }
                Err(_) => return Err(WgetError::FileNotFound(input_file.clone())),
            }
        }

        if all_urls.is_empty() {
            return Err(WgetError::Other("no URLs specified".to_string()));
        }

        // Check for Metalink mode
        #[cfg(feature = "metalink")]
        {
            if self.config.metalink.enabled {
                return self.run_metalink(&all_urls);
            }
        }

        // Check if recursive mode is enabled
        // GNU wget enters retrieve_tree when either -r or -p is set
        // (main.c:2147). With -p alone, recursive stays false but
        // page_requisites triggers the tree path.
        if self.config.recursive.enabled || self.config.page_requisites {
            // -j N in recursive mode: use parallel recursive download
            if self.config.concurrent_downloads > 1 {
                return self.run_recursive_parallel(&all_urls, self.config.concurrent_downloads);
            }
            return self.run_recursive(&all_urls);
        }

        // Use concurrent downloads if concurrency > 1
        if self.config.concurrent_downloads > 1 {
            return self.run_concurrent(&all_urls, self.config.concurrent_downloads);
        }

        for url_str in &all_urls {
            // Check for SIGINT/SIGTERM before starting each URL
            if crate::signal::should_stop() {
                if self.config.verbose >= 1 {
                    eprintln!("{}", crate::i18n::translate("utwget.signal_interrupted"));
                }
                break;
            }

            let expanded = self.expand_url(url_str);
            let url_str = expanded.as_str();

            let parsed = match ParsedUrl::parse(url_str) {
                Ok(p) => p,
                Err(e) => {
                    self.urls_attempted += 1;
                    // URL parse failures should produce exit code 1 (Error),
                    // not be silently swallowed as exit 0.
                    self.worst_status = ExitStatus::aggregate(
                        self.worst_status,
                        ExitStatus::Error,
                    );
                    if self.config.verbose >= 1 || self.config.debug {
                        eprintln!("wget-rs: {}", e);
                    }
                    continue;
                }
            };

            self.urls_attempted += 1;

            // Clear redirect GET-method set before each independent download
            // so a URL downgraded in a previous download doesn't bleed into
            // an unrelated download that targets the same URL.
            self.retriever.clear_redirect_state();

            let result = self.retriever.retrieve_with_retry(&parsed.display_with_credentials());

            match result {
                Ok(RetrieveOutcome::Success(body_result)) => {
                    self.urls_downloaded += 1;
                    if let Some(ref file) = body_result.local_file {
                        if self.config.verbose >= 1 {
                            eprintln!("{}", crate::i18n::translate_with_args("utwget.status_saved_to", &[("path", file.display().to_string())]));
                        }
                    }
                }
                Ok(RetrieveOutcome::NotModified) => {
                    if self.config.verbose >= 1 {
                        eprintln!("{}", crate::i18n::translate("utwget.status_not_modified"));
                    }
                }
                Ok(RetrieveOutcome::Redirected(new_url)) => {
                    if self.config.verbose >= 1 {
                        eprintln!("{}", crate::i18n::translate_with_args("utwget.status_redirected_to", &[("url", new_url.clone())]));
                    }
                    let mut redirect_url = new_url;
                    // The first redirect already occurred in the initial request,
                    // so start counting from 1.
                    let mut redirect_count = 1u32;
                    let max_redirects = self.config.max_redirect;
                    loop {
                        // GNU wget (retr.c:1061): ++count > max_redirect.
                        // With max=0: count(1) > 0 → true → stop.
                        // With max=1: count(1) > 1 → false → follow, then count(2) > 1 → stop.
                        if redirect_count > max_redirects {
                            if self.config.verbose >= 1 {
                                eprintln!("{}", crate::i18n::translate("utwget.error_too_many_redirects"));
                            }
                            self.worst_status = ExitStatus::aggregate(
                                self.worst_status,
                                ExitStatus::ServerError,
                            );
                            break;
                        }
                        redirect_count += 1;
                        let redirect_parsed = match ParsedUrl::parse(&redirect_url) {
                            Ok(p) => p,
                            Err(e) => {
                                if self.config.verbose >= 1 || self.config.debug {
                                    eprintln!("utwget: redirect parse error: {}", e);
                                }
                                self.worst_status = ExitStatus::ProtocolError;
                                break;
                            }
                        };
                        match self.retriever.retrieve_with_retry(&redirect_parsed.display_with_credentials()) {
                            Ok(RetrieveOutcome::Success(body_result)) => {
                                self.urls_downloaded += 1;
                                if let Some(ref file) = body_result.local_file {
                                    if self.config.verbose >= 1 {
                                        eprintln!("{}", crate::i18n::translate_with_args("utwget.status_saved_to", &[("path", file.display().to_string())]));
                                    }
                                }
                                break;
                            }
                            Ok(RetrieveOutcome::NotModified) => {
                                if self.config.verbose >= 1 {
                                    eprintln!("{}", crate::i18n::translate("utwget.status_not_modified"));
                                }
                                break;
                            }
                            Ok(RetrieveOutcome::Redirected(next_url)) => {
                                if self.config.verbose >= 1 {
                                    eprintln!("{}", crate::i18n::translate_with_args("utwget.status_redirected_to", &[("url", next_url.clone())]));
                                }
                                redirect_url = next_url;
                            }
                            Ok(RetrieveOutcome::SpiderOnly) => {
                                break;
                            }
                            Err(e) => {
                                let wg_err: WgetError = e.into();
                                let status = ExitStatus::from_error(&wg_err);
                                self.worst_status = ExitStatus::aggregate(self.worst_status, status);
                                if self.config.verbose >= 1 || self.config.debug {
                                    eprintln!("{}", crate::i18n::translate_with_args("utwget.error_downloading", &[
                                        ("url", redirect_url),
                                        ("error", wg_err.to_string()),
                                    ]));
                                }
                                break;
                            }
                        }
                    }
                }
                Ok(RetrieveOutcome::SpiderOnly) => {
                    // Spider mode, no download
                }
                Err(e) => {
                    let wg_err: WgetError = e.into();
                    let status = ExitStatus::from_error(&wg_err);
                    self.worst_status = ExitStatus::aggregate(self.worst_status, status);
                    if self.config.verbose >= 1 || self.config.debug {
                        eprintln!("{}", crate::i18n::translate_with_args("utwget.error_downloading", &[
                            ("url", url_str.to_string()),
                            ("error", wg_err.to_string()),
                        ]));
                    }
                }
            }
        }

        self.print_summary();

        if self.urls_attempted == 0 {
            Ok(ExitStatus::Error)
        } else if self.worst_status > ExitStatus::Success {
            Ok(self.worst_status)
        } else {
            Ok(ExitStatus::Success)
        }
    }

    /// Run concurrent downloads using tokio async runtime.
    ///
    /// Downloads multiple URLs in parallel using tokio tasks with configurable
    /// concurrency. Each task runs the synchronous Retriever in a blocking thread.
    ///
    /// # Arguments
    ///
    /// * `urls` - The slice of URL strings to download concurrently.
    /// * `concurrency` - Maximum number of concurrent downloads.
    ///
    /// # Returns
    ///
    /// * `ExitStatus::Success` if all downloads succeeded.
    /// * `ExitStatus::Error` if any download failed.
    fn run_concurrent(&mut self, urls: &[String], concurrency: usize) -> Result<ExitStatus, WgetError> {
        if urls.is_empty() {
            return Ok(ExitStatus::Error);
        }

        let urls = urls.to_vec();
        let config = self.config.clone();
        // Use atomic counters instead of Mutex to avoid lock contention.
        // Atomic operations are lock-free and significantly faster under
        // concurrent access than Mutex-protected counters.
        let worst_status = Arc::new(AtomicU8::new(ExitStatus::Success as u8));
        let urls_downloaded = Arc::new(AtomicU32::new(0));
        let urls_attempted = Arc::new(AtomicU32::new(0));

        // Create tokio runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(concurrency.min(num_cpus::get()))
            .enable_all()
            .build()
            .map_err(|e| WgetError::TaskJoin(format!("failed to create tokio runtime: {}", e)))?;

        runtime.block_on(async {
            // Create async retriever with concurrency limit
            let async_retriever = AsyncRetriever::new(config.clone(), concurrency);
            let mut handles = Vec::new();

            for url in urls {
                let async_retriever = async_retriever.clone();
                let worst_status = worst_status.clone();
                let urls_downloaded = urls_downloaded.clone();
                let urls_attempted = urls_attempted.clone();

                let handle = tokio::task::spawn(async move {
                    urls_attempted.fetch_add(1, Ordering::Relaxed);

                    // Use async retriever
                    let result = async_retriever.retrieve(&url).await;

                    match result {
                        Ok(RetrieveOutcome::Success(_)) | Ok(_) => {
                            urls_downloaded.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            let wg_err: WgetError = e.into();
                            let status = ExitStatus::from_error(&wg_err);
                            // Atomically update worst_status using GNU
                            // wget's aggregation logic (exits.c:74-84):
                            // first non-zero wins, lower non-zero replaces
                            // higher.
                            let status_u8 = status as u8;
                            loop {
                                let current = worst_status.load(Ordering::Relaxed);
                                // new != 0 && (current == 0 || new < current)
                                let should_update = status_u8 != 0
                                    && (current == 0 || status_u8 < current);
                                if !should_update {
                                    break;
                                }
                                match worst_status.compare_exchange_weak(
                                    current,
                                    status_u8,
                                    Ordering::Relaxed,
                                    Ordering::Relaxed,
                                ) {
                                    Ok(_) => break,
                                    Err(_) => continue,
                                }
                            }
                        }
                    }
                });
                handles.push(handle);
            }

            // Wait for all tasks to complete
            for handle in handles {
                if let Err(e) = handle.await {
                    // Task panicked or was cancelled
                    log::error!("Download task failed: {}", e);
                    let status_u8 = ExitStatus::NetworkFail as u8;
                    loop {
                        let current = worst_status.load(Ordering::Relaxed);
                        let should_update = status_u8 != 0
                            && (current == 0 || status_u8 < current);
                        if !should_update {
                            break;
                        }
                        match worst_status.compare_exchange_weak(
                            current,
                            status_u8,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(_) => continue,
                        }
                    }
                }
            }
        });

        self.urls_attempted = urls_attempted.load(Ordering::Relaxed);
        self.urls_downloaded = urls_downloaded.load(Ordering::Relaxed);
        self.worst_status = ExitStatus::from_u8(worst_status.load(Ordering::Relaxed));

        self.print_summary();

        if self.urls_attempted == 0 {
            Ok(ExitStatus::Error)
        } else if self.worst_status > ExitStatus::Success {
            Ok(self.worst_status)
        } else {
            Ok(ExitStatus::Success)
        }
    }

    /// Run in recursive mode.
    ///
    /// Creates a `RecursiveRetriever` and crawls each start URL, downloading
    /// linked pages up to the configured recursion depth. After crawling
    /// completes, performs link conversion if `--convert-links` was requested.
    ///
    /// # Arguments
    /// * `urls` — The slice of starting-point URL strings.
    ///
    /// # Returns
    /// * `ExitStatus::Success` if all start URLs completed without error.
    /// * `ExitStatus::Error` if any start URL or its subtree failed.
    fn run_recursive(&mut self, urls: &[String]) -> Result<ExitStatus, WgetError> {
        // Create a new progress display for recursive retriever
        let is_interactive = io::stdout().is_terminal();
        let progress = if !self.config.quiet {
            let style = self.config.progress.style;
            let force_noscroll = !is_interactive;
            ut_progress::create_progress_display(style, force_noscroll)
        } else {
            ut_progress::create_progress_display(ut_core::ProgressStyle::Silent, true)
        };

        let mut recursive_retriever = RecursiveRetriever::new(self.config.clone(), progress);

        let mut overall_status = ExitStatus::Success;

        for start_url in urls {
            let parsed = match ParsedUrl::parse(start_url) {
                Ok(p) => p,
                Err(e) => {
                    if self.config.verbose >= 1 || self.config.debug {
                        eprintln!("utwget: {}", e);
                    }
                    continue;
                }
            };

            if self.config.verbose >= 1 {
                eprintln!("Starting recursive download from: {}", parsed.display());
            }

            match recursive_retriever.retrieve_tree(&parsed.display_with_credentials()) {
                Ok(ut_retriever::ExitStatus::Success) => {
                    if self.config.verbose >= 1 {
                        eprintln!("Recursive download completed successfully");
                    }
                }
                Ok(ut_retriever::ExitStatus::NoUrlsFound) => {
                    if self.config.verbose >= 1 {
                        eprintln!("No URLs found to download");
                    }
                    overall_status = ExitStatus::Error;
                }
                Ok(ut_retriever::ExitStatus::Error) => {
                    overall_status = ExitStatus::Error;
                }
                Err(e) => {
                    if self.config.verbose >= 1 || self.config.debug {
                        eprintln!("utwget: error during recursive download: {}", e);
                    }
                    overall_status = ExitStatus::Error;
                }
            }
        }

        // Perform link conversion if requested
        if self.config.convert_links {
            self.convert_downloaded_links(&recursive_retriever);
        }

        // Persist cookies and HSTS collected during the recursive crawl.
        recursive_retriever.retriever_mut().save_state();

        self.print_summary();

        Ok(overall_status)
    }

    /// Run recursive download with parallel workers.
    ///
    /// Uses `RecursiveRetriever::retrieve_tree_parallel` with N worker threads.
    /// Each worker has its own `Retriever` instance but shares the TLS connection
    /// pool and `UrlQueue` via `Arc<Mutex<>>`.
    fn run_recursive_parallel(&mut self, urls: &[String], num_workers: usize) -> Result<ExitStatus, WgetError> {
        let is_interactive = io::stdout().is_terminal();
        let progress = if !self.config.quiet {
            let style = self.config.progress.style;
            let force_noscroll = !is_interactive;
            ut_progress::create_progress_display(style, force_noscroll)
        } else {
            ut_progress::create_progress_display(ut_core::ProgressStyle::Silent, true)
        };

        let mut recursive_retriever = RecursiveRetriever::new(self.config.clone(), progress);
        let mut overall_status = ExitStatus::Success;

        for start_url in urls {
            let parsed = match ParsedUrl::parse(start_url) {
                Ok(p) => p,
                Err(e) => {
                    if self.config.verbose >= 1 || self.config.debug {
                        eprintln!("utwget: {}", e);
                    }
                    continue;
                }
            };

            if self.config.verbose >= 1 {
                eprintln!("Starting parallel recursive download ({} workers) from: {}",
                    num_workers, parsed.display());
            }

            match recursive_retriever.retrieve_tree_parallel(
                &parsed.display_with_credentials(), num_workers,
            ) {
                Ok(ut_retriever::ExitStatus::Success) => {
                    if self.config.verbose >= 1 {
                        eprintln!("Parallel recursive download completed successfully");
                    }
                }
                Ok(ut_retriever::ExitStatus::NoUrlsFound) => {
                    if self.config.verbose >= 1 {
                        eprintln!("No URLs found to download");
                    }
                    overall_status = ExitStatus::Error;
                }
                Ok(ut_retriever::ExitStatus::Error) => {
                    overall_status = ExitStatus::Error;
                }
                Err(e) => {
                    if self.config.verbose >= 1 || self.config.debug {
                        eprintln!("utwget: error during parallel recursive download: {}", e);
                    }
                    overall_status = ExitStatus::Error;
                }
            }
        }

        // Perform link conversion if requested
        if self.config.convert_links {
            self.convert_downloaded_links(&recursive_retriever);
        }

        // Persist cookies and HSTS collected during the recursive crawl.
        recursive_retriever.retriever_mut().save_state();

        self.print_summary();

        Ok(overall_status)
    }


    /// Iterates over every URL-to-local-path mapping collected during the
    /// recursive crawl and rewrites HTML links so they point to local files
    /// instead of remote URLs. If `--backup-converted` was requested, the
    /// original file is backed up before modification.
    ///
    /// # Arguments
    /// * `recursive_retriever` — The retriever that finished crawling, which
    ///   holds the download registry with all URL-to-path mappings.
    fn convert_downloaded_links(&self, recursive_retriever: &RecursiveRetriever) {
        let registry = recursive_retriever.retriever().download_registry();
        let url_to_local: HashMap<String, String> = registry.get_all_mappings();

        if url_to_local.is_empty() {
            if self.config.verbose >= 1 {
                eprintln!("No files to convert links in");
            }
            return;
        }

        // Build a reverse map (local_path → url) so we can pass each
        // document's URL to the converter for relative-link resolution.
        let local_to_url: HashMap<&String, &String> = url_to_local
            .iter()
            .map(|(u, p)| (p, u))
            .collect();

        let converter = LinkConverter::new();
        let opts = ConvertOptions {
            convert_to_relative: true,
            convert_file_only: false,
            nullify_base: true,
            backup_converted: self.config.backup_converted,
        };

        let mut converted_count = 0;
        let mut failed_count = 0;

        for local_path in url_to_local.values() {
            // Only process HTML and CSS files — skip binary files (images,
            // PDFs, archives, etc.) to avoid corruption. GNU wget only
            // converts files in downloaded_html_set and downloaded_css_set
            // (convert.c:197-198).
            let path = std::path::Path::new(local_path);
            let is_html = path.extension()
                .map(|e| {
                    let ext = e.to_string_lossy().to_ascii_lowercase();
                    ext == "html" || ext == "htm" || ext == "xhtml" || ext == "shtml"
                })
                .unwrap_or(false);
            let is_css = path.extension()
                .map(|e| e.to_string_lossy().eq_ignore_ascii_case("css"))
                .unwrap_or(false);

            if !is_html && !is_css {
                continue;
            }

            if self.config.debug {
                eprintln!("Converting links in: {}", local_path);
            }

            if is_css {
                // CSS conversion: replace url() references with local paths.
                match Self::convert_css_links(local_path, &url_to_local, &opts) {
                    Ok(n) => {
                        converted_count += n;
                        if self.config.verbose >= 1 {
                            eprintln!("Converted {} links in {}", n, local_path);
                        }
                    }
                    Err(e) => {
                        failed_count += 1;
                        if self.config.verbose >= 1 || self.config.debug {
                            eprintln!("utwget: warning: failed to convert CSS links in {}: {}", local_path, e);
                        }
                    }
                }
            } else {
                let doc_url = local_to_url.get(local_path).map(|s| s.as_str());
                match converter.convert_links_with_base(local_path, &url_to_local, &opts, doc_url) {
                    Ok(stats) => {
                        converted_count += stats.converted;
                        if self.config.verbose >= 1 {
                            eprintln!("Converted {} links in {}", stats.converted, local_path);
                        }
                    }
                    Err(e) => {
                        failed_count += 1;
                        if self.config.verbose >= 1 || self.config.debug {
                            eprintln!("utwget: warning: failed to convert links in {}: {}", local_path, e);
                        }
                    }
                }
            }
        }

        if self.config.verbose >= 1 {
            eprintln!("Link conversion complete: {} links converted, {} files failed",
                converted_count, failed_count);
        }
    }

    /// Convert CSS `url()` references to local paths.
    ///
    /// Performs simple string replacement of `url("remote_url")` and
    /// `url(remote_url)` patterns with `url("local_path")` for any
    /// remote URL found in `url_to_local`. This mirrors GNU wget's
    /// CSS link conversion (convert.c:616-622).
    fn convert_css_links(
        file_path: &str,
        url_to_local: &HashMap<String, String>,
        opts: &ut_html::ConvertOptions,
    ) -> Result<usize, std::io::Error> {
        let path = std::path::Path::new(file_path);
        let content = std::fs::read_to_string(path)?;

        if opts.backup_converted {
            let backup_ext = path
                .extension()
                .map(|e| format!("{}.orig", e.to_string_lossy()))
                .unwrap_or_else(|| "orig".to_string());
            let backup_path = path.with_extension(&backup_ext);
            let _ = std::fs::copy(path, &backup_path);
        }

        let mut count = 0usize;
        let mut output = content.clone();

        for (remote_url, local_path) in url_to_local {
            // Skip URLs that are already local
            if remote_url.starts_with('#') || remote_url.starts_with("data:") {
                continue;
            }
            // Replace url("remote") and url(remote) forms
            let quoted = format!("url(\"{}\")", remote_url);
            let replacement = format!("url(\"{}\")", local_path);
            if output.contains(&quoted) {
                output = output.replace(&quoted, &replacement);
                count += 1;
            }
            let bare = format!("url({})", remote_url);
            if output.contains(&bare) {
                output = output.replace(&bare, &replacement);
                count += 1;
            }
        }

        if count > 0 {
            std::fs::write(path, output)?;
        }

        Ok(count)
    }

    /// Run in Metalink mode.
    ///
    /// Processes the provided URLs as Metalink resources. Supports:
    /// * Reading a local `.metalink` or `.meta4` file via `--input-metalink`.
    /// * Downloading a Metalink resource over HTTP when `--metalink-over-http`
    ///   is set and the response indicates a Metalink document.
    /// * Treating each URL directly as a Metalink file.
    ///
    /// This method is only compiled when the `metalink` feature is enabled.
    ///
    /// # Arguments
    /// * `urls` — The slice of URL strings to process.
    ///
    /// # Returns
    /// The combined `ExitStatus` for all Metalink files processed.
    #[cfg(feature = "metalink")]
    fn run_metalink(&mut self, urls: &[String]) -> Result<ExitStatus, WgetError> {
        let output_dir = self.config.dir_prefix.clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        // Handle input metalink file
        let input_file = self.config.metalink.input_file.clone();
        if let Some(ref metalink_file) = input_file {
            return self.process_metalink_file(metalink_file, &output_dir);
        }

        // Handle metalink-over-http
        let over_http = self.config.metalink.over_http;
        if over_http {
            for url_str in urls {
                // Download and check for Metalink headers
                let parsed = ParsedUrl::parse(url_str)
                    .map_err(|e| WgetError::UrlParse(format!("{}", e)))?;

                match self.retriever.retrieve(&parsed.display_with_credentials()) {
                    Ok(RetrieveOutcome::Success(body_result)) => {
                        if let Some(ref local_file) = body_result.local_file {
                            // Check if response indicates Metalink
                            // For now, check file extension or content-type
                            let ext = local_file.extension()
                                .and_then(|e| e.to_str())
                                .map(|e| e.to_lowercase());

                            if ext.as_deref() == Some("metalink") || ext.as_deref() == Some("meta4") {
                                return self.process_metalink_file(local_file, &output_dir);
                            }
                        }
                    }
                    Err(e) => {
                        if self.config.verbose >= 1 {
                            eprintln!("utwget: error downloading {}: {}", url_str, e);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Process URLs as Metalink files directly
        for url_str in urls {
            let parsed = ParsedUrl::parse(url_str)
                .map_err(|e| WgetError::UrlParse(format!("{}", e)))?;

            match self.retriever.retrieve(&parsed.display_with_credentials()) {
                Ok(RetrieveOutcome::Success(body_result)) => {
                    if let Some(ref local_file) = body_result.local_file {
                        return self.process_metalink_file(local_file, &output_dir);
                    }
                }
                Err(e) => {
                    if self.config.verbose >= 1 {
                        eprintln!("utwget: error downloading metalink: {}", e);
                    }
                    return Ok(ExitStatus::Error);
                }
                _ => {}
            }
        }

        Ok(ExitStatus::Success)
    }

    /// Parse and process a local Metalink file.
    ///
    /// Opens the file at `metalink_path`, parses its Metalink XML content,
    /// and downloads each referenced file using a `MetalinkDownloader`.
    ///
    /// This method is only compiled when the `metalink` feature is enabled.
    ///
    /// # Arguments
    /// * `metalink_path` — Path to the local `.metalink` or `.meta4` file.
    /// * `output_dir` — Directory into which downloaded files are placed.
    ///
    /// # Returns
    /// * `ExitStatus::Success` if all files were downloaded.
    /// * `ExitStatus::Error` if any file failed.
    #[cfg(feature = "metalink")]
    fn process_metalink_file(
        &mut self,
        metalink_path: &std::path::Path,
        output_dir: &std::path::Path,
    ) -> Result<ExitStatus, WgetError> {
        use ut_metalink::MetalinkError;

        if self.config.verbose >= 1 {
            eprintln!("Processing Metalink file: {}", metalink_path.display());
        }

        let file = fs::File::open(metalink_path)
            .map_err(|e| WgetError::MetalinkParse(format!("cannot open metalink file: {}", e)))?;
        let reader = std::io::BufReader::new(file);

        let metalink_files = MetalinkParser::parse(reader)
            .map_err(|e| WgetError::MetalinkParse(format!("parse error: {}", e)))?;

        if self.config.verbose >= 1 {
            eprintln!("Found {} file(s) in Metalink", metalink_files.len());
        }

        // Create a download function that uses our retriever
        let download_fn = |url: &str, path: &std::path::Path| -> Result<(), MetalinkError> {
            // This is a simplified download function
            // In a real implementation, we would use the retriever
            eprintln!("{}", crate::i18n::translate_with_args("utwget.downloading_to", &[
                ("url", url.to_string()),
                ("path", path.display().to_string()),
            ]));
            Ok(())
        };

        let downloader = MetalinkDownloader::new(download_fn);
        let mut overall_status = ExitStatus::Success;

        for metalink_file in &metalink_files {
            if self.config.verbose >= 1 {
                eprintln!("{}", crate::i18n::translate_with_args("utwget.downloading_to", &[
                    ("url", metalink_file.name.clone()),
                    ("path", metalink_file.size.map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string())),
                ]));
            }

            match downloader.download(metalink_file, output_dir) {
                Ok(result) => {
                    self.urls_downloaded += 1;
                    if self.config.verbose >= 1 {
                        eprintln!("{}", crate::i18n::translate_with_args("utwget.downloaded_info", &[
                            ("url", result.file_path.display().to_string()),
                            ("size", result.bytes_downloaded.to_string()),
                            ("checksum", if result.checksum_verified { "已验证".to_string() } else { "未验证".to_string() }),
                        ]));
                    }
                }
                Err(e) => {
                    if self.config.verbose >= 1 {
                        eprintln!("{}", crate::i18n::translate_with_args("utwget.error_downloading", &[
                            ("url", metalink_file.name.clone()),
                            ("error", e.to_string()),
                        ]));
                    }
                    overall_status = ExitStatus::Error;
                }
            }
        }

        self.print_summary();
        Ok(overall_status)
    }

    /// Expand a URL template or shorthand into its full form.
    ///
    /// Currently this is a pass-through; it returns the URL string unchanged.
    /// In the future it may support brace expansion or prefix defaults.
    ///
    /// # Arguments
    /// * `url` — The raw URL string as provided by the user.
    ///
    /// # Returns
    /// The expanded (or unchanged) URL string.
    fn expand_url(&self, url: &str) -> String {
        url.to_string()
    }

    /// Parse a local HTML file and extract all linked URLs.
    ///
    /// Used when `--force-html` is active and one of the "URLs" is actually
    /// a path to a local HTML file.
    ///
    /// # Arguments
    /// * `path` — Path to the local HTML file.
    ///
    /// # Returns
    /// A vector of URL strings extracted from the HTML content.
    ///
    /// # Errors
    /// Returns `WgetError::FileNotFound` if the file does not exist, or
    /// `WgetError::Other` if HTML parsing fails.
    fn read_html_file_urls(&self, path: &Path) -> Result<Vec<String>, WgetError> {
        let content = fs::read_to_string(path).map_err(|_| WgetError::FileNotFound(path.to_path_buf()))?;
        let extractor = ut_html::HtmlExtractor;
        let opts = ut_html::url_position::ExtractOptions::default();
        let mut cursor = Cursor::new(content.as_bytes());
        let links = ut_html::ContentExtractor::extract_urls(&extractor, &mut cursor, "", &opts)
            .map_err(|e| WgetError::ProtocolIo(format!("HTML parse error: {}", e)))?;
        Ok(links.into_iter().map(|l| l.url).collect())
    }

    /// Print the final download summary to stderr.
    ///
    /// The summary includes total bytes downloaded, number of files, and the
    /// elapsed wall-clock time. This is a no-op when `--quiet` is active or
    /// when verbose mode is not enabled.
    fn print_summary(&self) {
        if self.config.quiet {
            return;
        }

        let elapsed = self.start_time.elapsed();
        let total = self.retriever.total_downloaded();

        if self.config.verbose >= 1 {
            eprintln!("{}", crate::i18n::translate("utwget.progress_finished"));
            eprintln!("{}", crate::i18n::translate_with_args("utwget.progress_downloaded", &[
                ("bytes", ut_progress::format_size(total)),
                ("files", self.urls_downloaded.to_string()),
            ]));
            eprintln!("{}", crate::i18n::translate_with_args("utwget.progress_time", &[
                ("duration", ut_progress::format_duration(elapsed)),
            ]));
        }
    }

    /// Persist session state (cookies, HSTS) to disk.
    ///
    /// Should be called after all downloads complete, regardless of success
    /// or failure, so that accumulated cookies and HSTS entries are not lost.
    pub fn save_state(&mut self) {
        self.retriever.save_state();
    }
}

/// Build a fully-resolved `ut_core::Config` from the parsed command-line arguments.
///
/// Maps every CLI flag, option, and sub-option to the corresponding field on the
/// configuration object. This includes HTTP, FTP, TLS, proxy, recursive, WARC,
/// Metalink, progress, and miscellaneous settings.
///
/// # Arguments
/// Safely converts an f64 seconds value to Duration.
/// Returns None for negative, NaN, or infinite values instead of panicking.
fn safe_duration_f64(secs: f64) -> Option<Duration> {
    if secs.is_finite() && secs >= 0.0 {
        Some(Duration::from_secs_f64(secs))
    } else {
        eprintln!("warning: ignoring invalid duration value: {}", secs);
        None
    }
}

/// Parse a WARC max-size value with wget-compatible suffixes.
///
/// Accepts plain byte counts and values with K/M/G/T suffixes (e.g.
/// "100K", "2.5G"). The special value "inf" means unlimited, which
/// wget represents as 0.
fn parse_warc_maxsize(s: &str) -> Option<u64> {
    if s.trim().eq_ignore_ascii_case("inf") {
        return Some(0);
    }
    ut_core::utils::parse_size_string(s)
}

/// * `args` — The parsed command-line arguments.
///
/// # Returns
/// A `ut_core::Config` populated with all user-specified options and defaults.
///
/// Used by integration tests in `tests/integration_tests/`; the library
/// itself builds configs via `main.rs`, so this is allowed-dead externally.
#[allow(dead_code)]
pub fn build_config(args: &Args) -> ut_core::Config {
    let mut config = ut_core::Config::default();
    apply_args(&mut config, args);
    config
}

/// Apply command-line arguments to an existing configuration.
///
/// This function overrides config values with command-line arguments.
/// It should be called AFTER loading wgetrc files, so that command-line
/// arguments take precedence over wgetrc settings.
pub fn apply_args(config: &mut ut_core::Config, args: &Args) {
    if args.quiet {
        config.quiet = true;
        config.verbose = 0;
    } else if args.verbose {
        config.verbose = 1;
    } else if args.no_verbose {
        config.verbose = 0;
    }

    // GNU wget main.c:1630-1631: if verbose is still the sentinel -1
    // (neither --verbose nor --quiet nor --no-verbose was given on the
    // CLI, and wgetrc didn't set it), resolve to !quiet (default verbose).
    if config.verbose == -1 {
        config.verbose = if config.quiet { 0 } else { 1 };
    }

    // Only override wgetrc when the CLI flag is explicitly true.
    // For clap bool fields with ArgAction::SetTrue (default), false means
    // the flag was not given → preserve wgetrc value. --no-FOO flags
    // are handled separately below.
    if args.debug { config.debug = true; }
    if args.server_response { config.server_response = true; }
    if args.background { config.background = true; }
    // Only override wgetrc values when the CLI explicitly provides a value;
    // otherwise preserve the value loaded from wgetrc (GNU wget init.c
    // semantics: command-line overrides wgetrc, but absent CLI flags leave
    // wgetrc intact). For Option<T> fields, args.* is None when the flag
    // was not given, so we use .or() to keep the existing config value.
    if args.output_file.is_some() {
        config.output_file = args.output_file.clone();
    }
    if args.append_output.is_some() {
        config.append_output = args.append_output.clone();
    }
    config.tries = args.tries;
    config.retry_connrefused = args.retry_connrefused;
    config.retry_on_host_error = args.retry_on_host_error;
    config.retry_on_http_error = args.retry_on_http_error.clone();

    if args.output_document.is_some() {
        config.output_document = args.output_document.clone();
    }
    if args.input_file.is_some() {
        config.input_filename = args.input_file.clone();
    }
    if args.force_html { config.force_html = true; }
    if args.directory_prefix.is_some() {
        config.dir_prefix = args.directory_prefix.clone();
    }
    if args.no_clobber { config.noclobber = true; }
    if args.unlink { config.unlink = true; }
    if args.backups.is_some() {
        config.backups = args.backups;
    }
    if args.continue_download { config.continue_download = true; }
    if args.start_pos.is_some() {
        config.start_position = args.start_pos;
    }
    if args.timestamping { config.timestamping = true; }

    if args.no_if_modified_since {
        config.if_modified_since = false;
    }
    if args.no_use_server_timestamps {
        config.use_server_timestamps = false;
    }

    if let Some(s) = &args.quota {
        config.quota = ut_core::utils::parse_size_string(s);
    }
    if let Some(s) = &args.limit_rate {
        config.limit_rate = ut_core::utils::parse_size_string(s);
    }

    if let Some(d) = args.wait {
        config.wait = safe_duration_f64(d);
    }
    if let Some(d) = args.wait_retry {
        config.wait_retry = safe_duration_f64(d);
    }
    if args.random_wait { config.random_wait = true; }
    if args.delete_after { config.delete_after = true; }
    if args.content_disposition { config.content_disposition = true; }
    if args.auth_no_challenge { config.auth_without_challenge = true; }
    config.concurrent_downloads = args.concurrency;

    if args.no_netrc {
        config.use_netrc = false;
    }

    config.http.user = args.http_user.clone().or(args.user.clone()).or(config.http.user.take());
    config.http.password = args.http_password.clone().or(args.password.clone()).or(config.http.password.take());

    // Handle --ask-password: prompt for password interactively
    if args.ask_password && config.http.password.is_none() {
        if let Some(ref user) = config.http.user {
            config.http.password = prompt_password(&format!("Password for {}: ", user));
        } else {
            config.http.password = prompt_password("Password: ");
        }
    }

    // Handle --use-askpass: use an external program to obtain the password.
    // The askpass facility is only engaged when the user passes --use-askpass
    // (optionally with an explicit command). GNU wget does NOT consult the
    // WGET_ASKPASS/SSH_ASKPASS environment variables unless --use-askpass is
    // given, so we gate the whole path on the flag's presence.
    if config.http.password.is_none() && args.use_askpass.is_some() {
        if let Some(program) = resolve_askpass(args.use_askpass.as_deref()) {
            let prompt = match config.http.user {
                Some(ref user) => format!("Password for {}: ", user),
                None => "Password: ".to_string(),
            };
            config.http.password = run_askpass(&program, &prompt);
        }
    }

    // Only override wgetrc-loaded headers when the CLI explicitly passes
    // --header; otherwise keep the headers configured via wgetrc.
    if !args.header.is_empty() {
        config.http.headers = args.header.clone();
    }
    // Only override user_agent/referer when the CLI flag is present.
    if args.user_agent.is_some() {
        config.http.user_agent = args.user_agent.clone();
    }
    if args.referer.is_some() {
        config.http.referer = args.referer.clone();
    }
    config.http.save_headers = args.save_headers;

    // IRI configuration
    if args.no_iri {
        config.iri.enabled = false;
    }
    if let Some(ref enc) = args.local_encoding {
        config.iri.locale = Some(enc.clone());
    }
    if let Some(ref enc) = args.remote_encoding {
        config.iri.remote_encoding = Some(enc.clone());
    }

    config.http.save_headers = args.save_headers;
    config.http.content_on_error = args.content_on_error;
    config.http.https_only = args.https_only;
    config.http.force_http2 = args.http2;
    config.http.force_http1_1 = args.http1_1;

    if args.no_http_keep_alive || args.http_keep_alive {
        if args.no_http_keep_alive { config.http.keep_alive = false; }
        if args.http_keep_alive { config.http.keep_alive = true; }
    }

    // --no-cache: send Cache-Control: no-cache + Pragma: no-cache
    if args.no_cache {
        config.http.no_cache = true;
    }

    if let Some(ref method) = args.method {
        if let Ok(m) = method.parse() {
            config.http.method = Some(m);
        }
    }

    // --post-data / --post-file and --body-data / --body-file validation
    // and auto-method-setting, mirroring GNU wget main.c:1833-1893.
    //
    // post_data/post_file are mutually exclusive with each other and with
    // --method. They auto-set method=POST and feed the body.
    // body_data/body_file are mutually exclusive with each other and require
    // --method to be set explicitly.
    let has_post = args.post_data.is_some() || args.post_file.is_some();
    let has_body = args.body_data.is_some() || args.body_file.is_some();

    if has_post {
        if args.post_data.is_some() && args.post_file.is_some() {
            eprintln!("utwget: 不能同时指定 --post-data 和 --post-file");
            std::process::exit(2);
        }
        if config.http.method.is_some() {
            eprintln!(
                "utwget: 不能同时使用 --post-data/--post-file 和 --method。\
                 --method 通过 --body-data 和 --body-file 选项发送数据"
            );
            std::process::exit(2);
        }
        // Auto-set method=POST (main.c:1879)
        config.http.method = Some(ut_core::types::HttpMethod::Post);
    }

    if has_body {
        if config.http.method.is_none() {
            eprintln!(
                "utwget: 必须通过 --method=HTTP方法 指定方法才能使用 --body-data 或 --body-file"
            );
            std::process::exit(2);
        }
        if args.body_data.is_some() && args.body_file.is_some() {
            eprintln!("utwget: 不能同时指定 --body-data 和 --body-file");
            std::process::exit(2);
        }
    }

    if let Some(ref post_data) = args.post_data {
        config.http.post_data = Some(post_data.as_bytes().to_vec());
    }
    if let Some(ref post_file) = args.post_file {
        config.http.post_file = Some(post_file.clone());
    }
    if let Some(ref body_data) = args.body_data {
        config.http.body_data = Some(body_data.as_bytes().to_vec());
    }
    if let Some(ref body_file) = args.body_file {
        config.http.body_file = Some(body_file.clone());
    }

    if let Some(ref page) = args.default_page {
        config.http.default_page = page.clone();
    }

    config.ftp.user = args.ftp_user.clone().or(args.user.clone()).or(config.ftp.user.take());
    config.ftp.password = args.ftp_password.clone().or(args.password.clone()).or(config.ftp.password.take());

    if args.no_passive_ftp {
        config.ftp.passive = false;
    }
    if args.no_glob {
        config.ftp.glob = false;
    }
    if args.retr_symlinks {
        config.ftp.retrieve_symlinks = true;
    }
    if args.no_remove_listing {
        config.ftp.remove_listing = false;
    }
    if args.follow_ftp {
        config.ftp.follow_ftp = true;
    }

    // FTPS options
    config.ftp.ftps_implicit = args.ftps_implicit;
    config.ftp.ftps_resume_ssl = args.ftps_resume_ssl;
    config.ftp.ftps_clear_data = args.ftps_clear_data_connection;
    config.ftp.ftps_fallback = args.ftps_fallback_to_ftp;

    if args.no_check_certificate {
        config.tls.check_certificate = ut_core::CheckCertMode::Off;
        // 代码审查 P1 #2.4：在 CLI 设置点也加 stderr warning（log::warn! 在 -q 模式下被静音，
        // 但 --no-check-certificate 是用户应该始终意识到后果的安全开关）
        eprintln!("utwget: WARNING: TLS certificate verification disabled (--no-check-certificate). \
                   The connection will be vulnerable to man-in-the-middle attacks.");
    }
    if args.certificate.is_some() {
        config.tls.cert_file = args.certificate.clone();
    }
    if args.private_key.is_some() {
        config.tls.private_key = args.private_key.clone();
    }
    if args.ca_certificate.is_some() {
        config.tls.ca_cert = args.ca_certificate.clone();
    }
    if args.ca_directory.is_some() {
        config.tls.ca_directory = args.ca_directory.clone();
    }
    if args.crl_file.is_some() {
        config.tls.crl_file = args.crl_file.clone();
    }
    if args.pinnedpubkey.is_some() {
        config.tls.pinned_pubkey = args.pinnedpubkey.clone();
    }
    if args.ciphers.is_some() {
        config.tls.ciphers = args.ciphers.clone();
    }

    // Apply certificate/private-key type options
    if let Some(ref ct) = args.certificate_type {
        config.tls.cert_type = match ct.to_ascii_lowercase().as_str() {
            "pem" => ut_core::types::KeyFileType::Pem,
            "asn1" => ut_core::types::KeyFileType::Asn1,
            "der" => ut_core::types::KeyFileType::Der,
            _ => ut_core::types::KeyFileType::Pem,
        };
    }
    if let Some(ref pt) = args.private_key_type {
        config.tls.private_key_type = match pt.to_ascii_lowercase().as_str() {
            "pem" => ut_core::types::KeyFileType::Pem,
            "asn1" => ut_core::types::KeyFileType::Asn1,
            "der" => ut_core::types::KeyFileType::Der,
            _ => ut_core::types::KeyFileType::Pem,
        };
    }

    if let Some(ref sp) = args.secure_protocol {
        if let Ok(p) = parse_secure_protocol_arg(sp) {
            config.tls.secure_protocol = p;
        }
    }

    if args.recursive { config.recursive.enabled = true; }
    // -l 0 means unlimited depth (like original wget), so set to None
    if args.level != 1 {  // clap default is 1; only override if user set -l
        config.recursive.max_level = if args.level == 0 { None } else { Some(args.level) };
    }
    if args.page_requisites { config.page_requisites = true; }

    // GNU wget (main.c:1620-1626): when -p is given without -r, set
    // reclevel=0 (only download the starting page and its inline
    // requisites).  The recursive flag itself is NOT set (to avoid
    // confusing the FTP code), but retrieve_tree is still called.
    // We handle this by checking page_requisites in the run dispatch.
    if args.page_requisites && !args.recursive {
        config.recursive.max_level = Some(0);
    }

    if args.span_hosts { config.recursive.span_hosts = true; }
    if args.no_parent { config.recursive.no_parent = true; }
    if args.relative { config.recursive.relative_only = true; }
    if args.spider { config.recursive.spider = true; }

    if args.ignore_length { config.ignore_length = true; }
    if args.ignore_case { config.ignore_case = true; }

    if args.xattr { config.xattr = true; }
    if args.preserve_permissions { config.preserve_permissions = true; }

    if let Some(ref tags) = args.follow_tags {
        config.recursive.follow_tags = tags.split(',').map(String::from).collect();
    }
    if let Some(ref tags) = args.ignore_tags {
        config.recursive.ignore_tags = tags.split(',').map(String::from).collect();
    }
    if let Some(ref tags) = args.reject_tags {
        let reject: Vec<String> = tags.split(',').map(String::from).collect();
        config.recursive.ignore_tags.extend(reject);
    }
    if let Some(ref patterns) = args.accept {
        config.recursive.accept_patterns = patterns.split(',').map(String::from).collect();
    }
    if let Some(ref patterns) = args.reject {
        config.recursive.reject_patterns = patterns.split(',').map(String::from).collect();
    }
    if let Some(ref r) = args.accept_regex {
        config.recursive.accept_regex = Some(r.clone());
    }
    if let Some(ref r) = args.reject_regex {
        config.recursive.reject_regex = Some(r.clone());
    }
    if let Some(ref domains) = args.domains {
        config.recursive.domains = domains.split(',').map(String::from).collect();
    }
    if let Some(ref domains) = args.exclude_domains {
        config.recursive.exclude_domains = domains.split(',').map(String::from).collect();
    }
    if let Some(ref dirs) = args.include_directories {
        config.recursive.include_directories = dirs.split(',').map(String::from).collect();
    }
    if let Some(ref dirs) = args.exclude_directories {
        config.recursive.exclude_directories = dirs.split(',').map(String::from).collect();
    }

    if args.use_robots == Some(false) {
        config.recursive.use_robots = false;
    }

    if args.convert_links { config.convert_links = true; }
    if args.convert_file_only { config.convert_file_only = true; }
    if args.backup_converted { config.backup_converted = true; }
    if args.adjust_extension { config.adjust_extension = true; }
    if args.html_extension { config.adjust_extension = true; }

    if args.mirror {
        // --mirror is equivalent to -N -r -l inf --no-remove-listing in GNU wget
        // (see init.c: cmd_spec_mirror). Do NOT add -k, -p, -c, or change
        // use_robots here — those are independent options in GNU wget.
        config.recursive.enabled = true;
        config.timestamping = true;
        config.recursive.max_level = None; // Infinite recursion (-l inf)
        config.ftp.remove_listing = false; // --no-remove-listing
    }

    config.max_redirect = args.max_redirect;

    if let Some(s) = args.timeout {
        config.timeout = safe_duration_f64(s);
    }
    if let Some(s) = args.connect_timeout {
        config.connect_timeout = safe_duration_f64(s);
    }
    if let Some(s) = args.read_timeout {
        config.read_timeout = safe_duration_f64(s);
    }
    if let Some(s) = args.dns_timeout {
        config.dns_timeout = safe_duration_f64(s);
    }
    if args.no_dns_cache { config.no_dns_cache = true; }

    config.cookie.enabled = !args.no_cookies;
    if args.load_cookies.is_some() {
        config.cookie.input_file = args.load_cookies.clone();
    }
    if args.save_cookies.is_some() {
        config.cookie.output_file = args.save_cookies.clone();
    }
    config.cookie.keep_session_cookies = args.keep_session_cookies;

    #[cfg(feature = "hsts")]
    {
        config.hsts.enabled = !args.no_hsts;
        if args.hsts_file.is_some() {
            config.hsts.file = args.hsts_file.clone();
        }
    }

    if args.use_proxy == Some(false) || args.no_proxy {
        config.proxy.use_proxy = false;
    }
    // Precedence (GNU wget semantics): CLI flag > wgetrc value > environment
    // variable. The wgetrc loader may have set proxy_* from the `http_proxy`
    // / `https_proxy` / `ftp_proxy` wgetrc commands; we preserve that value
    // when neither a CLI flag nor an environment variable is present.
    config.proxy.http_proxy = args.http_proxy.clone()
        .or(config.proxy.http_proxy.take())
        .or_else(|| std::env::var("http_proxy").ok())
        .or_else(|| std::env::var("HTTP_PROXY").ok());
    config.proxy.https_proxy = args.https_proxy.clone()
        .or(config.proxy.https_proxy.take())
        .or_else(|| std::env::var("https_proxy").ok())
        .or_else(|| std::env::var("HTTPS_PROXY").ok());
    config.proxy.ftp_proxy = args.ftp_proxy.clone()
        .or(config.proxy.ftp_proxy.take())
        .or_else(|| std::env::var("ftp_proxy").ok())
        .or_else(|| std::env::var("FTP_PROXY").ok());
    if args.proxy_user.is_some() {
        config.proxy.proxy_user = args.proxy_user.clone();
    }
    if args.proxy_password.is_some() {
        config.proxy.proxy_password = args.proxy_password.clone();
    }

    // Read the no_proxy environment variable (comma-separated list of hosts
    // to bypass proxy), matching GNU wget init.c:416-418.
    if config.proxy.no_proxy.is_empty() {
        if let Ok(np) = std::env::var("no_proxy") {
            if !np.is_empty() && np != "*" {
                config.proxy.no_proxy = np
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
    }

    if args.no_host_directories { config.no_host_directories = true; }
    if args.protocol_directories { config.protocol_directories = true; }
    if args.no_directories { config.no_directories = true; }
    if args.force_directories { config.force_directories = true; }
    if let Some(c) = args.cut_dirs {
        config.cut_dirs = c;
    }

    if args.bind_address.is_some() {
        config.bind_address = args.bind_address.clone();
    }
    if args.inet4_only { config.force_ipv4 = true; }
    if args.inet6_only { config.force_ipv6 = true; }

    // Handle compression options
    #[cfg(feature = "compression")]
    {
        if args.no_compression {
            config.compression = ut_core::types::CompressionMode::None;
        } else if let Some(ref mode) = args.compression {
            config.compression = match mode.to_ascii_lowercase().as_str() {
                "auto" => ut_core::types::CompressionMode::Auto,
                "gzip" => ut_core::types::CompressionMode::Gzip,
                "none" => ut_core::types::CompressionMode::None,
                _ => {
                    eprintln!("utwget: unrecognized compression type '{}'", mode);
                    std::process::exit(2);
                }
            };
        }
    }

    if let Some(ref family) = args.prefer_family {
        config.prefer_family = parse_address_family_arg(family);
    }

    // WARC configuration
    if args.warc_file.is_some() || args.warc_cdx || args.warc_dedup || args.warc_compression || args.warc_digests {
        config.warc.enabled = true;
        if args.warc_file.is_some() {
            config.warc.filename = args.warc_file.clone();
        }
        if args.warc_maxsize.is_some() {
            config.warc.max_size = args.warc_maxsize.as_deref().map(parse_warc_maxsize).flatten();
        }
        config.warc.cdx = args.warc_cdx;
        config.warc.keep_log = args.warc_keep_log;
        config.warc.compression = args.warc_compression;
        config.warc.digests = args.warc_digests;
        if args.warc_temp_dir.is_some() {
            config.warc.tempdir = args.warc_temp_dir.clone();
        }
        if !args.warc_header.is_empty() {
            config.warc.user_headers = args.warc_header.clone();
        }
        // warc_dedup enables CDX dedup
        if args.warc_dedup {
            config.warc.cdx = true;
        }
    }
    // WARC negation options
    if args.no_warc_compression {
        config.warc.compression = false;
    }
    if args.no_warc_digests {
        config.warc.digests = false;
    }
    if args.no_warc_keep_log {
        config.warc.keep_log = false;
    }

    // Metalink configuration
    if args.metalink || args.metalink_over_http || args.input_metalink.is_some() {
        config.metalink.enabled = true;
        config.metalink.over_http = args.metalink_over_http;
        if args.input_metalink.is_some() {
            config.metalink.input_file = args.input_metalink.clone();
        }
    }

    config.progress.style = parse_progress_style_arg(&args.progress);
    config.progress.force_noscroll = !args.show_progress || !io::stdout().is_terminal();

    // Apply --restrict-file-names (comma-separated list of restrictions)
    if let Some(ref rfn) = args.restrict_file_names {
        for part in rfn.split(',') {
            let part = part.trim();
            match part.to_ascii_lowercase().as_str() {
                "unix" => config.filename_restrictions.restrict_os = ut_core::types::RestrictOs::Unix,
                "windows" => config.filename_restrictions.restrict_os = ut_core::types::RestrictOs::Windows,
                "lowercase" => config.filename_restrictions.case_restriction = ut_core::types::CaseRestriction::Lowercase,
                "uppercase" => config.filename_restrictions.case_restriction = ut_core::types::CaseRestriction::Uppercase,
                "nocontrol" => config.filename_restrictions.restrict_ctrl_chars = false,
                "ascii" => config.filename_restrictions.restrict_nonascii = true,
                _ => {
                    eprintln!("utwget: invalid restrict-file-names value '{}'", part);
                    std::process::exit(2);
                }
            }
        }
    }

    // Apply --report-speed
    if let Some(ref rs) = args.report_speed {
        config.report_bps = rs.eq_ignore_ascii_case("bits");
    }

    // Apply --trust-server-names
    if args.trust_server_names { config.trust_server_names = true; }

    // Apply --block-private-redirects (SSRF protection, utwget extension)
    if args.block_private_redirects { config.block_private_redirects = true; }

    if args.reject_log.is_some() {
        config.reject_log = args.reject_log.clone();
    }

    // ---- Handle --no-FOO negation flags (preprocessed from --no-foo) ----
    // GNU wget auto-generates --no-FOO for every boolean option. These hidden
    // flags are produced by rearrange_args and set the corresponding config
    // field to false, overriding both the default and any wgetrc value.
    // Field paths must match the struct hierarchy in core/src/config.rs.
    if args._no_recursive { config.recursive.enabled = false; }
    if args._no_quiet { config.quiet = false; config.verbose = 1; }
    if args._no_debug { config.debug = false; }
    if args._no_background { config.background = false; }
    if args._no_timestamping { config.timestamping = false; }
    if args._no_continue { config.continue_download = false; }
    if args._no_page_requisites { config.page_requisites = false; }
    if args._no_convert_links { config.convert_links = false; }
    if args._no_backup_converted { config.backup_converted = false; }
    if args._no_convert_file_only { config.convert_file_only = false; }
    if args._no_delete_after { config.delete_after = false; }
    if args._no_content_disposition { config.content_disposition = false; }
    if args._no_auth_no_challenge { config.auth_without_challenge = false; }
    if args._no_content_on_error { config.http.content_on_error = false; }
    if args._no_save_headers { config.http.save_headers = false; }
    if args._no_https_only { config.http.https_only = false; }
    if args._no_span_hosts { config.recursive.span_hosts = false; }
    if args._no_relative { config.recursive.relative_only = false; }
    if args._no_protocol_directories { config.protocol_directories = false; }
    if args._no_force_directories { config.force_directories = false; }
    if args._no_retr_symlinks { config.ftp.retrieve_symlinks = false; }
    if args._no_retry_connrefused { config.retry_connrefused = false; }
    if args._no_retry_on_host_error { config.retry_on_host_error = false; }
    if args._no_spider { config.recursive.spider = false; }
    // strict_comments is a CLI-only field, not in Config — skip.
    let _ = args._no_strict_comments;
    if args._no_trust_server_names { config.trust_server_names = false; }
    if args._no_unlink { config.unlink = false; }
    if args._no_xattr { config.xattr = false; }
    if args._no_preserve_permissions { config.preserve_permissions = false; }
    if args._no_backups { config.backups = None; }
    if args._no_follow_ftp { config.ftp.follow_ftp = false; }
    // show_progress maps to progress.force_noscroll logic; skip for now.
    let _ = args._no_show_progress;
    if args._no_keep_session_cookies { config.cookie.keep_session_cookies = false; }
    if args._no_parent { config.recursive.no_parent = false; }
    if args._no_clobber { config.noclobber = false; }
    if args._no_directories { config.no_directories = false; }
    if args._no_host_directories { config.no_host_directories = false; }
    if args._no_remove_listing { config.ftp.remove_listing = true; }
    if args._no_glob { config.ftp.glob = true; }
    if args._no_passive_ftp { config.ftp.passive = false; }
    if args._no_check_certificate { config.tls.check_certificate = ut_core::types::CheckCertMode::On; }
    if args._no_iri { config.iri.enabled = false; }
    if args._no_netrc { config.use_netrc = false; }
    if args._no_cache { config.http.no_cache = true; }
    if args._no_use_server_timestamps { config.use_server_timestamps = true; }
    if args._no_if_modified_since { config.if_modified_since = true; }
    if args._no_cookies { config.cookie.enabled = true; }
    if args._no_hsts { config.hsts.enabled = true; }
    if args._no_dns_cache { config.no_dns_cache = false; }
    if args._no_http_keep_alive { config.http.keep_alive = true; }
    if args._no_compression { config.compression = ut_core::types::CompressionMode::None; }
}

/// Prompt for password interactively from terminal.
///
/// Disables terminal echo on Unix platforms so the password is not displayed
/// as it is typed. Falls back to normal (echoing) input if terminal attributes
/// cannot be changed.
///
/// # Arguments
/// * `prompt` — The prompt string to display (e.g. "Password for user: ").
///
/// # Returns
/// The entered password, or `None` if input could not be read.
fn prompt_password(prompt: &str) -> Option<String> {
    use std::io::Write;

    // Write prompt to stderr
    let _ = std::io::stderr().write_all(prompt.as_bytes());
    let _ = std::io::stderr().flush();

    // Read password from stdin (without echo if possible)
    #[cfg(unix)]
    {
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        // Get current terminal attributes
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut term) } == 0 {
            // Disable echo
            let original_lflag = term.c_lflag;
            term.c_lflag &= !libc::ECHO;
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term) };

            let mut password = String::new();
            let result = std::io::stdin().read_line(&mut password);

            // Re-enable echo
            term.c_lflag = original_lflag;
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term) };

            // Print newline since echo was disabled
            let _ = std::io::stderr().write_all(b"\n");

            if result.is_ok() {
                return Some(password.trim().to_string());
            }
        }
    }

    // Fallback: read normally (echo will be visible)
    let mut password = String::new();
    if std::io::stdin().read_line(&mut password).is_ok() {
        Some(password.trim().to_string())
    } else {
        None
    }
}

/// Run external askpass program to get password.
///
/// Executes the askpass program and captures its stdout as the password.
/// The prompt string is passed as the first argument, matching GNU wget's
/// behavior (`argv[1] = question`).
///
/// # Arguments
/// * `program` — Path or name of the askpass executable.
/// * `prompt` — The prompt/question string passed to the program.
///
/// # Returns
/// The password text returned by the program, or `None` if the program could
/// not be run or returned a non-zero exit code.
fn run_askpass(program: &str, prompt: &str) -> Option<String> {
    use std::process::Command;

    let result = Command::new(program)
        .arg(prompt)
        .output()
        .ok()?;

    if result.status.success() {
        let password = String::from_utf8_lossy(&result.stdout);
        Some(password.trim().to_string())
    } else {
        None
    }
}

/// Resolve the askpass program and prompt string.
///
/// Implements GNU wget's `--use-askpass` resolution order:
/// 1. If `--use-askpass=COMMAND` was given an explicit value, use it.
/// 2. Otherwise, fall back to the `WGET_ASKPASS` environment variable.
/// 3. Then fall back to the `SSH_ASKPASS` environment variable.
///
/// Returns `Some(program)` if a program was resolved, or `None` (after
/// printing an error) if none of the sources yielded a value.
fn resolve_askpass(explicit: Option<&str>) -> Option<String> {
    if let Some(cmd) = explicit {
        if !cmd.is_empty() {
            return Some(cmd.to_string());
        }
    }
    if let Some(cmd) = std::env::var_os("WGET_ASKPASS") {
        if !cmd.is_empty() {
            return cmd.to_string_lossy().into_owned().into();
        }
    }
    if let Some(cmd) = std::env::var_os("SSH_ASKPASS") {
        if !cmd.is_empty() {
            return cmd.to_string_lossy().into_owned().into();
        }
    }
    eprintln!("use-askpass requires a string or either environment variable WGET_ASKPASS or SSH_ASKPASS to be set.");
    None
}

/// Parse a `--secure-protocol` argument string into a `SecureProtocol` value.
///
/// Accepts the following values (case-insensitive):
/// * `"auto"` or `"pfs"` — automatically select the best protocol.
/// * `"tlsv1_2"`, `"tlsv1.2"`, or `"tls1.2"` — TLS 1.2 only.
/// * `"tlsv1_3"`, `"tlsv1.3"`, or `"tls1.3"` — TLS 1.3 only.
///
/// # Arguments
/// * `s` — The protocol string from the command line.
///
/// # Returns
/// `Ok(SecureProtocol)` on a known value, `Err(())` otherwise.
fn parse_secure_protocol_arg(s: &str) -> Result<ut_core::SecureProtocol, ()> {
    match s.to_ascii_lowercase().as_str() {
        "auto" => Ok(ut_core::SecureProtocol::Auto),
        "pfs" => Ok(ut_core::SecureProtocol::Pfs),
        "tlsv1_2" | "tlsv1.2" | "tls1.2" | "tlsv1" | "tlsv1.1" | "tls1.1" => {
            // TLSv1 and TLSv1_1 are mapped to TLSv1_2 (the minimum supported
            // by rustls; TLS 1.0/1.1 are deprecated and unsupported).
            Ok(ut_core::SecureProtocol::TlsV1_2)
        }
        "tlsv1_3" | "tlsv1.3" | "tls1.3" => Ok(ut_core::SecureProtocol::TlsV1_3),
        "sslv2" | "sslv3" => Err(()), // Deprecated/unsafe, reject explicitly
        _ => Err(()),
    }
}

/// Parse a `--prefer-family` argument string into an `AddressFamily` value.
///
/// Accepts the following values (case-insensitive):
/// * `"ipv4"` or `"4"` — IPv4 only.
/// * `"ipv6"` or `"6"` — IPv6 only.
/// * `"prefer_ipv4"` or `"prefer-ipv4"` — prefer IPv4, fall back to IPv6.
/// * `"prefer_ipv6"` or `"prefer-ipv6"` — prefer IPv6, fall back to IPv4.
///
/// Any unrecognized value returns `AddressFamily::Unspecified`.
///
/// # Arguments
/// * `s` — The family string from the command line.
///
/// # Returns
/// The resolved `AddressFamily` variant.
fn parse_address_family_arg(s: &str) -> ut_core::AddressFamily {
    // GNU wget accepts "IPv4", "IPv6", and "none" (case-insensitive).
    // "IPv4" means *prefer* IPv4 (not IPv4-only); "IPv6" means *prefer* IPv6.
    // "none" disables the preference.
    match s.to_ascii_lowercase().as_str() {
        "ipv4" | "4" | "ipv4-only" => ut_core::AddressFamily::PreferIpv4,
        "ipv6" | "6" | "ipv6-only" => ut_core::AddressFamily::PreferIpv6,
        "none" => ut_core::AddressFamily::Unspecified,
        _ => ut_core::AddressFamily::Unspecified,
    }
}

/// Parse a `--progress` argument string into a `ProgressStyle` value.
///
/// Accepts the following values (case-insensitive):
/// * `"none"` or `"silent"` — no progress output.
/// * `"verbose"` or `"v"` — per-file verbose progress.
/// * `"dot"` or `"d"` — classic dot-style progress (1024 bytes/dot, 50 dots/line).
/// * Any other value — the default bar-style progress indicator.
///
/// # Arguments
/// * `s` — The progress style string from the command line.
///
/// # Returns
/// The resolved `ProgressStyle` variant.
fn parse_progress_style_arg(s: &str) -> ut_core::ProgressStyle {
    match s.to_ascii_lowercase().as_str() {
        "none" | "silent" => ut_core::ProgressStyle::Silent,
        "verbose" | "v" => ut_core::ProgressStyle::Verbose,
        "dot" | "d" => ut_core::ProgressStyle::Dot {
            bytes_per_dot: 1024,
            dots_per_line: 50,
            spacing: 10,
        },
        _ => ut_core::ProgressStyle::Bar,
    }
}

/// Apply `--execute` commands to a configuration object.
///
/// Each command in the slice is expected to be a `key=value` pair. If the value
/// is `"on"` or `"off"` it is treated as a boolean toggle; otherwise it is
/// treated as a string assignment. Delegates to `WgetrcParser` for the actual
/// application logic.
///
/// # Arguments
/// * `config` — The mutable configuration to modify.
/// * `commands` — The list of `key=value` command strings from `--execute`.
pub fn apply_execute_commands(config: &mut ut_core::Config, commands: &[String]) -> Result<(), String> {
    for cmd in commands {
        let parts: Vec<&str> = cmd.splitn(2, '=').collect();
        if parts.len() != 2 {
            // GNU wget: invalid --execute command (no '=') → exit 2
            return Err(format!("invalid --execute command \"{}\" (expected key=value)", cmd));
        }
        let key = parts[0].trim();
        let value = parts[1].trim();
        // GNU wget accepts on/yes/1 → true, off/no/0 → false
        let v = value.trim();
        let is_true = v.eq_ignore_ascii_case("on")
            || v.eq_ignore_ascii_case("yes")
            || v == "1";
        let is_false = v.eq_ignore_ascii_case("off")
            || v.eq_ignore_ascii_case("no")
            || v == "0";
        let result = if is_true || is_false {
            crate::wgetrc::WgetrcParser::apply_onoff(key, is_true, config)
        } else {
            crate::wgetrc::WgetrcParser::apply_set(key, value, config)
        };
        if let Err(e) = result {
            // GNU wget exits with WGET_EXIT_PARSE_ERROR (2) on unknown
            // --execute commands. Propagate the error instead of silently
            // discarding it.
            return Err(format!("--execute \"{}\": {}", cmd, e));
        }
    }
    Ok(())
}
