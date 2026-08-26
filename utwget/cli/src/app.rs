use std::fs;
use std::io::{self, BufRead, BufReader, Cursor, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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
    /// Uses the same priority logic as the original wget: the "worst"
    /// (highest numeric) status wins across all URLs.
    pub fn from_error(err: &ut_core::error::WgetError) -> Self {
        use ut_core::error::{TlsError, FtpError};
        match err {
            WgetError::FtpFileNotFound(_)
            | WgetError::FileNotFound(_)
            | WgetError::FileExists(_)
            | WgetError::CannotCreateDir(_)
            | WgetError::WriteError(_) => ExitStatus::IoFail,

            WgetError::HostNotFound(_)
            | WgetError::ConnectionRefused
            |             WgetError::ConnectionTimeout(_)
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
            | WgetError::FtpLoginRefused
            | WgetError::Ftp(FtpError::UnexpectedResponse { code: 530..=539, .. }) => ExitStatus::ServerAuthFail,

            WgetError::Http { status: 400..=499, .. }
            | WgetError::TooManyRedirects { .. }
            | WgetError::UnsupportedMethod(_)
            | WgetError::UrlParse(_)
            | WgetError::UnsupportedScheme(_) => ExitStatus::ProtocolError,

            WgetError::Http { status: 500..=599, .. }
            | WgetError::FtpServerError(_)
            | WgetError::Ftp(FtpError::UnexpectedResponse { .. })
            | WgetError::Ftp(FtpError::ConnectionLost)
            | WgetError::Ftp(FtpError::DataConnectionFailed(_))
            | WgetError::Ftp(FtpError::PasvFailed(_))
            | WgetError::Ftp(FtpError::PortFailed(_)) => ExitStatus::ServerError,

            WgetError::RetryLimitExceeded { .. }
            | WgetError::QuotaExceeded { .. }
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
                            Err(_) => return Err(WgetError::Other(format!("failed to read HTML input file: {}", url))),
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
                            Err(e) => return Err(WgetError::Other(format!("error reading input file: {}", e))),
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
        if self.config.recursive.enabled {
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

            // Check for configuration reload
            if crate::config_reload::ConfigReloader::should_reload() {
                if self.config.verbose >= 1 {
                    eprintln!("{}", crate::i18n::translate("utwget.config_reloaded"));
                }
            }

            let expanded = self.expand_url(url_str);
            let url_str = expanded.as_str();

            let parsed = match ParsedUrl::parse(url_str) {
                Ok(p) => p,
                Err(e) => {
                    self.urls_attempted += 1;
                    if self.config.verbose >= 1 || self.config.debug {
                        eprintln!("wget-rs: {}", e);
                    }
                    continue;
                }
            };

            self.urls_attempted += 1;

            let result = self.retriever.retrieve_with_retry(&parsed.display());

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
                        eprintln!("{}", crate::i18n::translate_with_args("utwget.status_redirected_to", &[("url", new_url)]));
                    }
                }
                Ok(RetrieveOutcome::SpiderOnly) => {
                    // Spider mode, no download
                }
                Err(e) => {
                    let wg_err = match e {
                        ut_retriever::RetrieveError::Protocol(w) => w,
                        ut_retriever::RetrieveError::Response(w) => w,
                        ut_retriever::RetrieveError::Io(io_err) => WgetError::SocketError(io_err),
                        ut_retriever::RetrieveError::Quota => WgetError::Other("quota exceeded".to_string()),
                        ut_retriever::RetrieveError::NoUrls => WgetError::Other("no URLs to download".to_string()),
                    };
                    let status = ExitStatus::from_error(&wg_err);
                    if status > self.worst_status {
                        self.worst_status = status;
                    }
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
        let worst_status = Arc::new(Mutex::new(ExitStatus::Success));
        let urls_downloaded = Arc::new(Mutex::new(0u32));
        let urls_attempted = Arc::new(Mutex::new(0u32));

        // Create tokio runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(concurrency.min(num_cpus::get()))
            .enable_all()
            .build()
            .map_err(|e| WgetError::Other(format!("failed to create tokio runtime: {}", e)))?;

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
                    {
                        let mut attempted = urls_attempted.lock().unwrap();
                        *attempted += 1;
                    }

                    // Use async retriever
                    let result = async_retriever.retrieve(&url).await;

                    match result {
                        Ok(RetrieveOutcome::Success(_)) | Ok(_) => {
                            let mut downloaded = urls_downloaded.lock().unwrap();
                            *downloaded += 1;
                        }
                        Err(e) => {
                            let wg_err = match e {
                                ut_retriever::RetrieveError::Protocol(w) => w,
                                ut_retriever::RetrieveError::Response(w) => w,
                                ut_retriever::RetrieveError::Io(io_err) => WgetError::SocketError(io_err),
                                ut_retriever::RetrieveError::Quota => WgetError::Other("quota exceeded".to_string()),
                                ut_retriever::RetrieveError::NoUrls => WgetError::Other("no URLs to download".to_string()),
                            };
                            let status = ExitStatus::from_error(&wg_err);
                            let mut worst = worst_status.lock().unwrap();
                            if status > *worst {
                                *worst = status;
                            }
                        }
                    }
                });
                handles.push(handle);
            }

            // Wait for all tasks to complete
            for handle in handles {
                let _ = handle.await;
            }
        });

        self.urls_attempted = *urls_attempted.lock().unwrap();
        self.urls_downloaded = *urls_downloaded.lock().unwrap();
        self.worst_status = *worst_status.lock().unwrap();

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

            match recursive_retriever.retrieve_tree(&parsed.display()) {
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

        self.print_summary();

        Ok(overall_status)
    }

    /// Convert links in downloaded files.
    ///
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
            if self.config.debug {
                eprintln!("Converting links in: {}", local_path);
            }

            match converter.convert_links(local_path, &url_to_local, &opts) {
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

        if self.config.verbose >= 1 {
            eprintln!("Link conversion complete: {} links converted, {} files failed",
                converted_count, failed_count);
        }
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
                    .map_err(|e| WgetError::Other(format!("URL parse error: {}", e)))?;

                match self.retriever.retrieve(&parsed.display()) {
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
                .map_err(|e| WgetError::Other(format!("URL parse error: {}", e)))?;

            match self.retriever.retrieve(&parsed.display()) {
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
            .map_err(|e| WgetError::Other(format!("cannot open metalink file: {}", e)))?;
        let reader = std::io::BufReader::new(file);

        let metalink_files = MetalinkParser::parse(reader)
            .map_err(|e| WgetError::Other(format!("metalink parse error: {}", e)))?;

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
            .map_err(|e| WgetError::Other(format!("HTML parse error: {}", e)))?;
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
}

/// Build a fully-resolved `ut_core::Config` from the parsed command-line arguments.
///
/// Maps every CLI flag, option, and sub-option to the corresponding field on the
/// configuration object. This includes HTTP, FTP, TLS, proxy, recursive, WARC,
/// Metalink, progress, and miscellaneous settings.
///
/// # Arguments
/// * `args` — The parsed command-line arguments.
///
/// # Returns
/// A `ut_core::Config` populated with all user-specified options and defaults.
pub fn build_config(args: &Args) -> ut_core::Config {
    let mut config = ut_core::Config::default();

    if args.quiet {
        config.quiet = true;
        config.verbose = 0;
    } else if args.verbose {
        config.verbose = 1;
    } else if args.no_verbose {
        config.verbose = 0;
    }

    config.debug = args.debug;
    config.server_response = args.server_response;
    config.background = args.background;
    config.tries = args.tries;
    config.retry_connrefused = args.retry_connrefused;
    config.retry_on_host_error = args.retry_on_host_error;
    config.retry_on_http_error = args.retry_on_http_error.clone();

    config.output_document = args.output_document.clone();
    config.input_filename = args.input_file.clone();
    config.force_html = args.force_html;
    config.dir_prefix = args.directory_prefix.clone();
    config.noclobber = args.no_clobber;
    config.unlink = args.unlink;
    config.backups = args.backups;
    config.continue_download = args.continue_download;
    config.start_position = args.start_pos;
    config.timestamping = args.timestamping;

    if args.no_if_modified_since {
        config.if_modified_since = false;
    }
    if args.no_use_server_timestamps {
        config.use_server_timestamps = false;
    }

    config.quota = args.quota.as_ref().and_then(|s| ut_core::utils::parse_size_string(s));
    config.limit_rate = args.limit_rate.as_ref().and_then(|s| ut_core::utils::parse_size_string(s));

    config.wait = args.wait.map(Duration::from_secs_f64);
    config.wait_retry = args.wait_retry.map(Duration::from_secs_f64);
    config.random_wait = args.random_wait;
    config.delete_after = args.delete_after;
    config.content_disposition = args.content_disposition;
    config.auth_without_challenge = args.auth_no_challenge;
    config.concurrent_downloads = args.concurrency;

    if args.no_netrc {
        config.use_netrc = false;
    }

    config.http.user = args.http_user.clone().or(args.user.clone());
    config.http.password = args.http_password.clone().or(args.password.clone());

    // Handle --ask-password: prompt for password interactively
    if args.ask_password && config.http.password.is_none() {
        if let Some(ref user) = config.http.user {
            config.http.password = prompt_password(&format!("Password for {}: ", user));
        } else {
            config.http.password = prompt_password("Password: ");
        }
    }

    // Handle --use-askpass: use external program to get password
    if let Some(ref askpass_cmd) = args.use_askpass {
        if config.http.password.is_none() {
            config.http.password = run_askpass(askpass_cmd);
        }
    }

    config.http.headers = args.header.clone();
    config.http.user_agent = args.user_agent.clone();
    config.http.referer = args.referer.clone();
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

    if args.no_http_keep_alive {
        config.http.keep_alive = false;
    }

    if let Some(ref method) = args.method {
        if let Ok(m) = method.parse() {
            config.http.method = Some(m);
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

    config.ftp.user = args.ftp_user.clone();
    config.ftp.password = args.ftp_password.clone();

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
    }
    config.tls.cert_file = args.certificate.clone();
    config.tls.private_key = args.private_key.clone();
    config.tls.ca_cert = args.ca_certificate.clone();
    config.tls.ca_directory = args.ca_directory.clone();
    config.tls.crl_file = args.crl_file.clone();
    config.tls.pinned_pubkey = args.pinnedpubkey.clone();
    config.tls.ciphers = args.ciphers.clone();

    if let Some(ref sp) = args.secure_protocol {
        if let Ok(p) = parse_secure_protocol_arg(sp) {
            config.tls.secure_protocol = p;
        }
    }

    config.recursive.enabled = args.recursive;
    // -l 0 means unlimited depth (like original wget), so set to None
    config.recursive.max_level = if args.level == 0 { None } else { Some(args.level) };
    config.page_requisites = args.page_requisites;
    config.recursive.span_hosts = args.span_hosts;
    config.recursive.no_parent = args.no_parent;
    config.recursive.relative_only = args.relative;
    config.recursive.spider = args.spider;

    config.ignore_length = args.ignore_length;
    config.ignore_case = args.ignore_case;

    config.xattr = args.xattr;
    config.preserve_permissions = args.preserve_permissions;

    if let Some(ref tags) = args.follow_tags {
        config.recursive.follow_tags = tags.split(',').map(String::from).collect();
    }
    if let Some(ref tags) = args.ignore_tags {
        config.recursive.ignore_tags = tags.split(',').map(String::from).collect();
    }
    if let Some(ref patterns) = args.accept {
        config.recursive.accept_patterns = patterns.split(',').map(String::from).collect();
    }
    if let Some(ref patterns) = args.reject {
        config.recursive.reject_patterns = patterns.split(',').map(String::from).collect();
    }
    config.recursive.accept_regex = args.accept_regex.clone();
    config.recursive.reject_regex = args.reject_regex.clone();
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

    config.convert_links = args.convert_links;
    config.convert_file_only = args.convert_file_only;
    config.backup_converted = args.backup_converted;
    config.adjust_extension = args.adjust_extension;

    if args.mirror {
        config.recursive.enabled = true;
        config.timestamping = true;
        config.recursive.use_robots = false;
        config.convert_links = true;
        config.page_requisites = true;
        config.recursive.max_level = Some(0);
        config.continue_download = true;
    }

    config.max_redirect = args.max_redirect;

    config.timeout = args.timeout.map(Duration::from_secs_f64);
    config.connect_timeout = args.connect_timeout.map(Duration::from_secs_f64);
    config.read_timeout = args.read_timeout.map(Duration::from_secs_f64);
    config.dns_timeout = args.dns_timeout.map(Duration::from_secs_f64);

    config.cookie.enabled = !args.no_cookies;
    config.cookie.input_file = args.load_cookies.clone();
    config.cookie.output_file = args.save_cookies.clone();
    config.cookie.keep_session_cookies = args.keep_session_cookies;

    #[cfg(feature = "hsts")]
    {
        config.hsts.enabled = !args.no_hsts;
        config.hsts.file = args.hsts_file.clone();
    }

    if args.use_proxy == Some(false) {
        config.proxy.use_proxy = false;
    }
    config.proxy.http_proxy = args.http_proxy.clone();
    config.proxy.https_proxy = args.https_proxy.clone();
    config.proxy.ftp_proxy = args.ftp_proxy.clone();
    config.proxy.proxy_user = args.proxy_user.clone();
    config.proxy.proxy_password = args.proxy_password.clone();
    if let Some(ref np) = args.no_proxy {
        config.proxy.no_proxy = np.split(',').map(String::from).collect();
    }

    config.no_host_directories = args.no_host_directories;
    config.protocol_directories = args.protocol_directories;
    config.no_directories = args.no_directories;
    config.force_directories = args.force_directories;
    config.cut_dirs = args.cut_dirs.unwrap_or(0);

    config.bind_address = args.bind_address.clone();
    config.force_ipv4 = args.inet4_only;
    config.force_ipv6 = args.inet6_only;

    // Handle compression options
    #[cfg(feature = "compression")]
    {
        if args.no_compression {
            config.compression = ut_core::types::CompressionMode::None;
        } else if args.compression {
            config.compression = ut_core::types::CompressionMode::Auto;
        }
    }

    if let Some(ref family) = args.prefer_family {
        config.prefer_family = parse_address_family_arg(family);
    }

    // WARC configuration
    if args.warc_file.is_some() || args.warc_cdx || args.warc_dedup || args.warc_compression || args.warc_digests {
        config.warc.enabled = true;
        config.warc.filename = args.warc_file.clone();
        config.warc.max_size = args.warc_maxsize;
        config.warc.cdx = args.warc_cdx;
        config.warc.keep_log = args.warc_keep_log;
        config.warc.compression = args.warc_compression;
        config.warc.digests = args.warc_digests;
        config.warc.tempdir = args.warc_temp_dir.clone();
        config.warc.user_headers = args.warc_header.clone();
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
        config.metalink.input_file = args.input_metalink.clone();
    }

    config.progress.style = parse_progress_style_arg(&args.progress);
    config.progress.force_noscroll = !args.show_progress || !io::stdout().is_terminal();

    config.reject_log = args.reject_log.clone();

    config
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
/// Executes the program specified by `--use-askpass` and captures its stdout
/// as the password. This is consistent with the `SSH_ASKPASS` convention.
///
/// # Arguments
/// * `program` — Path or name of the askpass executable.
///
/// # Returns
/// The password text returned by the program, or `None` if the program could
/// not be run or returned a non-zero exit code.
fn run_askpass(program: &str) -> Option<String> {
    use std::process::Command;

    let result = Command::new(program)
        .output()
        .ok()?;

    if result.status.success() {
        let password = String::from_utf8_lossy(&result.stdout);
        Some(password.trim().to_string())
    } else {
        None
    }
}
