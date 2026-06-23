//! Configuration types and settings for utwget.
//!
//! This module defines all configuration structures used throughout the
//! application, including HTTP, FTP, TLS, proxy, and recursive download settings.

use crate::error::ConfigError;
use crate::types::{
    AddressFamily, CaseRestriction, CheckCertMode, CompressionMode, Credentials,
    HttpMethod, KeyFileType, ProgressStyle, RestrictOs, Scheme, SecureProtocol,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Main configuration structure for utwget.
///
/// This struct holds all settings that control the behavior of the downloader,
/// including network settings, authentication, proxy configuration, and
/// recursive download options.
///
/// # Example
///
/// ```
/// use ut_core::Config;
///
/// let config = Config::default();
/// assert_eq!(config.tries, 20);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Verbosity level (-v, -q options)
    pub verbose: i32,
    /// Suppress all output (--quiet)
    pub quiet: bool,
    /// Number of retries (--tries)
    pub tries: u32,
    /// Retry on connection refused (--retry-connrefused)
    pub retry_connrefused: bool,
    /// Retry on host resolution errors (--retry-on-host-error)
    pub retry_on_host_error: bool,
    /// HTTP status codes to retry on (--retry-on-http-error)
    pub retry_on_http_error: Vec<u16>,
    /// Run in background mode (--background)
    pub background: bool,
    /// Enable debug output (--debug)
    pub debug: bool,
    /// Print server response headers (--server-response)
    pub server_response: bool,

    /// Output file path (--output-document)
    pub output_document: Option<PathBuf>,
    /// Input file with URLs to download (--input-file)
    pub input_filename: Option<PathBuf>,
    /// Force treating input as HTML (--force-html)
    pub force_html: bool,
    /// Directory prefix for downloaded files (--directory-prefix)
    pub dir_prefix: Option<PathBuf>,
    /// Don't overwrite existing files (--no-clobber)
    pub noclobber: bool,
    /// Remove file before overwriting (--unlink)
    pub unlink: bool,
    /// Number of backup files to rotate (--backups)
    pub backups: Option<u32>,
    /// Continue partial downloads (--continue)
    pub continue_download: bool,
    /// Starting byte position for download (--start-pos)
    pub start_position: Option<u64>,
    /// Use timestamping for conditional downloads (--timestamping)
    pub timestamping: bool,
    /// Send If-Modified-Since header (--if-modified-since)
    pub if_modified_since: bool,
    /// Use server timestamps for local files (--use-server-timestamps)
    pub use_server_timestamps: bool,
    /// Download quota in bytes (--quota)
    pub quota: Option<u64>,
    /// Maximum download rate in bytes/sec (--limit-rate)
    pub limit_rate: Option<u64>,
    /// Wait time between downloads (--wait)
    pub wait: Option<Duration>,
    /// Number of concurrent downloads (utwget extension, --concurrency/-j)
    pub concurrent_downloads: usize,
    /// Wait time between retries (--waitretry)
    pub wait_retry: Option<Duration>,
    /// Use random wait times (--random-wait)
    pub random_wait: bool,
    /// Delete downloaded files after completion (--delete-after)
    pub delete_after: bool,
    /// Use Content-Disposition header for filename (--content-disposition)
    pub content_disposition: bool,
    /// Send authentication without waiting for challenge (--auth-no-challenge)
    pub auth_without_challenge: bool,
    /// Use .netrc file for credentials (--no-netrc disables)
    pub use_netrc: bool,

    /// HTTP-specific configuration
    pub http: HttpConfig,
    /// FTP-specific configuration
    pub ftp: FtpConfig,
    /// TLS/SSL configuration
    pub tls: TlsConfig,
    /// Recursive download configuration
    pub recursive: RecursiveConfig,
    /// WARC archive configuration
    pub warc: WarcConfig,
    /// Metalink configuration
    pub metalink: MetalinkConfig,
    /// HSTS (HTTP Strict Transport Security) configuration
    #[cfg(feature = "hsts")]
    pub hsts: HstsConfig,
    /// Cookie configuration
    pub cookie: CookieConfig,
    /// Proxy configuration
    pub proxy: ProxyConfig,
    /// Progress display configuration
    pub progress: ProgressConfig,
    /// Filename restriction settings
    pub filename_restrictions: FilenameRestrictions,
    /// IRI (Internationalized Resource Identifier) configuration
    pub iri: IriConfig,
    /// Compression mode for downloads
    #[cfg(feature = "compression")]
    pub compression: CompressionMode,

    /// Preferred address family for DNS resolution (--prefer-family)
    pub prefer_family: AddressFamily,
    /// Force IPv4 only (--inet4-only)
    pub force_ipv4: bool,
    /// Force IPv6 only (--inet6-only)
    pub force_ipv6: bool,

    /// Convert links for local viewing (--convert-links)
    pub convert_links: bool,
    /// Only convert filename portion of URLs (--convert-file-only)
    pub convert_file_only: bool,
    /// Backup files before converting (--backup-converted)
    pub backup_converted: bool,
    /// Adjust file extensions based on Content-Type (--adjust-extension)
    pub adjust_extension: bool,
    /// Download all page requisites (--page-requisites)
    pub page_requisites: bool,

    /// Ignore Content-Length header (--ignore-length)
    pub ignore_length: bool,
    /// Ignore case in pattern matching (--ignore-case)
    pub ignore_case: bool,

    /// Store metadata in file extended attributes (xattr)
    pub xattr: bool,
    /// Preserve permissions of remote files
    pub preserve_permissions: bool,

    /// Maximum number of redirects to follow (--max-redirect)
    pub max_redirect: u32,
    /// Global timeout for all operations (--timeout)
    pub timeout: Option<Duration>,
    /// Connection establishment timeout (--connect-timeout)
    pub connect_timeout: Option<Duration>,
    /// Read operation timeout (--read-timeout)
    pub read_timeout: Option<Duration>,
    /// DNS resolution timeout (--dns-timeout)
    pub dns_timeout: Option<Duration>,

    /// Local address to bind for outgoing connections (--bind-address)
    pub bind_address: Option<String>,
    /// Don't create host directories (--no-host-directories)
    pub no_host_directories: bool,
    /// Create protocol directories (--protocol-directories)
    pub protocol_directories: bool,
    /// Don't create a directory hierarchy (--no-directories)
    pub no_directories: bool,
    /// Force creation of directory hierarchy (--force-directories)
    pub force_directories: bool,
    /// Number of directory levels to cut from path (--cut-dirs)
    pub cut_dirs: u32,
    /// Log rejected URLs to file (--reject-log)
    pub reject_log: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            verbose: -1,
            quiet: false,
            tries: 20,
            retry_connrefused: false,
            retry_on_host_error: false,
            retry_on_http_error: Vec::new(),
            background: false,
            debug: false,
            server_response: false,

            output_document: None,
            input_filename: None,
            force_html: false,
            dir_prefix: None,
            noclobber: false,
            unlink: false,
            backups: None,
            continue_download: false,
            start_position: None,
            timestamping: false,
            if_modified_since: true,
            use_server_timestamps: true,
            quota: None,
            limit_rate: None,
            wait: None,
            concurrent_downloads: 1,
            wait_retry: None,
            random_wait: false,
            delete_after: false,
            content_disposition: false,
            auth_without_challenge: false,
            use_netrc: true, // Default: use .netrc

            http: HttpConfig::default(),
            ftp: FtpConfig::default(),
            tls: TlsConfig::default(),
            recursive: RecursiveConfig::default(),
            warc: WarcConfig::default(),
            metalink: MetalinkConfig::default(),
            #[cfg(feature = "hsts")]
            hsts: HstsConfig::default(),
            cookie: CookieConfig::default(),
            proxy: ProxyConfig::default(),
            progress: ProgressConfig::default(),
            filename_restrictions: FilenameRestrictions::default(),
            iri: IriConfig::default(),
            #[cfg(feature = "compression")]
            compression: CompressionMode::Auto,

            prefer_family: AddressFamily::Unspecified,
            force_ipv4: false,
            force_ipv6: false,

            convert_links: false,
            convert_file_only: false,
            backup_converted: false,
            adjust_extension: false,
            page_requisites: false,

            ignore_length: false,
            ignore_case: false,

            xattr: false,
            preserve_permissions: false,

            max_redirect: 20,
            timeout: None,
            connect_timeout: None,
            read_timeout: None,
            dns_timeout: None,

            bind_address: None,
            no_host_directories: false,
            protocol_directories: false,
            no_directories: false,
            force_directories: false,
            cut_dirs: 0,
            reject_log: None,
        }
    }
}

/// HTTP protocol configuration.
///
/// Contains settings specific to HTTP downloads, including authentication,
/// headers, request methods, and user agent settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    /// HTTP authentication username (--http-user)
    pub user: Option<String>,
    /// HTTP authentication password (--http-password)
    pub password: Option<String>,
    /// Additional HTTP headers to send (--header)
    pub headers: Vec<String>,
    /// Use persistent HTTP connections (--keep-alive)
    pub keep_alive: bool,
    /// HTTP request method (--method)
    pub method: Option<HttpMethod>,
    /// POST data as bytes (--post-data)
    pub post_data: Option<Vec<u8>>,
    /// POST data from file (--post-file)
    pub post_file: Option<PathBuf>,
    /// Request body data as bytes (--body-data)
    pub body_data: Option<Vec<u8>>,
    /// Request body data from file (--body-file)
    pub body_file: Option<PathBuf>,
    /// User-Agent header value (--user-agent)
    pub user_agent: Option<String>,
    /// Referer header value (--referer)
    pub referer: Option<String>,
    /// Save HTTP headers to output file (--save-headers)
    pub save_headers: bool,
    /// Output content even on HTTP error (--content-on-error)
    pub content_on_error: bool,
    /// Only follow HTTPS links (--https-only)
    pub https_only: bool,
    /// Default page name for directory URLs (--default-page)
    pub default_page: String,
    /// Force HTTP/2 usage (--http2)
    pub force_http2: bool,
    /// Force HTTP/1.1 usage (--http1.1)
    pub force_http1_1: bool,
}
