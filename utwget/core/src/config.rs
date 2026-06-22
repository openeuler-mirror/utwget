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
