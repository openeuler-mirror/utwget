//! Command-line argument parsing for utwget.
//!
//! This module defines the `Args` struct which represents all command-line options
//! supported by utwget. The struct is derived from `clap::Parser` and provides
//! compatibility with GNU wget's command-line interface.
//!
//! # Option Categories
//!
//! The options are organized into the following categories:
//! - Startup: version, help, background, execute
//! - Logging: output-file, quiet, verbose, debug
//! - Download: tries, timeout, continue, output-document
//! - Directories: directory-prefix, cut-dirs, no-directories
//! - HTTP: user-agent, headers, cookies, authentication
//! - HTTPS/TLS: certificates, protocols, ciphers
//! - FTP: user, password, passive mode
//! - Recursive: level, accept/reject patterns
//! - WARC: archiving options
//! - Metalink: metalink download options

use std::path::PathBuf;

use clap::Parser;

/// Command-line arguments for utwget.
///
/// This struct captures all options supported by utwget, providing full
/// compatibility with GNU wget 1.21.4. Options are parsed using clap's
/// derive macro, with custom handling for wget-style argument placement.
///
/// # Argument Ordering
///
/// Unlike typical CLI tools, GNU wget allows options to appear anywhere
/// on the command line, including after URLs. The `main` module handles
/// this by rearranging arguments before parsing.
///
/// # Example
///
/// ```bash
/// utwget -r -l 3 -A "*.html" http://example.com
/// ```
#[derive(Parser, Debug)]
#[command(name = "utwget", version, about = "The non-interactive network downloader", long_about = None, disable_version_flag = true, disable_help_flag = true)]
#[command(arg_required_else_help = false)]
pub struct Args {
    /// Display the version of Wget and exit.
    #[arg(short = 'V', long = "version")]
    pub version: bool,

    /// Print help message and exit.
    #[arg(short = 'h', long = "help")]
    pub help: bool,

    /// Print help message and exit (short form with '?'').
    #[arg(short = '?')]
    pub help_short: bool,

    /// Go to background after startup.
    #[arg(short = 'b', long = "background")]
    pub background: bool,

    /// Execute a `.wgetrc`-style command.
    ///
    /// Can be specified multiple times. Each command should be in the form `key=value`.
    #[arg(short = 'e', long = "execute", num_args = 1)]
    pub execute: Vec<String>,

    /// Log messages to FILE instead of stderr.
    #[arg(short = 'o', long = "output-file")]
    pub output_file: Option<PathBuf>,

    /// Append messages to FILE instead of overwriting.
    #[arg(short = 'a', long = "append-output")]
    pub append_output: Option<PathBuf>,

    /// Print lots of debugging information.
    #[arg(short = 'd', long = "debug")]
    pub debug: bool,

    /// Quiet mode - suppress all output.
    #[arg(short = 'q', long = "quiet", conflicts_with = "verbose")]
    pub quiet: bool,

    /// Be verbose (this is the default).
    #[arg(short = 'v', long = "verbose", conflicts_with = "quiet")]
    pub verbose: bool,

    /// Turn off verboseness without being completely quiet.
    #[arg(long = "no-verbose")]
    pub no_verbose: bool,

    /// Read URLs from FILE, one per line.
    ///
    /// Lines starting with '#' are treated as comments and ignored.
    #[arg(short = 'i', long = "input-file")]
    pub input_file: Option<PathBuf>,

    /// Treat input file as HTML, extracting URLs from links.
    #[arg(short = 'F', long = "force-html")]
    pub force_html: bool,

    /// Resolve HTML input-file links relative to URL.
    ///
    /// Used with `-i -F` to provide a base URL for relative links.
    #[arg(short = 'B', long = "base")]
    pub base: Option<String>,

    /// Specify an alternate configuration file to read.
    #[arg(long = "config")]
    pub config_file: Option<PathBuf>,

    /// Enable recursive downloading.
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,

    /// Maximum recursion depth (0 or 'inf' for infinite).
    #[arg(short = 'l', long = "level", default_value = "5")]
    pub level: u32,

    /// Download all page requisites (images, stylesheets, etc.).
    #[arg(short = 'p', long = "page-requisites")]
    pub page_requisites: bool,

    /// Delete downloaded files after downloading them.
    #[arg(long = "delete-after")]
    pub delete_after: bool,

    /// Convert links in downloaded files to point to local files.
    #[arg(short = 'k', long = "convert-links")]
    pub convert_links: bool,

    /// Back up original files before converting links (as .orig).
    #[arg(short = 'K', long = "backup-converted")]
    pub backup_converted: bool,

    /// Only convert the filename part of URLs, not the full path.
    #[arg(long = "convert-file-only")]
    pub convert_file_only: bool,

    /// Mirror mode: equivalent to -N -r -l inf --no-remove-listing.
    #[arg(short = 'm', long = "mirror")]
    pub mirror: bool,

    /// Turn on timestamping: don't re-retrieve files unless newer.
    #[arg(short = 'N', long = "timestamping")]
    pub timestamping: bool,

    /// Skip downloads that would overwrite existing files.
    #[arg(long = "no-clobber")]
    pub no_clobber: bool,

    /// Remove file before overwriting (unlink instead of truncate).
    #[arg(long = "unlink")]
    pub unlink: bool,

    /// Rotate up to N backup files before writing.
    #[arg(long = "backups")]
    pub backups: Option<u32>,

    /// Continue getting a partially-downloaded file.
    #[arg(short = 'c', long = "continue")]
    pub continue_download: bool,

    /// Start downloading from zero-based byte position OFFSET.
    #[arg(long = "start-pos")]
    pub start_pos: Option<u64>,

    /// Write all documents to FILE (concatenated).
    #[arg(short = 'O', long = "output-document", value_name = "FILE")]
    pub output_document: Option<PathBuf>,

    /// Save files to PREFIX/... instead of current directory.
    #[arg(short = 'P', long = "directory-prefix")]
    pub directory_prefix: Option<PathBuf>,

    /// Ignore NUMBER remote directory components when saving.
    #[arg(long = "cut-dirs")]
    pub cut_dirs: Option<u32>,

    /// Restrict characters in file names to those allowed by OS.
    ///
    /// Valid values: unix, windows, nocontrol, ascii, lowercase, uppercase.
    #[arg(long = "restrict-file-names")]
    pub restrict_file_names: Option<String>,

    /// Set retrieval quota to NUMBER bytes (may use K, M, G suffixes).
    #[arg(short = 'Q', long = "quota")]
    pub quota: Option<String>,

    /// Limit download rate to RATE bytes per second.
    ///
    /// Examples: 100K, 1M, 500k.
    #[arg(long = "limit-rate")]
    pub limit_rate: Option<String>,

    /// Wait SECONDS between retrievals.
    #[arg(short = 'w', long = "wait")]
    pub wait: Option<f64>,

    /// Wait 1..SECONDS between retries of a retrieval.
    #[arg(long = "waitretry")]
    pub wait_retry: Option<f64>,

    /// Wait randomly from 0.5*WAIT to 1.5*WAIT seconds between retrievals.
    #[arg(long = "random-wait")]
    pub random_wait: bool,

    /// Set number of retries to NUMBER (0 for unlimited).
    #[arg(short = 't', long = "tries", default_value = "20")]
    pub tries: u32,

    /// Retry even if connection is refused.
    #[arg(long = "retry-connrefused")]
    pub retry_connrefused: bool,

    /// Comma-separated list of HTTP error codes to retry on.
    ///
    /// Example: --retry-on-http-error=404,500
    #[arg(long = "retry-on-http-error")]
    pub retry_on_http_error: Vec<u16>,

    /// Retry on host errors (DNS failure, no route to host, etc.).
    #[arg(long = "retry-on-host-error")]
    pub retry_on_host_error: bool,

    /// Don't download anything, just check for existence.
    #[arg(long = "spider")]
    pub spider: bool,

    /// Set all timeout values to SECONDS.
    #[arg(short = 'T', long = "timeout")]
    pub timeout: Option<f64>,

    /// Set the connect timeout to SECONDS.
    #[arg(long = "connect-timeout")]
    pub connect_timeout: Option<f64>,

    /// Set the read timeout to SECONDS.
    #[arg(long = "read-timeout")]
    pub read_timeout: Option<f64>,

    /// Set the DNS lookup timeout to SECONDS.
    #[arg(long = "dns-timeout")]
    pub dns_timeout: Option<f64>,

    /// Honor the Content-Disposition header when choosing local file names.
    #[arg(long = "content-disposition")]
    pub content_disposition: bool,

    /// Send Basic HTTP authentication without waiting for server challenge.
    #[arg(long = "auth-no-challenge")]
    pub auth_no_challenge: bool,

    /// Save HTML/CSS documents with proper extensions (.html, .css).
    #[arg(short = 'E', long = "adjust-extension")]
    pub adjust_extension: bool,

    /// Set HTTP authentication user.
    #[arg(long = "http-user")]
    pub http_user: Option<String>,

    /// Set HTTP authentication password.
    #[arg(long = "http-password")]
    pub http_password: Option<String>,

    /// Set both FTP and HTTP user to USER.
    #[arg(long = "user")]
    pub user: Option<String>,

    /// Set both FTP and HTTP password to PASS.
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Prompt for password interactively.
    #[arg(long = "ask-password")]
    pub ask_password: bool,

    /// Specify external program to prompt for password.
    ///
    /// Uses SSH_ASKPASS convention if no COMMAND is specified.
    #[arg(long = "use-askpass")]
    pub use_askpass: Option<String>,

    /// Don't try to obtain credentials from .netrc file.
    #[arg(long = "no-netrc")]
    pub no_netrc: bool,

    /// Identify as AGENT instead of Wget/VERSION.
    #[arg(short = 'U', long = "user-agent")]
    pub user_agent: Option<String>,

    /// Disable IRI (Internationalized Resource Identifier) support.
    #[arg(long = "no-iri")]
    pub no_iri: bool,

    /// Set local encoding for IRI (e.g., UTF-8).
    #[arg(long = "local-encoding")]
    pub local_encoding: Option<String>,

    /// Set default remote encoding for IRI.
    #[arg(long = "remote-encoding")]
    pub remote_encoding: Option<String>,

    /// Don't use conditional If-Modified-Since GET requests.
    #[arg(long = "no-if-modified-since")]
    pub no_if_modified_since: bool,

    /// Don't set local file timestamp from server's Last-Modified.
    #[arg(long = "no-use-server-timestamps")]
    pub no_use_server_timestamps: bool,

    /// Print server response headers.
    #[arg(short = 'S', long = "server-response")]
    pub server_response: bool,

    /// Save HTTP headers to file before content.
    #[arg(long = "save-headers")]
    pub save_headers: bool,

    /// Output received content even on server errors (4xx, 5xx).
    #[arg(long = "content-on-error")]
    pub content_on_error: bool,

    /// Insert STRING among the HTTP headers.
    ///
    /// Can be specified multiple times. Example: --header="X-Custom: value"
    #[arg(long = "header", num_args = 1)]
    pub header: Vec<String>,

    /// Include 'Referer: URL' header in HTTP request.
    #[arg(long = "referer")]
    pub referer: Option<String>,

    /// Use POST method; send STRING as the data.
    #[arg(long = "post-data")]
    pub post_data: Option<String>,

    /// Use POST method; send contents of FILE as the data.
    #[arg(long = "post-file")]
    pub post_file: Option<PathBuf>,

    /// Use HTTP method in the request (GET, POST, PUT, etc.).
    #[arg(long = "method")]
    pub method: Option<String>,

    /// Send STRING as data. Requires --method to be set.
    #[arg(long = "body-data")]
    pub body_data: Option<String>,

    /// Send contents of FILE as data. Requires --method to be set.
    #[arg(long = "body-file")]
    pub body_file: Option<PathBuf>,

    /// Maximum number of redirections allowed per page.
    #[arg(long = "max-redirect", default_value = "20")]
    pub max_redirect: u32,

    /// Comma-separated list of HTML tags to follow when recursing.
    #[arg(long = "follow-tags")]
    pub follow_tags: Option<String>,

    /// Comma-separated list of HTML tags to ignore when recursing.
    #[arg(long = "ignore-tags")]
    pub ignore_tags: Option<String>,

    /// Comma-separated list of accepted file extensions/patterns.
    #[arg(short = 'A', long = "accept")]
    pub accept: Option<String>,

    /// Comma-separated list of rejected file extensions/patterns.
    #[arg(short = 'R', long = "reject")]
    pub reject: Option<String>,

    /// Regular expression matching accepted URLs.
    #[arg(long = "accept-regex")]
    pub accept_regex: Option<String>,

    /// Regular expression matching rejected URLs.
    #[arg(long = "reject-regex")]
    pub reject_regex: Option<String>,

    /// Regular expression type: posix (default) or pcre.
    #[arg(long = "regex-type")]
    pub regex_type: Option<String>,

    /// Turn on strict (SGML) handling of HTML comments.
    #[arg(long = "strict-comments")]
    pub strict_comments: bool,

    /// Comma-separated list of accepted domains.
    #[arg(short = 'D', long = "domains")]
    pub domains: Option<String>,

    /// Comma-separated list of rejected domains.
    #[arg(long = "exclude-domains")]
    pub exclude_domains: Option<String>,

    /// Follow FTP links from HTML documents when recursing.
    #[arg(long = "follow-ftp")]
    pub follow_ftp: bool,

    /// Go to foreign hosts when recursing.
    #[arg(short = 'H', long = "span-hosts")]
    pub span_hosts: bool,

    /// Follow relative links only.
    #[arg(short = 'L', long = "relative")]
    pub relative: bool,

    /// Don't ascend to the parent directory when recursing.
    #[arg(long = "no-parent")]
    pub no_parent: bool,

    /// Comma-separated list of directories to include when recursing.
    #[arg(short = 'I', long = "include-directories")]
    pub include_directories: Option<String>,

    /// Comma-separated list of directories to exclude when recursing.
    #[arg(short = 'X', long = "exclude-directories")]
    pub exclude_directories: Option<String>,

    /// Don't create host-prefixed directories.
    #[arg(long = "no-host-directories")]
    pub no_host_directories: bool,

    /// Use protocol name in directory path (http/, https/).
    #[arg(long = "protocol-directories")]
    pub protocol_directories: bool,

    /// Don't create a directory hierarchy.
    #[arg(long = "no-directories")]
    pub no_directories: bool,

    /// Force creation of directory hierarchy.
    #[arg(long = "force-directories")]
    pub force_directories: bool,

    /// Don't validate the server's SSL/TLS certificate.
    #[arg(long = "no-check-certificate")]
    pub no_check_certificate: bool,

    /// Client certificate file for SSL/TLS authentication.
    #[arg(long = "certificate")]
    pub certificate: Option<PathBuf>,

    /// Client certificate type: PEM (default) or DER.
    #[arg(long = "certificate-type")]
    pub certificate_type: Option<String>,

    /// Private key file for SSL/TLS authentication.
    #[arg(long = "private-key")]
    pub private_key: Option<PathBuf>,

    /// Private key type: PEM (default) or DER.
    #[arg(long = "private-key-type")]
    pub private_key_type: Option<String>,

    /// File containing the bundle of CA certificates.
    #[arg(long = "ca-certificate")]
    pub ca_certificate: Option<PathBuf>,

    /// Directory with hash list of CA certificates.
    #[arg(long = "ca-directory")]
    pub ca_directory: Option<PathBuf>,

    /// File containing certificate revocation list (CRL).
    #[arg(long = "crl-file")]
    pub crl_file: Option<PathBuf>,

    /// Public key file or base64 SHA256 hashes for pinning.
    #[arg(long = "pinnedpubkey")]
    pub pinnedpubkey: Option<String>,

    /// Choose secure protocol: auto, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3, PFS.
    #[arg(long = "secure-protocol")]
    pub secure_protocol: Option<String>,

    /// Force HTTP/2 usage (utwget extension).
    #[arg(long = "http2")]
    pub http2: bool,

    /// Force HTTP/1.1 usage (disable HTTP/2).
    #[arg(long = "http1.1")]
    pub http1_1: bool,

    /// Set cipher suite priority string (OpenSSL/GnuTLS syntax).
    #[arg(long = "ciphers")]
    pub ciphers: Option<String>,

    /// Only follow secure HTTPS links.
    #[arg(long = "https-only")]
    pub https_only: bool,

    /// Set FTP authentication user.
    #[arg(long = "ftp-user")]
    pub ftp_user: Option<String>,

    /// Set FTP authentication password.
    #[arg(long = "ftp-password")]
    pub ftp_password: Option<String>,

    /// Don't remove temporary '.listing' files after FTP transfers.
    #[arg(long = "no-remove-listing")]
    pub no_remove_listing: bool,

    /// Turn off FTP file name globbing (wildcard expansion).
    #[arg(long = "no-glob")]
    pub no_glob: bool,

    /// Disable passive FTP transfer mode (use active mode).
    #[arg(long = "no-passive-ftp")]
    pub no_passive_ftp: bool,

    /// Use implicit FTPS (SSL/TLS from start, default port 990).
    #[arg(long = "ftps-implicit")]
    pub ftps_implicit: bool,

    /// Resume SSL/TLS session when opening FTP data connection.
    #[arg(long = "ftps-resume-ssl")]
    pub ftps_resume_ssl: bool,

    /// Use cleartext for FTPS data connection (only control channel encrypted).
    #[arg(long = "ftps-clear-data-connection")]
    pub ftps_clear_data_connection: bool,

    /// Fallback to plain FTP if FTPS is not supported by server.
    #[arg(long = "ftps-fallback-to-ftp")]
    pub ftps_fallback_to_ftp: bool,

    /// When recursing, retrieve symbolic links as files (not directories).
    #[arg(long = "retr-symlinks")]
    pub retr_symlinks: bool,

    /// Disable HTTP keep-alive (persistent connections).
    #[arg(long = "no-http-keep-alive")]
    pub no_http_keep_alive: bool,

    /// Don't use HTTP cookies.
    #[arg(long = "no-cookies")]
    pub no_cookies: bool,

    /// Load cookies from FILE before the session.
    #[arg(long = "load-cookies")]
    pub load_cookies: Option<PathBuf>,

    /// Save cookies to FILE after the session.
    #[arg(long = "save-cookies")]
    pub save_cookies: Option<PathBuf>,

    /// Load and save session (non-permanent) cookies.
    #[arg(long = "keep-session-cookies")]
    pub keep_session_cookies: bool,

    /// Disable HTTP Strict Transport Security (HSTS).
    #[arg(long = "no-hsts")]
    pub no_hsts: bool,

    /// Path of HSTS database file (overrides default).
    #[arg(long = "hsts-file")]
    pub hsts_file: Option<PathBuf>,

    /// Whether to use robots.txt files (on/off).
    #[arg(long = "use-robots")]
    pub use_robots: Option<bool>,

    /// Whether to use proxy (on/off).
    #[arg(long = "use-proxy")]
    pub use_proxy: Option<bool>,

    /// HTTP proxy URL.
    #[arg(long = "http-proxy")]
    pub http_proxy: Option<String>,

    /// HTTPS proxy URL.
    #[arg(long = "https-proxy")]
    pub https_proxy: Option<String>,

    /// FTP proxy URL.
    #[arg(long = "ftp-proxy")]
    pub ftp_proxy: Option<String>,

    /// Proxy authentication user.
    #[arg(long = "proxy-user")]
    pub proxy_user: Option<String>,

    /// Proxy authentication password.
    #[arg(long = "proxy-password")]
    pub proxy_password: Option<String>,

    /// Comma-separated list of domains to bypass proxy.
    #[arg(long = "no-proxy")]
    pub no_proxy: Option<String>,

    /// Save request/response data to WARC file (.warc.gz).
    #[arg(long = "warc-file")]
    pub warc_file: Option<String>,

    /// Maximum size of WARC files in bytes.
    #[arg(long = "warc-maxsize")]
    pub warc_maxsize: Option<u64>,

    /// Write CDX index files for WARC.
    #[arg(long = "warc-cdx")]
    pub warc_cdx: bool,

    /// Enable CDX deduplication for WARC.
    #[arg(long = "warc-dedup")]
    pub warc_dedup: bool,

    /// Enable GZIP compression for WARC files.
    #[arg(long = "warc-compression")]
    pub warc_compression: bool,

    /// Enable SHA1 digest computation for WARC records.
    #[arg(long = "warc-digests")]
    pub warc_digests: bool,

    /// Store log file in WARC record.
    #[arg(long = "warc-keep-log")]
    pub warc_keep_log: bool,

    /// Disable GZIP compression for WARC files.
    #[arg(long = "no-warc-compression")]
    pub no_warc_compression: bool,

    /// Disable SHA1 digest computation for WARC records.
    #[arg(long = "no-warc-digests")]
    pub no_warc_digests: bool,

    /// Don't store log file in WARC record.
    #[arg(long = "no-warc-keep-log")]
    pub no_warc_keep_log: bool,

    /// Location for temporary files created by WARC writer.
    #[arg(long = "warc-temp-dir")]
    pub warc_temp_dir: Option<PathBuf>,

    /// Number of concurrent downloads (utwget extension).
    #[arg(long = "concurrency", short = 'j', default_value = "1")]
    pub concurrency: usize,

    /// Insert STRING into the warcinfo record.
    ///
    /// Can be specified multiple times.
    #[arg(long = "warc-header", num_args = 1)]
    pub warc_header: Vec<String>,

    /// Use Metalink from HTTP response headers.
    #[arg(long = "metalink-over-http")]
    pub metalink_over_http: bool,

    /// Read Metalink description from FILE.
    #[arg(long = "input-metalink")]
    pub input_metalink: Option<PathBuf>,

    /// Output as Metalink format (deprecated).
    #[arg(long = "metalink")]
    pub metalink: bool,

    /// Progress indicator style: bar, dot, none.
    #[arg(long = "progress", default_value = "bar")]
    pub progress: String,

    /// Display progress bar in any verbosity mode.
    #[arg(long = "show-progress")]
    pub show_progress: bool,

    /// Disable caching of DNS lookups.
    #[arg(long = "no-dns-cache")]
    pub no_dns_cache: bool,

    /// Disable server-side cache (send Cache-Control: no-cache).
    #[arg(long = "no-cache")]
    pub no_cache: bool,

    /// Bind to ADDRESS (hostname or IP) on local host for outgoing connections.
    #[arg(long = "bind-address")]
    pub bind_address: Option<String>,

    /// Enable compression (Accept-Encoding: gzip, deflate).
    #[arg(long = "compression")]
    pub compression: bool,

    /// Disable compression.
    #[arg(long = "no-compression")]
    pub no_compression: bool,

    /// Connect only to IPv4 addresses.
    #[arg(short = '4', long = "inet4-only")]
    pub inet4_only: bool,

    /// Connect only to IPv6 addresses.
    #[arg(short = '6', long = "inet6-only")]
    pub inet6_only: bool,

    /// Prefer address family: IPv4, IPv6, or none.
    #[arg(long = "prefer-family")]
    pub prefer_family: Option<String>,

    /// Use server-provided file names instead of deriving from URL.
    #[arg(long = "trust-server-names")]
    pub trust_server_names: bool,

    /// Output bandwidth as TYPE: bits or bytes.
    #[arg(long = "report-speed")]
    pub report_speed: Option<String>,

    /// Change default page name (normally 'index.html').
    #[arg(long = "default-page")]
    pub default_page: Option<String>,

    /// Specify robots.txt handling: on, off, or server-specific.
    #[arg(long = "robots")]
    pub robots: Option<String>,

    /// Log reasons for URL rejection to FILE.
    #[arg(long = "reject-log")]
    pub reject_log: Option<PathBuf>,

    /// Ignore 'Content-Length' header field.
    #[arg(long = "ignore-length")]
    pub ignore_length: bool,

    /// Ignore case when matching files and directories.
    #[arg(long = "ignore-case")]
    pub ignore_case: bool,

    /// Store metadata in file extended attributes (xattr).
    #[arg(long = "xattr")]
    pub xattr: bool,

    /// Preserve permissions of remote files.
    #[arg(long = "preserve-permissions")]
    pub preserve_permissions: bool,

    /// URLs to download.
    ///
    /// Multiple URLs can be specified. Options can appear anywhere
    /// on the command line, not just before URLs.
    pub urls: Vec<String>,
}
