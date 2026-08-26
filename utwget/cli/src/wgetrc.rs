//! wgetrc configuration file parser.
//!
//! This module provides parsing and application of wgetrc configuration files,
//! which contain wget settings in a simple `key = value` format. The parser
//! supports both system-wide (`/etc/wgetrc`) and user-specific (`~/.wgetrc`)
//! configuration files.
//!
//! # File Format
//!
//! wgetrc files use a simple line-based format:
//!
//! ```text
//! # This is a comment
//! key = value
//! flag = on
//! other_flag = off
//! ```
//!
//! Lines starting with `#` are comments. Settings can be:
//! - Key-value pairs: `key = value`
//! - Boolean flags: `flag = on` or `flag = off`
//! - Commands with arguments: `command arg1 arg2 ...`
//!
//! # Configuration Priority
//!
//! Settings are applied in this order (later overrides earlier):
//! 1. System-wide `/etc/wgetrc`
//! 2. User-specific `~/.wgetrc`
//! 3. Custom config file specified with `--config`
//! 4. Commands from `--execute` options
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use utwget::cli::wgetrc::{WgetrcParser, WgetrcCommand};
//!
//! // Parse a wgetrc file
//! let commands = WgetrcParser::parse(Path::new("/etc/wgetrc"))?;
//!
//! // Apply commands to configuration
//! let mut config = ut_core::Config::default();
//! WgetrcParser::apply(&commands, &mut config)?;
//! # Ok::<(), ut_core::error::WgetError>(())
//! ```

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use ut_core::error::{ConfigError, WgetError};

/// A parsed command from a wgetrc configuration file.
///
/// Commands can take three forms:
/// - `Set(key, value)` - A key-value assignment like `dir_prefix = /downloads`
/// - `OnOff(key, flag)` - A boolean toggle like `quiet = on`
/// - `Command(name, args)` - A command with arguments like `accept *.html *.css`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WgetrcCommand {
    /// A key-value setting: `key = value`.
    Set(String, String),
    /// A boolean toggle: `key = on` or `key = off`.
    OnOff(String, bool),
    /// A command with space-separated arguments.
    Command(String, Vec<String>),
}

/// Parser for wgetrc configuration files.
///
/// This zero-sized type provides methods for parsing wgetrc files and
/// applying the parsed settings to a `Config` object.
///
/// # Supported Settings
///
/// The parser recognizes most wget configuration options, including:
/// - Download settings: `dir_prefix`, `tries`, `timeout`, `continue`
/// - HTTP settings: `user_agent`, `http_user`, `http_password`
/// - Proxy settings: `http_proxy`, `use_proxy`
/// - TLS settings: `check_certificate`, `secure_protocol`
/// - Recursive settings: `recursive`, `level`, `accept`, `reject`
/// - Cookie settings: `cookies`, `load_cookies`, `save_cookies`
pub struct WgetrcParser;

impl WgetrcParser {
    /// Parse a wgetrc configuration file.
    ///
    /// Reads the file at `path` line by line, skipping comments and empty lines,
    /// and returns a vector of parsed commands.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the wgetrc file to parse.
    ///
    /// # Returns
    ///
    /// A vector of `WgetrcCommand` representing the parsed settings.
    ///
    /// # Errors
    ///
    /// Returns `WgetError::Config` if the file cannot be opened or read.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::Path;
    /// let commands = WgetrcParser::parse(Path::new("/etc/wgetrc"))?;
    /// # Ok::<(), ut_core::error::WgetError>(())
    /// ```
    pub fn parse(path: &Path) -> Result<Vec<WgetrcCommand>, WgetError> {
        let file = fs::File::open(path).map_err(|e| {
            WgetError::Config(ConfigError::FileError {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
        })?;
        let reader = BufReader::new(file);
        let mut commands = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| WgetError::Config(ConfigError::FileError {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }))?;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(cmd) = Self::parse_line(trimmed, path) {
                commands.push(cmd);
            }
        }

        Ok(commands)
    }

    /// Parse a single line from a wgetrc file.
    ///
    /// Handles three formats:
    /// - `key = value` - Returns `Set` or `OnOff` depending on value
    /// - `key = on/off` - Returns `OnOff` with boolean flag
    /// - `command arg1 arg2 ...` - Returns `Command` with arguments
    ///
    /// # Arguments
    ///
    /// * `line` - The trimmed line to parse.
    /// * `_path` - Path to the file (used for error context, currently unused).
    ///
    /// # Returns
    ///
    /// `Some(WgetrcCommand)` if the line is valid, `None` if empty or invalid.
    fn parse_line(line: &str, _path: &Path) -> Option<WgetrcCommand> {
        if let Some(idx) = line.find('=') {
            let key = line[..idx].trim().to_string();
            let value = line[idx + 1..].trim().to_string();
            if key.is_empty() {
                return None;
            }

            if value.eq_ignore_ascii_case("on") {
                Some(WgetrcCommand::OnOff(key, true))
            } else if value.eq_ignore_ascii_case("off") {
                Some(WgetrcCommand::OnOff(key, false))
            } else {
                Some(WgetrcCommand::Set(key, value))
            }
        } else {
            let parts: Vec<String> = line.split_whitespace().map(String::from).collect();
            if parts.is_empty() {
                None
            } else {
                Some(WgetrcCommand::Command(parts[0].clone(), parts[1..].to_vec()))
            }
        }
    }

    /// Apply a list of parsed commands to a configuration object.
    ///
    /// Iterates through all commands and applies each one to the config.
    /// Commands are applied in order; later commands override earlier ones.
    ///
    /// # Arguments
    ///
    /// * `commands` - Slice of parsed commands to apply.
    /// * `config` - Mutable reference to the configuration to modify.
    ///
    /// # Returns
    ///
    /// `Ok(())` if all commands were applied successfully.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if any command fails to apply.
    pub fn apply(commands: &[WgetrcCommand], config: &mut ut_core::Config) -> Result<(), ConfigError> {
        for cmd in commands {
            Self::apply_command(cmd, config)?;
        }
        Ok(())
    }

    /// Apply a single command to the configuration.
    ///
    /// Dispatches to the appropriate handler based on command type.
    ///
    /// # Arguments
    ///
    /// * `cmd` - The command to apply.
    /// * `config` - Mutable reference to the configuration to modify.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if the command fails to apply.
    fn apply_command(cmd: &WgetrcCommand, config: &mut ut_core::Config) -> Result<(), ConfigError> {
        match cmd {
            WgetrcCommand::Set(key, value) => Self::apply_set(key, value, config),
            WgetrcCommand::OnOff(key, flag) => Self::apply_onoff(key, *flag, config),
            WgetrcCommand::Command(key, args) => Self::apply_cmd(key, args, config),
        }
    }

    /// Apply a key-value setting to the configuration.
    ///
    /// Handles string and numeric settings like `dir_prefix`, `user_agent`,
    /// `tries`, `timeout`, etc. The key is matched case-insensitively.
    ///
    /// # Arguments
    ///
    /// * `key` - The setting name (case-insensitive).
    /// * `value` - The setting value as a string.
    /// * `config` - Mutable reference to the configuration to modify.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the setting was applied successfully.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::InvalidValue` if the value cannot be parsed
    /// (e.g., non-numeric value for a numeric setting).
    ///
    /// # Supported Keys
    ///
    /// - `dir_prefix`, `directory_prefix` - Download directory
    /// - `output_document` - Output file name
    /// - `input_file` - Input URL file
    /// - `user_agent` - HTTP User-Agent header
    /// - `http_user`, `http_password` - HTTP credentials
    /// - `ftp_user`, `ftp_password` - FTP credentials
    /// - `tries` - Number of retries
    /// - `timeout`, `connect_timeout`, `read_timeout`, `dns_timeout` - Timeouts
    /// - `accept`, `reject` - File pattern lists
    /// - And many more...
    pub fn apply_set(key: &str, value: &str, config: &mut ut_core::Config) -> Result<(), ConfigError> {
        let key = key.to_ascii_lowercase();
        let key = normalize_wgetrc_key(&key);

        match key.as_str() {
            "directory_prefix" => {
                config.dir_prefix = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "output_document" => {
                config.output_document = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "input_file" => {
                config.input_filename = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "user_agent" | "user-agent" | "useragent" => {
                config.http.user_agent = Some(value.to_string());
            }
            "http_user" | "http-user" => {
                config.http.user = Some(value.to_string());
            }
            "http_password" | "http-password" => {
                config.http.password = Some(value.to_string());
            }
            "ftp_user" | "ftp-user" => {
                config.ftp.user = Some(value.to_string());
            }
            "ftp_password" | "ftp-password" => {
                config.ftp.password = Some(value.to_string());
            }
            "proxy_user" | "proxy-user" => {
                config.proxy.proxy_user = Some(value.to_string());
            }
            "proxy_password" | "proxy-password" => {
                config.proxy.proxy_password = Some(value.to_string());
            }
            "http_proxy" | "http-proxy" => {
                config.proxy.http_proxy = Some(value.to_string());
            }
            "https_proxy" | "https-proxy" => {
                config.proxy.https_proxy = Some(value.to_string());
            }
            "ftp_proxy" | "ftp-proxy" => {
                config.proxy.ftp_proxy = Some(value.to_string());
            }
            "no_proxy" | "no-proxy" => {
                config.proxy.no_proxy = value.split(',').map(String::from).collect();
            }
            "bind_address" | "bind-address" => {
                config.bind_address = Some(value.to_string());
            }
            "secure_protocol" | "secure-protocol" => {
                config.tls.secure_protocol = parse_secure_protocol(value)?;
            }
            "ciphers" => {
                config.tls.ciphers = Some(value.to_string());
            }
            "ca_certificate" | "ca-certificate" => {
                config.tls.ca_cert = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "ca_directory" | "ca-directory" => {
                config.tls.ca_directory = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "certificate" => {
                config.tls.cert_file = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "private_key" => {
                config.tls.private_key = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "crl_file" | "crl-file" => {
                config.tls.crl_file = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "pinnedpubkey" => {
                config.tls.pinned_pubkey = Some(value.to_string());
            }
            "quota" => {
                config.quota = ut_core::utils::parse_size_string(value);
            }
            "limit_rate" | "limit-rate" => {
                config.limit_rate = ut_core::utils::parse_size_string(value);
            }
            "tries" => {
                config.tries = value.parse().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "not a number".to_string(),
                })?;
            }
            "timeout" => {
                config.timeout = parse_duration(value)?;
            }
            "connect_timeout" | "connect-timeout" => {
                config.connect_timeout = parse_duration(value)?;
            }
            "read_timeout" | "read-timeout" => {
                config.read_timeout = parse_duration(value)?;
            }
            "dns_timeout" | "dns-timeout" => {
                config.dns_timeout = parse_duration(value)?;
            }
            "wait" => {
                config.wait = parse_duration(value)?;
            }
            "waitretry" | "wait_retry" => {
                config.wait_retry = parse_duration(value)?;
            }
            "level" => {
                let level: u32 = value.parse().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "not a number".to_string(),
                })?;
                // -l 0 means unlimited depth (like original wget)
                config.recursive.max_level = if level == 0 { None } else { Some(level) };
            }
            "cut_dirs" | "cut-dirs" => {
                config.cut_dirs = value.parse().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "not a number".to_string(),
                })?;
            }
            "max_redirect" | "max-redirect" => {
                config.max_redirect = value.parse().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "not a number".to_string(),
                })?;
            }
            "accept" => {
                config.recursive.accept_patterns = value.split(',').map(String::from).collect();
            }
            "reject" => {
                config.recursive.reject_patterns = value.split(',').map(String::from).collect();
            }
            "accept_regex" | "accept-regex" => {
                config.recursive.accept_regex = Some(value.to_string());
            }
            "reject_regex" | "reject-regex" => {
                config.recursive.reject_regex = Some(value.to_string());
            }
            "domains" => {
                config.recursive.domains = value.split(',').map(String::from).collect();
            }
            "exclude_domains" | "exclude-domains" => {
                config.recursive.exclude_domains = value.split(',').map(String::from).collect();
            }
            "include_directories" | "include-directories" => {
                config.recursive.include_directories = value.split(',').map(String::from).collect();
            }
            "exclude_directories" | "exclude-directories" => {
                config.recursive.exclude_directories = value.split(',').map(String::from).collect();
            }
            "follow_tags" | "follow-tags" => {
                config.recursive.follow_tags = value.split(',').map(String::from).collect();
            }
            "ignore_tags" | "ignore-tags" => {
                config.recursive.ignore_tags = value.split(',').map(String::from).collect();
            }
            "load_cookies" | "load-cookies" => {
                config.cookie.input_file = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "save_cookies" | "save-cookies" => {
                config.cookie.output_file = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "invalid path".to_string(),
                })?);
            }
            "hsts_file" | "hsts-file" => {
                #[cfg(feature = "hsts")]
                {
                    config.hsts.file = Some(value.parse::<std::path::PathBuf>().map_err(|_| ConfigError::InvalidValue {
                        option: key.to_string(),
                        reason: "invalid path".to_string(),
                    })?);
                }
            }
            "default_page" | "default-page" => {
                config.http.default_page = value.to_string();
            }
            "warc_file" | "warc-file" => {
                config.warc.filename = Some(value.to_string());
            }
            "warc_maxsize" | "warc-maxsize" => {
                config.warc.max_size = value.parse().ok();
            }
            "prefer_family" | "prefer-family" => {
                config.prefer_family = parse_address_family(value)?;
            }
            "header" => {
                config.http.headers.push(value.to_string());
            }
            "post_data" | "post-data" => {
                config.http.post_data = Some(value.as_bytes().to_vec());
            }
            "method" => {
                config.http.method = Some(value.parse().map_err(|_| ConfigError::InvalidValue {
                    option: key.to_string(),
                    reason: "unsupported method".to_string(),
                })?);
            }
            "body_data" | "body-data" => {
                config.http.body_data = Some(value.as_bytes().to_vec());
            }
            _ => {}
        }
        Ok(())
    }

    /// Apply a boolean toggle setting to the configuration.
    ///
    /// Handles settings like `verbose = on`, `quiet = off`, etc.
    /// The key is matched case-insensitively.
    ///
    /// # Arguments
    ///
    /// * `key` - The setting name (case-insensitive).
    /// * `flag` - The boolean value (`true` for "on", `false` for "off").
    /// * `config` - Mutable reference to the configuration to modify.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the setting was applied successfully.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if the setting is invalid (currently always returns Ok).
    ///
    /// # Supported Keys
    ///
    /// - `verbose` - Verbosity level
    /// - `quiet` - Suppress output
    /// - `timestamping` - Use If-Modified-Since
    /// - `noclobber` - Don't overwrite existing files
    /// - `continue` - Resume partial downloads
    /// - `recursive` - Enable recursive download
    /// - `convert_links` - Convert links for local viewing
    /// - `check_certificate` - Verify SSL/TLS certificates
    /// - `use_proxy` - Enable proxy usage
    /// - `cookies` - Enable cookie handling
    /// - And many more...
    pub fn apply_onoff(key: &str, flag: bool, config: &mut ut_core::Config) -> Result<(), ConfigError> {
        let key = key.to_ascii_lowercase();

        match key.as_str() {
            "verbose" => {
                if flag {
                    config.verbose = config.verbose.max(1);
                } else {
                    config.verbose = 0;
                }
            }
            "quiet" => {
                config.quiet = flag;
            }
            "timestamping" => {
                config.timestamping = flag;
            }
            "noclobber" | "no_clobber" | "no-clobber" => {
                config.noclobber = flag;
            }
            "continue_download" | "continue-download" | "continue" => {
                config.continue_download = flag;
            }
            "background" => {
                config.background = flag;
            }
            "debug" => {
                config.debug = flag;
            }
            "server_response" | "server-response" => {
                config.server_response = flag;
            }
            "force_html" | "force-html" => {
                config.force_html = flag;
            }
            "recursive" => {
                config.recursive.enabled = flag;
            }
            "page_requisites" | "page-requisites" => {
                config.page_requisites = flag;
            }
            "delete_after" | "delete-after" => {
                config.delete_after = flag;
            }
            "convert_links" | "convert-links" => {
                config.convert_links = flag;
            }
            "backup_converted" | "backup-converted" => {
                config.backup_converted = flag;
            }
            "adjust_extension" | "adjust-extension" => {
                config.adjust_extension = flag;
            }
            "random_wait" | "random-wait" => {
                config.random_wait = flag;
            }
            "retry_connrefused" | "retry-connrefused" => {
                config.retry_connrefused = flag;
            }
            "spider" => {
                config.recursive.spider = flag;
            }
            "content_disposition" | "content-disposition" => {
                config.content_disposition = flag;
            }
            "auth_without_challenge" | "auth-without-challenge" | "auth_no_challenge" => {
                config.auth_without_challenge = flag;
            }
            "if_modified_since" | "if-modified-since" => {
                config.if_modified_since = flag;
            }
            "use_server_timestamps" | "use-server-timestamps" => {
                config.use_server_timestamps = flag;
            }
            "save_headers" | "save-headers" => {
                config.http.save_headers = flag;
            }
            "content_on_error" | "content-on-error" => {
                config.http.content_on_error = flag;
            }
            "https_only" | "https-only" => {
                config.http.https_only = flag;
            }
            "span_hosts" | "span-hosts" => {
                config.recursive.span_hosts = flag;
            }
            "relative" => {
                config.recursive.relative_only = flag;
            }
            "no_parent" | "no-parent" => {
                config.recursive.no_parent = flag;
            }
            "follow_ftp" | "follow-ftp" => {
                config.ftp.follow_ftp = flag;
            }
            "no_host_directories" | "no-host-directories" => {
                config.no_host_directories = flag;
            }
            "protocol_directories" | "protocol-directories" => {
                config.protocol_directories = flag;
            }
            "check_certificate" | "check-certificate" => {
                config.tls.check_certificate = if flag {
                    ut_core::CheckCertMode::On
                } else {
                    ut_core::CheckCertMode::Off
                };
            }
            "keep_alive" | "keep-alive" | "http_keep_alive" => {
                config.http.keep_alive = flag;
            }
            "cookies" => {
                config.cookie.enabled = flag;
            }
            "keep_session_cookies" | "keep-session-cookies" => {
                config.cookie.keep_session_cookies = flag;
            }
            "glob" => {
                config.ftp.glob = flag;
            }
            "passive_ftp" | "passive-ftp" => {
                config.ftp.passive = flag;
            }
            "remove_listing" | "remove-listing" => {
                config.ftp.remove_listing = flag;
            }
            "retrieve_symlinks" | "retr-symlinks" | "retr_symlinks" => {
                config.ftp.retrieve_symlinks = flag;
            }
            "htmlify" => {
                config.ftp.htmlify = flag;
            }
            "use_proxy" | "use-proxy" => {
                config.proxy.use_proxy = flag;
            }
            "dns_cache" => {
                if !flag {
                    // no_dns_cache handled at app level
                }
            }
            "no_hsts" | "no-hsts" => {
                #[cfg(feature = "hsts")]
                {
                    config.hsts.enabled = !flag;
                }
            }
            "robots" => {
                config.recursive.use_robots = flag;
            }
            "trust_server_names" | "trust-server-names" => {
                // handled at app level
            }
            _ => {}
        }
        Ok(())
    }

    /// Apply a command-style setting to the configuration.
    ///
    /// Handles settings specified as `command arg1 arg2 ...` rather than
    /// `key = value`. Currently supports limited command-style syntax.
    ///
    /// # Arguments
    ///
    /// * `key` - The command name.
    /// * `args` - The command arguments.
    /// * `_config` - Mutable reference to the configuration (currently unused).
    ///
    /// # Returns
    ///
    /// `Ok(())` if the command was applied successfully.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if the command is invalid.
    fn apply_cmd(key: &str, args: &[String], _config: &mut ut_core::Config) -> Result<(), ConfigError> {
        let key = key.to_ascii_lowercase();
        match key.as_str() {
            "accept" | "reject" | "include_directories" | "exclude_directories" => {
                if args.len() == 1 {
                    let mut cfg = ut_core::Config::default();
                    Self::apply_set(&key, args[0].as_str(), &mut cfg)?;
                    return Ok(());
                }
            }
            _ => {}
        }
        Ok(())
    }
}
