//! Error types for utwget.
//!
//! This module defines all error types used throughout the application,
//! including network errors, TLS errors, FTP errors, and configuration errors.

use std::path::PathBuf;
use std::time::Duration;

/// Main error type for wget operations.
///
/// Represents all possible errors that can occur during download operations,
/// including network, TLS, HTTP, FTP, and file system errors.
#[derive(Debug, thiserror::Error)]
pub enum WgetError {
    /// DNS resolution failed for the given hostname.
    #[error("host not found: {0}")]
    HostNotFound(String),

    /// Connection was refused by the remote host.
    #[error("connection refused")]
    ConnectionRefused,

    /// Connection attempt timed out.
    #[error("connection timed out after {0:?}")]
    ConnectionTimeout(Duration),

    /// Socket I/O error.
    #[error("socket error: {0}")]
    SocketError(#[from] std::io::Error),

    /// TLS/SSL error.
    #[error("TLS error: {0}")]
    Tls(#[from] TlsError),

    /// Certificate verification failed.
    #[error("certificate verification failed for {host}")]
    CertVerificationFailed { host: String },

    /// TLS initialization failed.
    #[error("TLS initialization failed")]
    TlsInitFailed,

    /// HTTP error response.
    #[error("HTTP {status}: {message}")]
    Http { status: u16, message: String },

    /// Too many HTTP redirects encountered.
    #[error("too many redirects (>{max})")]
    TooManyRedirects { max: u32 },

    /// Authentication failed.
    #[error("authentication failed for {0}")]
    AuthFailed(String),

    /// Unsupported HTTP method.
    #[error("unsupported HTTP method: {0}")]
    UnsupportedMethod(String),

    /// FTP protocol error.
    #[error("FTP error: {0}")]
    Ftp(#[from] FtpError),

    /// FTP login was refused.
    #[error("FTP login refused")]
    FtpLoginRefused,

    /// FTP server returned an error.
    #[error("FTP server error: {0}")]
    FtpServerError(String),

    /// FTP file not found.
    #[error("FTP file not found: {0}")]
    FtpFileNotFound(String),

    /// Local file not found.
    #[error("file not found: {0}")]
    FileNotFound(PathBuf),

    /// File already exists (noclobber mode).
    #[error("file already exists (noclobber): {0}")]
    FileExists(PathBuf),

    /// Cannot create directory.
    #[error("cannot create directory: {0}")]
    CannotCreateDir(PathBuf),

    /// File write error.
    #[error("write error: {0}")]
    WriteError(#[source] std::io::Error),

    /// URL parsing failed.
    #[error("URL parse error: {0}")]
    UrlParse(String),

    /// Unsupported URL scheme.
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),

    /// Download quota exceeded.
    #[error("quota exceeded: downloaded {downloaded}, limit {quota}")]
    QuotaExceeded { downloaded: u64, quota: u64 },

    /// Maximum retry count exceeded.
    #[error("retry limit exceeded ({tries} tries)")]
    RetryLimitExceeded { tries: u32 },

    /// Metalink file parsing failed.
    #[error("metalink parse error: {0}")]
    MetalinkParse(String),

    /// Metalink download failed.
    #[error("metalink download error: {0}")]
    MetalinkDownload(String),

    /// Metalink checksum verification failed.
    #[error("metalink checksum mismatch: expected {expected}, got {actual}")]
    MetalinkChecksum { expected: String, actual: String },

    /// WARC archive error.
    #[error("WARC error: {0}")]
    Warc(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Generic error with message.
    #[error("{0}")]
    Other(String),
}

/// Result type alias for wget operations.
pub type Result<T> = std::result::Result<T, WgetError>;

/// TLS/SSL related errors.
///
/// Represents errors that can occur during TLS handshake, certificate
/// verification, or secure communication.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    HandshakeFailed(String),

    /// Certificate validation error.
    #[error("certificate error: {0}")]
    CertError(String),

    /// Invalid certificate file.
    #[error("invalid certificate file: {0}")]
    InvalidCertFile(PathBuf),

    /// Invalid private key file.
    #[error("invalid private key file: {0}")]
    InvalidKeyFile(PathBuf),

    /// Unsupported TLS protocol version.
    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocol(String),

    /// Cipher suite negotiation error.
    #[error("cipher suite error: {0}")]
    CipherError(String),

    /// Certificate hostname mismatch.
    #[error("hostname mismatch: expected {expected}, got {got}")]
    HostnameMismatch { expected: String, got: String },

    /// Certificate has expired.
    #[error("certificate expired")]
    CertExpired,

    /// Certificate is not yet valid.
    #[error("certificate not yet valid")]
    CertNotYetValid,

    /// Self-signed certificate encountered.
    #[error("self-signed certificate")]
    SelfSigned,

    /// Certificate signed by unknown authority.
    #[error("unknown authority: {0}")]
    UnknownAuthority(String),

    /// TLS I/O error.
    #[error("TLS I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// FTP protocol errors.
///
/// Represents errors that can occur during FTP operations,
/// including connection issues and protocol violations.
#[derive(Debug, thiserror::Error)]
pub enum FtpError {
    /// Unexpected FTP response code.
    #[error("FTP unexpected response: {code} {message}")]
    UnexpectedResponse { code: u16, message: String },

    /// FTP connection was lost.
    #[error("FTP connection lost")]
    ConnectionLost,

    /// FTP data connection failed.
    #[error("FTP data connection failed: {0}")]
    DataConnectionFailed(String),

    /// PASV (passive) mode failed.
    #[error("FTP PASV mode failed: {0}")]
    PasvFailed(String),

    /// PORT (active) mode failed.
    #[error("FTP PORT mode failed: {0}")]
    PortFailed(String),

    /// FTP command syntax error.
    #[error("FTP syntax error: {0}")]
    SyntaxError(String),

    /// FTP I/O error.
    #[error("FTP I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration errors.
///
/// Represents errors that can occur when parsing or applying
/// configuration settings.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Unknown configuration option.
    #[error("unknown config option: {0}")]
    UnknownOption(String),

    /// Invalid value for a configuration option.
    #[error("invalid value for '{option}': {reason}")]
    InvalidValue { option: String, reason: String },

    /// Error reading configuration file.
    #[error("config file error at {path}: {reason}")]
    FileError { path: PathBuf, reason: String },

    /// Failed to read configuration file.
    #[error("cannot read config file: {0}")]
    ReadFailed(#[source] std::io::Error),

    /// Duplicate configuration option.
    #[error("duplicate config option: {0}")]
    DuplicateOption(String),

    /// Required option is missing.
    #[error("missing required option: {0}")]
    MissingOption(String),
}

impl WgetError {
    /// Determines if the error is retryable.
    ///
    /// Some errors (like connection refused, timeouts, or server errors)
    /// may succeed on retry, while others (like file not found or
    /// authentication failures) will likely fail again.
    ///
    /// # Returns
    ///
    /// `true` if the operation might succeed on retry, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use ut_core::error::WgetError;
    ///
    /// let err = WgetError::ConnectionRefused;
    /// assert!(err.is_retryable());
    ///
    /// let err = WgetError::AuthFailed("example.com".to_string());
    /// assert!(!err.is_retryable());
    /// ```
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            WgetError::ConnectionRefused
                | WgetError::ConnectionTimeout(_)
                | WgetError::SocketError(_)
                | WgetError::Tls(TlsError::HandshakeFailed(_))
                | WgetError::Http { status: 500..=599, .. }
                | WgetError::Ftp(FtpError::UnexpectedResponse { .. })
                | WgetError::Ftp(FtpError::ConnectionLost)
                | WgetError::TooManyRedirects { .. }
        )
    }
}
