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
