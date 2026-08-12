//! FTP client implementation.
//!
//! This module provides a complete FTP client for file transfer operations.
//! It supports both active and passive mode, IPv4 and IPv6, and various
//! FTP commands for file and directory operations.
//!
//! # Example
//!
//! ```no_run
//! use utwget_ftp::client::FtpClient;
//!
//! let mut client = FtpClient::new();
//! client.connect("ftp.example.com", 21).unwrap();
//! client.login("user", "password").unwrap();
//! client.type_binary().unwrap();
//! // ... perform operations
//! client.quit().unwrap();
//! ```

use std::io::{self, Read, Write};

use crate::command::{FtpCommand, FtpCommandError, FtpResponse, Transport};
use crate::data_conn::{self, DataConnection};
use crate::listing::{parse_listing, FtpEntry};

/// Errors that can occur during FTP operations.
///
/// This enum covers all possible error conditions when using the FTP client,
/// including connection failures, authentication issues, command errors,
/// and I/O problems.
#[derive(Debug, thiserror::Error)]
pub enum FtpError {
    /// Failed to establish a connection to the FTP server.
    #[error("connection error: {0}")]
    Connect(String),
    /// The server refused the login attempt.
    #[error("login refused: {0}")]
    LoginRefused(String),
    /// An FTP command failed with a negative response.
    #[error("command failed ({code}): {message}")]
    CommandFailed { code: u16, message: String },
    /// Failed to establish a data connection for file transfer.
    #[error("data connection failed: {0}")]
    DataConnectFailed(String),
    /// File transfer operation failed.
    #[error("transfer failed: {0}")]
    TransferFailed(String),
    /// The requested file was not found on the server.
    #[error("file not found: {0}")]
    FileNotFound(String),
    /// Failed to parse server response or URL.
    #[error("parse error: {0}")]
    ParseError(String),
    /// An I/O error occurred during the operation.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// An FTP protocol error occurred.
    #[error("FTP protocol error: {0}")]
    Protocol(#[from] FtpCommandError),
}

impl From<ut_core::WgetError> for FtpError {
    fn from(e: ut_core::WgetError) -> Self {
        FtpError::Connect(e.to_string())
    }
}

/// Result of fetching metadata from an FTP URL.
///
/// Contains information about the remote resource including whether it's
/// a directory or file, its size, modification time, and directory listing
/// if applicable.
#[derive(Debug)]
pub struct FtpFetchResult {
    /// FTP status code from the operation.
    pub status_code: u16,
    /// Size of the file in bytes, if known.
    pub content_length: Option<u64>,
    /// Content type (e.g., "application/octet-stream" for files,
    /// "text/ftp; type=directory" for directories).
    pub content_type: Option<String>,
    /// Last modification time of the resource.
    pub last_modified: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether the resource is a directory.
    pub is_directory: bool,
    /// Directory listing entries, if the resource is a directory.
    pub file_list: Option<Vec<FtpEntry>>,
}

/// FTP client for file transfer operations.
///
/// This struct manages an FTP control connection and provides methods
/// for all standard FTP operations including file transfer, directory
/// navigation, and file management.
///
/// The client supports both passive (PASV/EPSV) and active (PORT/EPRT)
/// modes, with passive mode being the default. It also handles both
/// IPv4 and IPv6 connections automatically.
pub struct FtpClient {
    /// Control connection transport.
    ctrl: Option<Box<dyn Transport<Error = io::Error>>>,
    /// Connected host name.
    host: Option<String>,
    /// Whether to use passive mode for data connections.
    passive: bool,
    /// Whether the connection is over IPv6.
    is_ipv6: bool,
    /// Whether binary (image) mode is active.
    binary: bool,
    /// Current working directory on the server.
    current_dir: String,
}
