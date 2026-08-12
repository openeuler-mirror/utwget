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
