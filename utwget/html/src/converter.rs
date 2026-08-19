//! Link converter for transforming URLs in HTML documents.
//!
//! This module provides functionality to convert absolute URLs in HTML documents
//! to relative or local paths after recursive downloading, enabling offline
//! browsing of mirrored sites.

use std::sync::{Arc, Mutex};

use lol_html::element;
use lol_html::{HtmlRewriter, Settings, MemorySettings};


/// Errors that can occur during link conversion.
///
/// These errors cover file operations, HTML rewriting, and backup operations.
#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    /// I/O error during file read/write operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Error during HTML rewriting process.
    #[error("HTML rewrite error: {0}")]
    Rewrite(String),

    /// Error acquiring a lock on shared state.
    #[error("lock error: {0}")]
    Lock(String),

    /// The specified file was not found.
    #[error("file not found: {path}")]
    FileNotFound {
        /// Path to the file that was not found.
        path: String
    },

    /// Failed to create a backup of the original file.
    #[error("backup failed: {0}")]
    BackupFailed(String),
}
