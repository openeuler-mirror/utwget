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

/// Options controlling link conversion behavior.
///
/// These options determine how URLs in HTML documents are transformed
/// during the link conversion process.
#[derive(Debug, Clone)]
pub struct ConvertOptions {
    /// Convert absolute URLs to relative paths.
    ///
    /// When true, absolute URLs pointing to downloaded resources are
    /// converted to relative paths for offline browsing.
    pub convert_to_relative: bool,

    /// Only convert the file portion of URLs, keeping the host intact.
    ///
    /// When true, only the path component of URLs is converted,
    /// preserving the original host and scheme.
    pub convert_file_only: bool,

    /// Remove `<base>` elements from the document.
    ///
    /// When true, `<base href="...">` elements are removed to prevent
    /// conflicts with converted relative paths.
    pub nullify_base: bool,

    /// Create backup files before conversion.
    ///
    /// When true, original files are backed up with a `.orig` extension
    /// before being modified.
    pub backup_converted: bool,
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            convert_to_relative: true,
            convert_file_only: false,
            nullify_base: true,
            backup_converted: false,
        }
    }
}
