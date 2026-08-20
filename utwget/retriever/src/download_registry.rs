//! Download registry for tracking downloaded files and URL redirections.
//!
//! This module provides the `DownloadRegistry` struct which maintains mappings
//! between URLs and local file paths, as well as tracking HTTP redirections
//! to ensure proper link conversion during recursive downloads.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Registry for tracking downloaded files and URL redirections.
///
/// The `DownloadRegistry` maintains three key mappings:
/// - Direct downloads: URL → local file path
/// - Redirections: source URL → target URL
/// - Combined mapping: URL → local file path (including redirected URLs)
///
/// This is essential for recursive downloads where links need to be converted
/// from absolute URLs to relative local paths.
///
/// # Example
///
/// ```
/// use ut_retriever::DownloadRegistry;
/// use std::path::PathBuf;
///
/// let mut registry = DownloadRegistry::new();
/// registry.register_download("http://example.com/file.html", &PathBuf::from("file.html"));
/// registry.register_redirection("http://example.com/old", "http://example.com/file.html");
///
/// assert!(registry.is_downloaded("http://example.com/file.html"));
/// assert!(registry.is_visited("http://example.com/old"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct DownloadRegistry {
    /// Direct downloads: normalized URL → local file path.
    downloads: HashMap<String, PathBuf>,
    /// Redirections: normalized source URL → normalized target URL.
    redirections: HashMap<String, String>,
    /// Combined mapping: normalized URL → local file path (including redirected URLs).
    url_to_local: HashMap<String, PathBuf>,
}
