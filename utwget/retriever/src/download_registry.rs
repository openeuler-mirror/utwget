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

impl DownloadRegistry {
    /// Create a new empty download registry.
    ///
    /// # Returns
    ///
    /// A new `DownloadRegistry` instance with empty mappings.
    pub fn new() -> Self {
        DownloadRegistry {
            downloads: HashMap::new(),
            redirections: HashMap::new(),
            url_to_local: HashMap::new(),
        }
    }

    /// Register a successful download mapping a URL to a local file path.
    ///
    /// The URL is normalized (fragment removed) before being stored.
    /// Both the `downloads` and `url_to_local` maps are updated.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL that was downloaded.
    /// * `local_file` - The local filesystem path where the file was saved.
    pub fn register_download(&mut self, url: &str, local_file: &Path) {
        let normalized = normalize_url(url);
        self.downloads.insert(normalized.clone(), local_file.to_path_buf());
        self.url_to_local.insert(normalized, local_file.to_path_buf());
    }

    /// Register a URL redirection from one URL to another.
    ///
    /// When a URL redirects to another URL that has already been downloaded,
    /// the source URL is mapped to the same local file as the target URL.
    /// This enables proper link conversion for redirected resources.
    ///
    /// # Arguments
    ///
    /// * `from` - The source URL that redirected.
    /// * `to` - The target URL of the redirection.
    pub fn register_redirection(&mut self, from: &str, to: &str) {
        let normalized_from = normalize_url(from);
        let normalized_to = normalize_url(to);
        if let Some(local) = self.downloads.get(&normalized_to).cloned() {
            self.url_to_local.insert(normalized_from.clone(), local);
        }
        self.redirections.insert(normalized_from, normalized_to);
    }

    /// Get the local file path for a URL, if it has been downloaded.
    ///
    /// This checks the combined `url_to_local` map, which includes both
    /// direct downloads and redirected URLs.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to look up.
    ///
    /// # Returns
    ///
    /// `Some(&PathBuf)` if the URL has been downloaded, `None` otherwise.
    pub fn get_local(&self, url: &str) -> Option<&PathBuf> {
        self.url_to_local.get(&normalize_url(url))
    }

    /// Check if a URL has been directly downloaded.
    ///
    /// This only checks the `downloads` map, not redirections.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to check.
    ///
    /// # Returns
    ///
    /// `true` if the URL has been downloaded, `false` otherwise.
    pub fn is_downloaded(&self, url: &str) -> bool {
        self.downloads.contains_key(&normalize_url(url))
    }

    /// Check if a URL has been visited (downloaded or redirected).
    ///
    /// This checks both the `downloads` and `redirections` maps.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to check.
    ///
    /// # Returns
    ///
    /// `true` if the URL has been visited, `false` otherwise.
    pub fn is_visited(&self, url: &str) -> bool {
        let normalized = normalize_url(url);
        self.downloads.contains_key(&normalized)
            || self.redirections.contains_key(&normalized)
    }

    /// Get a reference to the URL-to-local-path mapping.
    ///
    /// This returns the combined map including both direct downloads
    /// and redirected URLs.
    ///
    /// # Returns
    ///
    /// A reference to the internal `HashMap<String, PathBuf>`.
    pub fn url_to_local_map(&self) -> &HashMap<String, PathBuf> {
        &self.url_to_local
    }

    /// Get all URL to local path mappings as owned HashMap with String values.
    ///
    /// This is useful for serialization or when owned data is needed.
    /// Path values are converted to strings using `to_string_lossy()`.
    ///
    /// # Returns
    ///
    /// A `HashMap<String, String>` containing all URL-to-path mappings.
    pub fn get_all_mappings(&self) -> HashMap<String, String> {
        self.url_to_local
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string_lossy().to_string()))
            .collect()
    }

    /// Resolve a URL through any registered redirections.
    ///
    /// Follows the chain of redirections until a non-redirecting URL is found.
    /// Detects and breaks cycles to prevent infinite loops.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to resolve.
    ///
    /// # Returns
    ///
    /// `Some(String)` containing the final target URL if the input URL
    /// redirects, `None` if the URL does not redirect.
    pub fn resolve_redirect(&self, url: &str) -> Option<String> {
        let mut current = normalize_url(url);
        let mut seen = std::collections::HashSet::new();
        while let Some(target) = self.redirections.get(&current) {
            if seen.contains(target) {
                break;
            }
            seen.insert(target.clone());
            current = target.clone();
        }
        if current == normalize_url(url) {
            None
        } else {
            Some(current)
        }
    }
}
