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

/// Statistics from a link conversion operation.
///
/// Tracks the number of URLs that were converted, skipped, or already relative.
#[derive(Debug, Clone, Default)]
pub struct ConvertStats {
    /// Number of URLs successfully converted.
    pub converted: usize,
    /// Number of URLs skipped (not found in mapping).
    pub skipped: usize,
    /// Number of URLs that were already relative.
    pub already_relative: usize,
}

/// HTML link converter for transforming URLs to local paths.
///
/// This struct provides functionality to convert URLs in HTML documents
/// to relative or local paths, enabling offline browsing of downloaded sites.
///
/// # Example
///
/// ```ignore
/// use html::converter::{LinkConverter, ConvertOptions};
///
/// let converter = LinkConverter::new();
/// let url_map = HashMap::new();
/// // url_map.insert("http://example.com/page.html", "example.com/page.html");
///
/// let stats = converter.convert_links("index.html", &url_map, &ConvertOptions::default())?;
/// println!("Converted {} links", stats.converted);
/// ```
pub struct LinkConverter;

/// Mapping of HTML element names to their URL-containing attributes.
///
/// Each tuple represents (tag_name, attribute_name) where the attribute
/// contains a URL that should be converted.
const URL_ATTR_MAP: &[(&str, &str)] = &[
    ("a", "href"),
    ("area", "href"),
    ("link", "href"),
    ("img", "src"),
    ("script", "src"),
    ("iframe", "src"),
    ("frame", "src"),
    ("embed", "src"),
    ("object", "data"),
    ("source", "src"),
    ("track", "src"),
    ("video", "poster"),
    ("body", "background"),
    ("applet", "codebase"),
];

/// CSS selector for all elements with URL attributes.
///
/// This selector matches all elements that have URL-containing attributes
/// and should be processed during link conversion.
const CONVERT_SELECTOR: &str = concat!(
    "a[href], area[href], link[href], img[src], script[src], ",
    "iframe[src], frame[src], embed[src], object[data], ",
    "source[src], track[src], video[poster], body[background], ",
    "applet[codebase], base[href]"
);

impl LinkConverter {
    /// Creates a new link converter instance.
    ///
    /// # Returns
    ///
    /// A new `LinkConverter` instance.
    pub fn new() -> Self {
        Self
    }

    /// Converts URLs in an HTML file to local paths.
    ///
    /// This method reads an HTML file, finds all URL-containing attributes,
    /// and replaces URLs that exist in the mapping with their local paths.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the HTML file to convert.
    /// * `url_to_local` - Mapping from original URLs to local file paths.
    /// * `opts` - Options controlling conversion behavior.
    ///
    /// # Returns
    ///
    /// A `ConvertStats` struct containing conversion statistics, or a
    /// `ConvertError` if the operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file does not exist (`FileNotFound`)
    /// - The file cannot be read or written (`Io`)
    /// - HTML parsing fails (`Rewrite`)
    /// - Backup creation fails (`BackupFailed`)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let converter = LinkConverter::new();
    /// let mut url_map = HashMap::new();
    /// url_map.insert("http://example.com/style.css".to_string(), "example.com/style.css".to_string());
    ///
    /// let opts = ConvertOptions {
    ///     backup_converted: true,
    ///     ..Default::default()
    /// };
    ///
    /// let stats = converter.convert_links("index.html", &url_map, &opts)?;
    /// ```
    pub fn convert_links(
        &self,
        file_path: &str,
        url_to_local: &std::collections::HashMap<String, String>,
        opts: &ConvertOptions,
    ) -> Result<ConvertStats, ConvertError> {
        let path = std::path::Path::new(file_path);
        if !path.exists() {
            return Err(ConvertError::FileNotFound {
                path: file_path.to_string(),
            });
        }

        let content = std::fs::read_to_string(path)?;

        if opts.backup_converted {
            let backup_ext = path
                .extension()
                .map(|e| format!("{}.orig", e.to_string_lossy()))
                .unwrap_or_else(|| "orig".to_string());
            let backup_path = path.with_extension(&backup_ext);
            std::fs::copy(path, &backup_path).map_err(|e| {
                ConvertError::BackupFailed(format!(
                    "{} -> {}: {}",
                    path.display(),
                    backup_path.display(),
                    e
                ))
            })?;
        }

        let rewritten_content: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let rewrite_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));

        let url_to_local_clone = url_to_local.clone();
        let rewritten_a = rewritten_content.clone();
        let count_a = rewrite_count.clone();
        let nullify_base = opts.nullify_base;

        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![element!(CONVERT_SELECTOR, move |el| {
                    let tag = el.tag_name().to_lowercase();
                    let tag_str = tag.as_str();

                    if tag_str == "base" && nullify_base {
                        el.remove();
                        return Ok(());
                    }

                    if let Some(attr_name) =
                        URL_ATTR_MAP.iter().find(|(t, _)| *t == tag_str).map(|(_, a)| *a)
                    {
                        if let Some(original_url) = el.get_attribute(attr_name) {
                            let original_url = original_url.trim().to_string();
                            if original_url.starts_with('#')
                                || original_url.starts_with("javascript:")
                                || original_url.starts_with("data:")
                            {
                                return Ok(());
                            }

                            if let Some(local_path) = url_to_local_clone.get(&original_url) {
                                let _ = el.set_attribute(attr_name, local_path);
                                *count_a.lock().unwrap() += 1;
                            }
                        }
                    }

                    Ok(())
                })],
                memory_settings: MemorySettings::default(),
                ..Default::default()
            },
            {
                let out = rewritten_a.clone();
                move |chunk: &[u8]| {
                    out.lock().unwrap().extend_from_slice(chunk);
                }
            },
        );

        rewriter
            .write(content.as_bytes())
            .map_err(|e| ConvertError::Rewrite(e.to_string()))?;
        rewriter
            .end()
            .map_err(|e| ConvertError::Rewrite(e.to_string()))?;

        let rewritten = match Arc::try_unwrap(rewritten_content) {
            Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
            Err(arc) => arc.lock().unwrap().clone(),
        };

        let count = match Arc::try_unwrap(rewrite_count) {
            Ok(mutex) => mutex.into_inner().unwrap_or(0),
            Err(arc) => *arc.lock().unwrap(),
        };

        let output = String::from_utf8(rewritten)
            .map_err(|e| ConvertError::Rewrite(format!("utf8: {e}")))?;

        std::fs::write(path, output)?;

        let total_urls = url_to_local.len();
        Ok(ConvertStats {
            converted: count,
            skipped: total_urls.saturating_sub(count),
            already_relative: 0,
        })
    }
}
