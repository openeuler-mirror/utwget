//! Verbose progress display implementation.
//!
//! This module provides a detailed progress display that outputs comprehensive
//! information about the download process, including timestamps, URLs, file sizes,
//! content types, and transfer statistics. This is similar to the output format
//! of the original GNU wget in verbose mode.
//!
//! # Output Format
//!
//! ```text
//! --2026-06-17 10:30:00--  http://example.com/file.tar.gz
//! Resolving... connecting...
//! length: 12345678 (12345678) [application/gzip]
//! Saving to: ...
//!
//! --2026-06-17 10:30:05--  finished
//! `http://example.com/file.tar.gz' saved [12345678]
//! Downloaded: 12345678 in 5s (2469135.60 B/s)
//! ```

use crate::{FinishStatus, ProgressDisplay};
use chrono::Local;
use std::io::{self, Write};
use std::time::{Duration, Instant};

/// A verbose progress display that provides detailed download information.
///
/// This display outputs comprehensive information about the download process,
/// including timestamps, URLs, content types, file sizes, and transfer
/// statistics. It is designed to match the output format of GNU wget's
/// verbose mode.
///
/// # Fields
///
/// - `url`: The URL being downloaded
/// - `total_size`: The expected total file size (if known)
/// - `downloaded`: The number of bytes downloaded so far
/// - `start_time`: When the download started
/// - `content_type`: The MIME type of the downloaded content
/// - `finished`: Whether the download has completed
///
/// # Example
///
/// ```
/// use utwget_progress::VerboseProgress;
/// use utwget_progress::ProgressDisplay;
///
/// let mut progress = VerboseProgress::new();
/// progress.set_content_type("application/octet-stream");
/// progress.begin("http://example.com/file", Some(1000), None);
/// ```
pub struct VerboseProgress {
    url: String,
    total_size: Option<u64>,
    downloaded: u64,
    start_time: Instant,
    content_type: Option<String>,
    finished: bool,
}

impl VerboseProgress {
    /// Creates a new `VerboseProgress` instance.
    ///
    /// Initializes a new verbose progress display with default values.
    /// The start time is set to the current instant, and all other
    /// fields are initialized to their empty/default states.
    ///
    /// # Returns
    ///
    /// A new `VerboseProgress` instance ready for use.
    ///
    /// # Example
    ///
    /// ```
    /// use utwget_progress::VerboseProgress;
    /// let progress = VerboseProgress::new();
    /// ```
    pub fn new() -> Self {
        VerboseProgress {
            url: String::new(),
            total_size: None,
            downloaded: 0,
            start_time: Instant::now(),
            content_type: None,
            finished: false,
        }
    }

    /// Sets the content type for the download.
    ///
    /// The content type is displayed in the verbose output when the
    /// download begins, showing the MIME type of the content being
    /// downloaded (e.g., "application/gzip", "text/html").
    ///
    /// # Arguments
    ///
    /// * `ct` - The content type string (MIME type) to set.
    ///
    /// # Example
    ///
    /// ```
    /// use utwget_progress::VerboseProgress;
    /// let mut progress = VerboseProgress::new();
    /// progress.set_content_type("application/json");
    /// ```
    pub fn set_content_type(&mut self, ct: &str) {
        self.content_type = Some(ct.to_string());
    }

    /// Generates a timestamp string for the current time.
    ///
    /// Returns the current local time formatted as "YYYY-MM-DD HH:MM:SS",
    /// which is used in the verbose output to mark the start and end
    /// of downloads.
    ///
    /// # Returns
    ///
    /// A formatted timestamp string.
    fn timestamp_str() -> String {
        Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }

    /// Returns the content type string for display.
    ///
    /// If a content type has been set, returns it; otherwise returns
    /// "unspecified" to indicate the content type is unknown.
    ///
    /// # Returns
    ///
    /// The content type string or "unspecified".
    fn content_type_str(&self) -> &str {
        self.content_type.as_deref().unwrap_or("unspecified")
    }

    /// Returns the total file size string for display.
    ///
    /// If the total size is known, returns it as a string; otherwise
    /// returns "unspecified" to indicate the size is unknown.
    ///
    /// # Returns
    ///
    /// The file size as a string or "unspecified".
    fn length_str(&self) -> String {
        match self.total_size {
            Some(size) => format!("{}", size),
            None => "unspecified".to_string(),
        }
    }
}
