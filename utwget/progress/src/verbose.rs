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
