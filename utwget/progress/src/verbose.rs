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

impl ProgressDisplay for VerboseProgress {
    /// Initializes the verbose display for a new download.
    ///
    /// Outputs the initial download information including timestamp,
    /// URL, connection status, file size, and content type.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL being downloaded.
    /// * `total_size` - The total expected file size, if known.
    /// * `_resume_from` - Resume offset if continuing a partial download (not used in output).
    fn begin(&mut self, url: &str, total_size: Option<u64>, _resume_from: Option<u64>) {
        self.url = url.to_string();
        self.total_size = total_size;
        self.downloaded = 0;
        self.start_time = Instant::now();
        self.finished = false;

        let mut stderr = io::stderr();
        let _ = stderr.write_all(format!("--{}--  {}\n", Self::timestamp_str(), url).as_bytes());

        if let Some(size) = total_size {
            let _ = stderr.write_all(format!("Resolving... connecting...\n").as_bytes());
            let _ = stderr.write_all(format!("length: {} ({}) [{}]\n",
                size,
                self.length_str(),
                self.content_type_str(),
            ).as_bytes());
        }
        let _ = stderr.write_all(b"Saving to: ...\n");
        let _ = stderr.flush();
    }

    /// Updates the progress display with the current download status.
    ///
    /// In verbose mode, this method primarily tracks the downloaded bytes
    /// but does not produce continuous output. Progress information is
    /// shown at the end of the download.
    ///
    /// # Arguments
    ///
    /// * `downloaded` - Total bytes downloaded so far.
    /// * `_elapsed` - Time elapsed since download started (not used for intermediate output).
    fn update(&mut self, downloaded: u64, _elapsed: Duration) {
        self.downloaded = downloaded;

        if self.finished {
            return;
        }

        if let Some(total) = self.total_size {
            if downloaded >= total {
                return;
            }
        }
    }

    /// Finalizes the verbose display with the download result.
    ///
    /// Outputs the final download status including timestamp, URL,
    /// total bytes downloaded, duration, and average transfer speed.
    /// For error cases, outputs the error message.
    ///
    /// # Arguments
    ///
    /// * `status` - The final status of the download operation.
    fn finish(&mut self, status: FinishStatus) {
        self.finished = true;

        let mut stderr = io::stderr();

        match status {
            FinishStatus::Success { downloaded, elapsed } => {
                let secs = elapsed.as_secs();
                let speed = if secs > 0 {
                    downloaded as f64 / secs as f64
                } else {
                    0.0
                };

                let _ = stderr.write_all(format!("\n--{}--  finished\n", Self::timestamp_str()).as_bytes());
                let _ = stderr.write_all(format!(
                    "`{}' saved [{}]\n",
                    self.url,
                    downloaded,
                ).as_bytes());

                if self.total_size == Some(downloaded) || self.total_size.is_none() {
                    let _ = stderr.write_all(format!(
                        "Downloaded: {} in {} ({:.2} B/s)\n",
                        downloaded,
                        crate::format_duration(elapsed),
                        speed,
                    ).as_bytes());
                }
            }
            FinishStatus::Error(ref err) => {
                let _ = stderr.write_all(format!("--{}--  error: {}\n", Self::timestamp_str(), err).as_bytes());
            }
            FinishStatus::AlreadyExists => {
                let _ = stderr.write_all(b"Server file no newer than local file -- not retrieving.\n");
            }
            FinishStatus::NotModified => {
                let _ = stderr.write_all(b"The file is already fully retrieved; nothing to do.\n");
            }
            FinishStatus::Redirected(ref new_url) => {
                let _ = stderr.write_all(format!("--{}--  redirected to: {}\n", Self::timestamp_str(), new_url).as_bytes());
            }
        }

        let _ = stderr.flush();
    }

    /// Handles URL redirection by outputting a redirect notice.
    ///
    /// Outputs a timestamped message indicating that the download is
    /// following a redirect to a new URL, and updates the internal
    /// URL tracking.
    ///
    /// # Arguments
    ///
    /// * `new_url` - The new URL after redirection.
    fn set_redirected(&mut self, new_url: &str) {
        let mut stderr = io::stderr();
        let _ = stderr.write_all(format!("--{}--  following redirect to: {}\n",
            Self::timestamp_str(), new_url).as_bytes());
        let _ = stderr.flush();
        self.url = new_url.to_string();
    }

    /// Resets the verbose display to its initial state.
    ///
    /// Clears all tracking fields including URL, size, content type,
    /// and finished flag, preparing the display for a new download.
    fn reset(&mut self) {
        self.url = String::new();
        self.total_size = None;
        self.downloaded = 0;
        self.content_type = None;
        self.finished = false;
    }

    /// Returns whether this display is interactive.
    ///
    /// Verbose progress is not considered interactive as it doesn't use
    /// terminal cursor control or in-place line updates.
    ///
    /// # Returns
    ///
    /// Always returns `false` for verbose progress display.
    fn is_interactive(&self) -> bool {
        false
    }
}
