//! Dot-style progress display implementation.
//!
//! This module provides a classic "dot" progress indicator for download operations,
//! displaying progress as a series of dots printed to stderr. Each dot represents
//! a fixed amount of downloaded data, providing a simple visual indication of
//! download activity.
//!
//! # Display Format
//!
//! ```text
//!        0 ..........
//!    10.0K ..........
//!    20.0K ..........
//! ```
//!
//! The display shows the total downloaded size at the start of each line,
//! followed by a configurable number of dots.

use crate::{format_size, FinishStatus, ProgressDisplay};
use std::io::{self, Write};
use std::time::Duration;

/// A dot-style progress display that shows download progress as dots.
///
/// This display renders progress as a series of dots, where each dot represents
/// a fixed number of bytes downloaded. Lines are broken after a configurable
/// number of dots, with the total downloaded size shown at the start of each line.
///
/// # Configuration
///
/// - `bytes_per_dot`: Number of bytes each dot represents (default: 1024)
/// - `dots_per_line`: Number of dots per line before wrapping (default: 50)
/// - `spacing`: Insert a space every N dots for readability (default: 10)
///
/// # Example
///
/// ```text
///        0 ..........  ..........  ..........  ..........  ..........
///   50.0K ..........  ..........  ..........  ..........  ..........
/// ```
pub struct DotProgress {
    bytes_per_dot: usize,
    dots_per_line: usize,
    spacing: usize,
    current_bytes: usize,
    current_dots: usize,
    total_downloaded: u64,
    line_count: usize,
    finished: bool,
}

impl DotProgress {
    /// Creates a new `DotProgress` instance with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `bytes_per_dot` - Number of bytes each dot represents. A dot is printed
    ///   for every `bytes_per_dot` bytes downloaded.
    /// * `dots_per_line` - Number of dots to print before starting a new line.
    ///   After this many dots, a newline is printed and the current total is shown.
    /// * `spacing` - Insert a space every N dots for improved readability.
    ///   Set to 0 to disable spacing.
    ///
    /// # Returns
    ///
    /// A new `DotProgress` instance configured with the specified parameters.
    ///
    /// # Example
    ///
    /// ```
    /// use utwget_progress::DotProgress;
    /// let progress = DotProgress::new(1024, 50, 10);
    /// ```
    pub fn new(bytes_per_dot: usize, dots_per_line: usize, spacing: usize) -> Self {
        DotProgress {
            bytes_per_dot,
            dots_per_line,
            spacing,
            current_bytes: 0,
            current_dots: 0,
            total_downloaded: 0,
            line_count: 0,
            finished: false,
        }
    }

    /// Emits a single dot to the progress display.
    ///
    /// This method handles the actual printing of a dot character to stderr,
    /// including spacing between dots and line wrapping when the configured
    /// number of dots per line is reached.
    ///
    /// When a line wraps, the current total downloaded size is printed at
    /// the start of the new line.
    fn emit_dot(&mut self) {
        if self.finished {
            return;
        }

        self.current_dots += 1;
        self.current_bytes = 0;

        let mut stderr = io::stderr();

        if self.spacing > 0 && (self.current_dots % self.spacing == 0) && self.current_dots < self.dots_per_line {
            let _ = stderr.write_all(b" ");
        }

        let _ = stderr.write_all(b".");

        if self.current_dots >= self.dots_per_line {
            self.current_dots = 0;
            self.line_count += 1;
            let _ = stderr.write_all(b"\n");
            let _ = stderr.write_all(format!("  {:>12} ", format_size(self.total_downloaded)).as_bytes());
        }

        let _ = stderr.flush();
    }
}

impl ProgressDisplay for DotProgress {
    /// Initializes the dot progress display for a new download.
    ///
    /// Prints the initial line with zero bytes and starts the dot sequence.
    ///
    /// # Arguments
    ///
    /// * `_url` - The URL being downloaded (not displayed in dot mode).
    /// * `_total_size` - The total expected file size (not used in dot mode).
    /// * `_resume_from` - Resume offset if continuing a partial download (not used).
    fn begin(&mut self, _url: &str, _total_size: Option<u64>, _resume_from: Option<u64>) {
        self.current_bytes = 0;
        self.current_dots = 0;
        self.total_downloaded = 0;
        self.line_count = 0;
        self.finished = false;

        let mut stderr = io::stderr();
        let _ = stderr.write_all(b"\n");
        let _ = stderr.write_all(format!("       0 ..........  ").as_bytes());
        let _ = stderr.flush();
    }

    /// Updates the progress display based on bytes downloaded.
    ///
    /// Calculates how many new dots should be printed based on the increase
    /// in downloaded bytes since the last update, and emits them.
    ///
    /// # Arguments
    ///
    /// * `downloaded` - Total bytes downloaded so far.
    /// * `_elapsed` - Time elapsed since download started (not used in dot mode).
    fn update(&mut self, downloaded: u64, _elapsed: Duration) {
        if self.finished {
            return;
        }

        let delta = downloaded.saturating_sub(self.total_downloaded);
        self.total_downloaded = downloaded;
        self.current_bytes += delta as usize;

        while self.current_bytes >= self.bytes_per_dot {
            self.current_bytes -= self.bytes_per_dot;
            self.emit_dot();
        }
    }

    /// Finalizes the dot progress display with the given status.
    ///
    /// Prints a final newline if needed and displays the completion status,
    /// including the total downloaded size for successful downloads or
    /// an error message for failures.
    ///
    /// # Arguments
    ///
    /// * `status` - The final status of the download operation.
    fn finish(&mut self, status: FinishStatus) {
        self.finished = true;

        let mut stderr = io::stderr();

        if self.current_dots > 0 {
            let _ = stderr.write_all(b"\n");
        }

        match status {
            FinishStatus::Success { downloaded, .. } => {
                let _ = stderr.write_all(format!("  {:>12} saved [{}]\n", format_size(downloaded), self.total_downloaded).as_bytes());
            }
            FinishStatus::Error(ref err) => {
                let _ = stderr.write_all(format!("ERROR: {}\n", err).as_bytes());
            }
            FinishStatus::AlreadyExists => {
                let _ = stderr.write_all(b"File already exists; not retrieving.\n");
            }
            FinishStatus::NotModified => {
                let _ = stderr.write_all(b"The file is already fully retrieved; nothing to do.\n");
            }
            FinishStatus::Redirected(ref new_url) => {
                let _ = stderr.write_all(format!("Redirected to: {}\n", new_url).as_bytes());
            }
        }

        let _ = stderr.flush();
    }

    /// Handles URL redirection (no-op for dot mode).
    ///
    /// The dot progress display does not show URL information, so this
    /// method does nothing.
    ///
    /// # Arguments
    ///
    /// * `_new_url` - The new URL after redirection.
    fn set_redirected(&mut self, _new_url: &str) {}

    /// Resets the progress display to its initial state.
    ///
    /// Clears all counters and resets the finished flag, preparing the
    /// display for a new download operation.
    fn reset(&mut self) {
        self.current_bytes = 0;
        self.current_dots = 0;
        self.total_downloaded = 0;
        self.line_count = 0;
        self.finished = false;
    }

    /// Returns whether this display is interactive.
    ///
    /// Dot progress is not considered interactive as it doesn't require
    /// terminal cursor control or line updates.
    ///
    /// # Returns
    ///
    /// Always returns `false` for dot progress display.
    fn is_interactive(&self) -> bool {
        false
    }
}
