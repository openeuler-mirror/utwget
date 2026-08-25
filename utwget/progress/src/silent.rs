//! Silent progress display implementation.
//!
//! This module provides a no-op progress display that produces no output.
//! It is useful for scenarios where progress reporting should be completely
//! suppressed, such as when running in quiet mode or when downloading
//! in background.

use crate::{FinishStatus, ProgressDisplay};
use std::time::Duration;

/// A silent progress display that produces no output.
///
/// This display implements the `ProgressDisplay` trait but all methods
/// are no-ops. It is used when progress reporting should be completely
/// disabled, such as with the `--quiet` command-line option.
///
/// # Behavior
///
/// - `begin()`: Does nothing
/// - `update()`: Does nothing
/// - `finish()`: Does nothing
/// - `is_interactive()`: Returns `false`
///
/// # Example
///
/// ```
/// use utwget_progress::SilentProgress;
/// use utwget_progress::ProgressDisplay;
///
/// let mut progress = SilentProgress;
/// progress.begin("http://example.com", Some(1000), None);
/// // No output is produced
/// ```
pub struct SilentProgress;

impl ProgressDisplay for SilentProgress {
    /// Initializes the silent display (no-op).
    ///
    /// This method does nothing as the silent display produces no output.
    ///
    /// # Arguments
    ///
    /// * `_url` - The URL being downloaded (ignored).
    /// * `_total_size` - The total expected file size (ignored).
    /// * `_resume_from` - Resume offset if continuing a partial download (ignored).
    fn begin(&mut self, _url: &str, _total_size: Option<u64>, _resume_from: Option<u64>) {}

    /// Updates the silent display (no-op).
    ///
    /// This method does nothing as the silent display produces no output.
    ///
    /// # Arguments
    ///
    /// * `_downloaded` - Total bytes downloaded so far (ignored).
    /// * `_elapsed` - Time elapsed since download started (ignored).
    fn update(&mut self, _downloaded: u64, _elapsed: Duration) {}

    /// Finalizes the silent display (no-op).
    ///
    /// This method does nothing as the silent display produces no output.
    ///
    /// # Arguments
    ///
    /// * `_status` - The final status of the download operation (ignored).
    fn finish(&mut self, _status: FinishStatus) {}

    /// Handles URL redirection (no-op).
    ///
    /// This method does nothing as the silent display produces no output.
    ///
    /// # Arguments
    ///
    /// * `_new_url` - The new URL after redirection (ignored).
    fn set_redirected(&mut self, _new_url: &str) {}

    /// Resets the silent display (no-op).
    ///
    /// This method does nothing as the silent display has no state to reset.
    fn reset(&mut self) {}

    /// Returns whether this display is interactive.
    ///
    /// Silent progress is not interactive as it produces no output.
    ///
    /// # Returns
    ///
    /// Always returns `false` for silent progress display.
    fn is_interactive(&self) -> bool {
        false
    }
}
