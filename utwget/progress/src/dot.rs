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
