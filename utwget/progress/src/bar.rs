//! Progress bar display implementation.
//!
//! This module provides a visual progress bar for download operations,
//! displaying download progress with percentage, speed, and ETA information.

use crate::{format_duration, format_size, format_speed, FinishStatus, ProgressDisplay};
use std::io::{self, Write};
use std::time::{Duration, Instant};

/// A progress bar display that shows download progress visually.
///
/// This display renders a progress bar with percentage, downloaded/total size,
/// current speed, and estimated time of arrival (ETA). It supports both known
/// and unknown file sizes, adjusting the display accordingly.
///
/// # Example
///
/// ```text
///  45% [######################                          ]   4.5M/10.0M   1.2M/s eta 00:04
/// ```
pub struct BarProgress {
    url: String,
    total_size: Option<u64>,
    downloaded: u64,
    resume_from: u64,
    start_time: Instant,
    last_update: Instant,
    terminal_width: usize,
    tick_count: usize,
    force_noscroll: bool,
    report_speed_bytes: bool,
    finished: bool,
}
