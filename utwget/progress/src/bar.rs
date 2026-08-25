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

impl BarProgress {
    /// Creates a new `BarProgress` instance.
    ///
    /// # Arguments
    ///
    /// * `force_noscroll` - If `true`, forces the progress bar to stay on a single line
    ///   without scrolling. This is useful for terminals that don't support scrolling.
    ///
    /// # Returns
    ///
    /// A new `BarProgress` instance with default settings.
    pub fn new(force_noscroll: bool) -> Self {
        BarProgress {
            url: String::new(),
            total_size: None,
            downloaded: 0,
            resume_from: 0,
            start_time: Instant::now(),
            last_update: Instant::now(),
            terminal_width: detect_terminal_width(),
            tick_count: 0,
            force_noscroll,
            report_speed_bytes: false,
            finished: false,
        }
    }

    /// Configures whether to report speed in bytes per second format.
    ///
    /// # Arguments
    ///
    /// * `enabled` - If `true`, speed will be displayed as raw bytes per second (e.g., "1234567B/s").
    ///   If `false`, speed will be formatted with units (e.g., "1.2M/s").
    ///
    /// # Returns
    ///
    /// The modified `BarProgress` instance for method chaining.
    pub fn with_report_speed_bytes(mut self, enabled: bool) -> Self {
        self.report_speed_bytes = enabled;
        self
    }

    /// Renders the progress bar when the total file size is known.
    ///
    /// Displays a visual progress bar with percentage, downloaded/total size,
    /// current speed, and estimated time remaining.
    ///
    /// # Returns
    ///
    /// A formatted string representing the progress bar.
    fn render_known_size(&self) -> String {
        let total = self.total_size.unwrap_or(self.downloaded);
        let pct = if total > 0 {
            (self.downloaded * 100) / total
        } else {
            100
        };

        let elapsed = self.start_time.elapsed();
        let speed = if elapsed.as_secs() > 0 {
            self.downloaded as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let eta = if speed > 0.0 {
            let remaining = total.saturating_sub(self.downloaded) as f64;
            Duration::from_secs_f64(remaining / speed)
        } else {
            Duration::ZERO
        };

        let bar_width = self.terminal_width.saturating_sub(50).min(60);
        let filled = if total > 0 {
            ((self.downloaded as f64 / total as f64) * bar_width as f64).round() as usize
        } else {
            bar_width
        };
        let filled = filled.min(bar_width);
        let empty = bar_width - filled;

        let speed_str = if self.report_speed_bytes {
            format!("{:.0}B/s", speed)
        } else {
            format_speed(speed)
        };

        let bar = format!("{:pad$}{:>pad2$}", "#".repeat(filled), "".to_string(), pad = bar_width, pad2 = 0);
        let bar_visual = format!("{}{}", bar, " ".repeat(empty));

        format!(
            "\r{:>3}% [{}] {:>10}/{:<10} {:>10} eta {:>6}",
            pct,
            bar_visual,
            format_size(self.downloaded + self.resume_from),
            format_size(total),
            speed_str,
            format_duration(eta),
        )
    }

    /// Renders the progress display when the total file size is unknown.
    ///
    /// Displays only the downloaded amount and current speed, without a progress bar.
    ///
    /// # Returns
    ///
    /// A formatted string showing downloaded size and speed.
    fn render_unknown_size(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let speed = if elapsed.as_secs() > 0 {
            self.downloaded as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let speed_str = if self.report_speed_bytes {
            format!("{:.0}B/s", speed)
        } else {
            format_speed(speed)
        };

        format!(
            "\r{:>10} downloaded  {:>10}",
            format_size(self.downloaded),
            speed_str,
        )
    }

    /// Flushes both stderr and stdout to ensure output is displayed immediately.
    fn flush_line(&self) {
        let mut stderr = io::stderr();
        let _ = stderr.flush();
        let mut stdout = io::stdout();
        let _ = stdout.flush();
    }
}
