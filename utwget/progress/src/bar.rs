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

impl ProgressDisplay for BarProgress {
    /// Initializes the progress bar for a new download.
    ///
    /// Prints the URL being downloaded and prepares the progress bar
    /// for tracking the download progress.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL being downloaded.
    /// * `total_size` - The total expected file size, if known.
    /// * `resume_from` - Resume offset if continuing a partial download.
    fn begin(&mut self, url: &str, total_size: Option<u64>, resume_from: Option<u64>) {
        self.url = url.to_string();
        self.total_size = total_size;
        self.resume_from = resume_from.unwrap_or(0);
        self.downloaded = 0;
        self.start_time = Instant::now();
        self.last_update = Instant::now();
        self.tick_count = 0;
        self.finished = false;

        eprintln!("{}", url);
        self.flush_line();
    }

    /// Updates the progress bar with the current download status.
    ///
    /// Renders and displays the progress bar showing percentage, downloaded/total
    /// size, current speed, and estimated time remaining. Updates are throttled
    /// to avoid excessive terminal I/O.
    ///
    /// # Arguments
    ///
    /// * `downloaded` - Total bytes downloaded so far.
    /// * `_elapsed` - Time elapsed since download started (used for speed calculation).
    fn update(&mut self, downloaded: u64, _elapsed: Duration) {
        self.downloaded = downloaded;

        if self.finished {
            return;
        }

        self.tick_count += 1;
        let now = Instant::now();
        let since_last = now.duration_since(self.last_update);

        if since_last < Duration::from_millis(50) && self.tick_count % 10 != 0 {
            return;
        }
        self.last_update = now;

        let line = if self.total_size.is_some() && self.total_size != Some(0) {
            self.render_known_size()
        } else {
            self.render_unknown_size()
        };

        if self.force_noscroll {
            eprint!("{}  \r", line);
        } else {
            eprint!("{}", line);
        }
        self.flush_line();
    }

    /// Finalizes the progress bar with the download result.
    ///
    /// Clears the progress bar line and prints the final download status,
    /// including the URL, total bytes downloaded, duration, and average speed
    /// for successful downloads, or an error message for failures.
    ///
    /// # Arguments
    ///
    /// * `status` - The final status of the download operation.
    fn finish(&mut self, status: FinishStatus) {
        self.finished = true;

        match status {
            FinishStatus::Success { downloaded, elapsed } => {
                let speed = if elapsed.as_secs() > 0 {
                    downloaded as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                };

                if self.force_noscroll {
                    eprint!("\r{:>50}  \n", "");
                } else {
                    eprintln!();
                }

                let speed_str = if self.report_speed_bytes {
                    format!("{:.0}B/s", speed)
                } else {
                    format_speed(speed)
                };

                eprintln!("{}", ut_core::i18n::translate_with_args("utwget.status_saved", &[
                    ("url", self.url.clone()),
                    ("size", downloaded.to_string()),
                    ("duration", format_duration(elapsed)),
                    ("speed", speed_str),
                ]));
            }
            FinishStatus::Error(ref err) => {
                eprintln!();
                eprintln!("{}", ut_core::i18n::translate_with_args("utwget.error", &[("reason", err.to_string())]));
            }
            FinishStatus::AlreadyExists => {
                eprintln!();
                eprintln!("{}", ut_core::i18n::translate("utwget.status_already_exists"));
            }
            FinishStatus::NotModified => {
                eprintln!();
                eprintln!("{}", ut_core::i18n::translate("utwget.status_fully_retrieved"));
            }
            FinishStatus::Redirected(ref new_url) => {
                eprintln!();
                eprintln!("{}", ut_core::i18n::translate_with_args("utwget.status_redirected_to", &[("url", new_url.to_string())]));
            }
        }
        self.flush_line();
    }

    /// Handles URL redirection by updating the tracked URL.
    ///
    /// Updates the internal URL tracking to reflect the new URL after
    /// a redirect, which is used in the final output message.
    ///
    /// # Arguments
    ///
    /// * `new_url` - The new URL after redirection.
    fn set_redirected(&mut self, new_url: &str) {
        self.url = new_url.to_string();
    }

    /// Resets the progress bar to its initial state.
    ///
    /// Clears all tracking fields and resets counters, preparing the
    /// progress bar for a new download operation.
    fn reset(&mut self) {
        self.url = String::new();
        self.total_size = None;
        self.downloaded = 0;
        self.resume_from = 0;
        self.tick_count = 0;
        self.finished = false;
    }

    /// Returns whether this display is interactive.
    ///
    /// The progress bar is considered interactive as it uses terminal
    /// cursor control to update the display in place.
    ///
    /// # Returns
    ///
    /// Always returns `true` for bar progress display.
    fn is_interactive(&self) -> bool {
        true
    }
}
