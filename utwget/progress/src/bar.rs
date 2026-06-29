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
    filename: String,
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
            filename: String::new(),
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
            if self.downloaded >= total { 100 } else { (self.downloaded * 100) / total }
        } else {
            100
        };

        let elapsed = self.start_time.elapsed();
        let secs = elapsed.as_secs_f64().max(1e-6);
        let speed = self.downloaded as f64 / secs;

        let bar_width = 20;
        let filled = if total > 0 {
            ((self.downloaded as f64 / total as f64) * bar_width as f64).round() as usize
        } else {
            bar_width
        };
        let filled = filled.min(bar_width);
        let empty = bar_width - filled;

        let mut bar = String::with_capacity(bar_width + 2);
        bar.push('[');
        for i in 0..filled {
            if i == filled - 1 && empty > 0 {
                bar.push('>');
            } else {
                bar.push('=');
            }
        }
        for _ in 0..empty {
            bar.push(' ');
        }
        bar.push(']');

        let speed_str = if self.report_speed_bytes {
            format!("{:.0}B/s", speed)
        } else if speed >= 1024.0 * 1024.0 * 1024.0 {
            format!("{:.2}GB/s", speed / (1024.0 * 1024.0 * 1024.0))
        } else if speed >= 1024.0 * 1024.0 {
            format!("{:.2}MB/s", speed / (1024.0 * 1024.0))
        } else if speed >= 1024.0 {
            format!("{:.2}KB/s", speed / 1024.0)
        } else {
            format!("{:.0}B/s", speed)
        };

        let time_str = format!("用时 {}s", elapsed.as_secs());

        format!(
            "\r{} {} {:>3}% {}  {}  {}  [{}/{}]",
            self.filename,
            bar,
            pct,
            format_size(total),
            speed_str,
            time_str,
            self.downloaded,
            total,
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
        let secs = elapsed.as_secs_f64().max(1e-6);
        let speed = self.downloaded as f64 / secs;

        let speed_str = if self.report_speed_bytes {
            format!("{:.0}B/s", speed)
        } else if speed >= 1024.0 * 1024.0 * 1024.0 {
            format!("{:.2}GB/s", speed / (1024.0 * 1024.0 * 1024.0))
        } else if speed >= 1024.0 * 1024.0 {
            format!("{:.2}MB/s", speed / (1024.0 * 1024.0))
        } else if speed >= 1024.0 {
            format!("{:.2}KB/s", speed / 1024.0)
        } else {
            format!("{:.0}B/s", speed)
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
        self.filename = url.rsplit('/').next().unwrap_or(url)
            .trim_end_matches('#').to_string();
        self.total_size = total_size;
        self.resume_from = resume_from.unwrap_or(0);
        self.downloaded = 0;
        self.start_time = Instant::now();
        self.last_update = Instant::now();
        self.tick_count = 0;
        self.finished = false;

        self.flush_line();
    }

    fn begin_with_output_path(&mut self, url: &str, output_path: &str, total_size: Option<u64>, resume_from: Option<u64>) {
        self.url = url.to_string();
        self.filename = output_path.to_string();
        self.total_size = total_size;
        self.resume_from = resume_from.unwrap_or(0);
        self.downloaded = 0;
        self.start_time = Instant::now();
        self.last_update = Instant::now();
        self.tick_count = 0;
        self.finished = false;

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

                // Update to show 100% before clearing
                self.downloaded = downloaded;
                if self.total_size.is_some() {
                    let line = self.render_known_size();
                    eprint!("{}\r", line);
                    self.flush_line();
                }

                if self.force_noscroll {
                    eprint!("\r{:>50}  \n", "");
                } else {
                    eprintln!();
                }

        let speed_str = if self.report_speed_bytes {
            format!("{:.0}B/s", speed)
        } else if speed >= 1024.0 * 1024.0 * 1024.0 {
            format!("{:.2}GB/s", speed / (1024.0 * 1024.0 * 1024.0))
        } else if speed >= 1024.0 * 1024.0 {
            format!("{:.2}MB/s", speed / (1024.0 * 1024.0))
        } else if speed >= 1024.0 {
            format!("{:.2}KB/s", speed / 1024.0)
        } else {
            format!("{:.0}B/s", speed)
        };

                // Format timestamp like wget: YYYY-MM-DD HH:MM:SS
                let now = std::time::SystemTime::now();
                let timestamp = now.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| {
                        let secs = d.as_secs();
                        let days = secs / 86400;
                        let time_of_day = secs % 86400;
                        let hours = time_of_day / 3600;
                        let minutes = (time_of_day % 3600) / 60;
                        let seconds = time_of_day % 60;
                        // Calculate year, month, day from days since epoch
                        let (year, month, day) = days_to_ymd(days);
                        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hours, minutes, seconds)
                    })
                    .unwrap_or_default();

                eprintln!("{}", ut_core::i18n::translate_with_args("utwget.status_saved", &[
                    ("url", self.filename.clone()),
                    ("downloaded", downloaded.to_string()),
                    ("total", self.total_size.map_or(downloaded, |t| t).to_string()),
                    ("duration", format_duration(elapsed)),
                    ("speed", speed_str),
                    ("timestamp", timestamp),
                ]));
            }
            FinishStatus::Error(ref err) => {
                let now = std::time::SystemTime::now();
                let timestamp = now.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| {
                        let secs = d.as_secs();
                        let days = secs / 86400;
                        let time_of_day = secs % 86400;
                        let hours = time_of_day / 3600;
                        let minutes = (time_of_day % 3600) / 60;
                        let seconds = time_of_day % 60;
                        let (year, month, day) = days_to_ymd(days);
                        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hours, minutes, seconds)
                    })
                    .unwrap_or_default();
                eprintln!();
                eprintln!("{} {}", timestamp, err);
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
        self.filename = String::new();
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

/// Detects the current terminal width.
///
/// Attempts to determine the width of the terminal window for proper
/// progress bar formatting. Falls back to a default width of 80 columns
/// if the terminal size cannot be determined.
///
/// # Returns
///
/// The terminal width in columns, or 80 if detection fails.
fn detect_terminal_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80)
}

/// Converts days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let mut y = 1970u32;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining < days_in_year as u64 {
            break;
        }
        remaining -= days_in_year as u64;
        y += 1;
    }
    let month_days = [
        (31, false), (28, is_leap_year(y)), (31, false),
        (30, false), (31, false), (30, false),
        (31, false), (31, false), (30, false),
        (31, false), (30, false), (31, false),
    ];
    let mut m = 1u32;
    for (days, _) in &month_days {
        if remaining < *days as u64 {
            break;
        }
        remaining -= *days as u64;
        m += 1;
    }
    (y, m, remaining as u32 + 1)
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}
