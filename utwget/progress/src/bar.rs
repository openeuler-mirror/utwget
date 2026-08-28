//! Progress bar display implementation.
//!
//! This module provides a visual progress bar for download operations,
//! displaying download progress with percentage, speed, and ETA information.

use crate::{format_duration, format_eta, format_size, format_speed_with_prefix, FinishStatus, ProgressDisplay};
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
        self.render_known_size_with_done(false)
    }

    /// Renders the progress bar when the total file size is known.
    ///
    /// When `done` is true, shows elapsed time instead of ETA.
    fn render_known_size_with_done(&self, done: bool) -> String {
        let total = self.total_size.unwrap_or(self.downloaded);
        let pct = if total > 0 {
            if self.downloaded >= total { 100 } else { (self.downloaded * 100) / total }
        } else {
            100
        };

        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();
        let secs = elapsed_secs.max(1e-6);
        let speed = self.downloaded as f64 / secs;

        // Detect terminal width for the progress bar.
        let term_width = terminal_size::terminal_size()
            .map(|(w, _)| w.0 as usize)
            .unwrap_or(80);
        // GNU wget: MAX_FILENAME_COLS = width / 4
        let max_filename_cols = term_width / 4;
        // Reserve space for: filename(1/4 width+1) + pct(4) + bar(2) + size(8) + speed(10) + eta(15)
        let reserved = max_filename_cols + 1 + 4 + 2 + 8 + 10 + 15;
        let bar_width = if term_width > reserved {
            term_width - reserved
        } else {
            10
        };
        let bar_width = bar_width.max(5);

        let filled = if total > 0 {
            ((self.downloaded as f64 / total as f64) * bar_width as f64).round() as usize
        } else {
            bar_width
        };
        let filled = filled.min(bar_width);
        let empty = bar_width - filled;

        let mut bar = String::with_capacity(bar_width + 2);
        bar.push('[');
        // GNU wget: draw filled-1 '=' chars, then one '>' at the leading edge.
        // When filled == 0, the bar is all spaces.
        if filled > 0 {
            for _ in 0..filled - 1 {
                bar.push('=');
            }
            bar.push('>');
        }
        for _ in 0..empty {
            bar.push(' ');
        }
        bar.push(']');

        // Filename: pad to max_filename_cols + 1 (matching GNU wget)
        let filename_display = if self.filename.chars().count() > max_filename_cols {
            &self.filename[..max_filename_cols]
        } else {
            &self.filename
        };
        let filename_padded = format!("{:<width$}", filename_display, width = max_filename_cols + 1);

        // Downloaded size: right-aligned to 8 chars (PROGRESS_FILESIZE_LEN = 7 + 1)
        let size_str = format_size(self.downloaded);
        let size_padded = format!("{:>8}", size_str);

        // Speed format: "  %4.*f%s" with 2-space prefix
        // Show --.-KB/s when no data or elapsed <= 0
        let speed_str = if self.downloaded == 0 || elapsed_secs <= 0.0 {
            "  --.-KB/s".to_string()
        } else if self.report_speed_bytes {
            format!("{:.0} B/s", speed)
        } else {
            format_speed_with_prefix(speed)
        };

        // ETA / elapsed time area (15 chars total, PROGRESS_ETA_LEN)
        const ETA_LEN: usize = 15;
        let eta_str = if done {
            // Download complete: show elapsed time ("  用时 Xs" or "  用时 Xm Ys")
            let time_str = if elapsed_secs >= 10.0 {
                format_eta(elapsed_secs.round() as u64)
            } else {
                format!("{:.1}s", elapsed_secs)
            };
            let label = ut_core::i18n::translate_with_args("utwget.progress_elapsed", &[("time", time_str.clone())]);
            if label.chars().count() < ETA_LEN {
                format!("{}{}", label, " ".repeat(ETA_LEN - label.chars().count()))
            } else {
                label
            }
        } else if total > self.downloaded && elapsed_secs > 3.0 && speed > 1.0 {
            // Show ETA only after 3 seconds of downloading
            let remaining = total - self.downloaded;
            let eta_secs = (remaining as f64 / speed) as u64;
            let time_str = format_eta(eta_secs);
            let label = ut_core::i18n::translate_with_args("utwget.progress_eta", &[("time", time_str)]);
            if label.chars().count() < ETA_LEN {
                format!("{}{}", label, " ".repeat(ETA_LEN - label.chars().count()))
            } else {
                label
            }
        } else {
            // Not enough data for ETA: pad with spaces
            " ".repeat(ETA_LEN)
        };

        // Format: "filename   xx%[bar]   nnn.nnK  ddd.ddKB/s  eta Xm Ys"
        // (matching GNU wget's create_image layout)
        // Note: no leading \r here; the caller adds it via display_image.
        // speed_str already includes 2-space prefix, so no extra space needed.
        let line = format!(
            "{}{:>3}%{}{}{}{}",
            filename_padded,
            pct,
            bar,
            size_padded,
            speed_str,
            eta_str,
        );

        // Pad to full terminal width so old characters are overwritten
        // (matching GNU wget's create_image padding logic).
        let line_cols = line.chars().count();
        if line_cols < term_width {
            format!("{}{}", line, " ".repeat(term_width - line_cols))
        } else {
            line
        }
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
        let elapsed_secs = elapsed.as_secs_f64();
        let speed = self.downloaded as f64 / elapsed_secs.max(1e-6);

        let speed_str = if self.downloaded == 0 || elapsed_secs <= 0.0 {
            "  --.-KB/s".to_string()
        } else if self.report_speed_bytes {
            format!("{:.0} B/s", speed)
        } else {
            crate::format_speed_with_prefix(speed)
        };

        format!(
            "{:>10}{}",
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
            .split('?').next().unwrap_or("")
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

        // GNU wget's display_image: output \r then the buffer content.
        // The buffer is padded to full terminal width so the entire line
        // is overwritten on each update (no leftover characters).
        eprint!("\r{}", line);
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
                let speed = if elapsed.as_millis() > 0 {
                    downloaded as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                };

                // Update to show 100% before clearing
                self.downloaded = downloaded;
                if self.total_size.is_some() {
                    let line = self.render_known_size_with_done(true);
                    eprint!("\r{}", line);
                    self.flush_line();
                }

                // Move to next line after the progress bar
                eprintln!();

        let speed_str = if self.report_speed_bytes {
            format!("{:.0} B/s", speed)
        } else {
            crate::format_speed(speed)
        };

                // Format timestamp like wget: YYYY-MM-DD HH:MM:SS in local time
                let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

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
                // Format timestamp like wget: YYYY-MM-DD HH:MM:SS in local time
                let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
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

