//! Progress bar display implementation.
//!
//! This module provides a visual progress bar for download operations,
//! displaying download progress with percentage, speed, and ETA information.

use crate::{format_duration, format_eta, format_size, format_speed_with_prefix, FinishStatus, ProgressDisplay};
use std::io::{self, Write};
use std::time::{Duration, Instant};
use unicode_width::UnicodeWidthStr;

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
    /// Sliding-window samples (instant, cumulative_downloaded) for the
    /// speed estimate (report 8.3-2): a whole-run average misrepresents
    /// throughput for slow-start/changing links.
    samples: std::collections::VecDeque<(Instant, u64)>,
    /// Bytes already present when the download began (`-c` resume).
    initial_bytes: u64,
}

impl BarProgress {
    /// Speed over the last ~3 seconds of samples, in bytes/sec.
    ///
    /// Uses the sliding sample window instead of the whole-run average so
    /// the displayed speed tracks current throughput (8.3-2). Falls back
    /// to the run average when fewer than 2 samples exist.
    fn sliding_speed(&self) -> f64 {
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(3);
        // Find the oldest sample within the window.
        let mut base: Option<(Instant, u64)> = None;
        for (t, b) in &self.samples {
            if *t >= cutoff {
                base = Some((*t, *b));
                break;
            }
        }
        match base {
            Some((t0, b0)) if now.duration_since(t0).as_secs_f64() > 0.05 => {
                let db = (self.initial_bytes + self.downloaded).saturating_sub(b0);
                db as f64 / now.duration_since(t0).as_secs_f64()
            }
            _ => {
                let secs = self.start_time.elapsed().as_secs_f64().max(1e-6);
                self.downloaded as f64 / secs
            }
        }
    }

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
            samples: std::collections::VecDeque::new(),
            initial_bytes: 0,
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
        // Effective position includes bytes restored by `-c` resume, so the
        // percentage starts at resume%/100 rather than 0% (8.3-2).
        let effective = self.initial_bytes + self.downloaded;
        let total = self.total_size.unwrap_or(effective).max(effective);
        let pct = if total > 0 {
            if effective >= total { 100 } else { (effective * 100) / total }
        } else {
            100
        };

        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();
        let secs = elapsed_secs.max(1e-6);
        // Sliding-window speed over the last ~3 seconds (falls back to the
        // whole-run average before enough samples exist) (8.3-2).
        let speed = self.sliding_speed();

        // Detect terminal width for the progress bar.
        let term_width = terminal_size::terminal_size()
            .map(|(w, _)| w.0 as usize)
            .unwrap_or(80);

        // GNU wget: MAX_FILENAME_COLS = width / 4
        let max_filename_cols = term_width / 4;

        // Build the non-bar components first, measuring their *display width*
        // (CJK characters occupy 2 terminal columns but count as 1 char).
        let pct_str = format!("{:>3}%", pct);

        let size_str = format_size(self.downloaded);
        let size_padded = format!("{:>8}", size_str);

        let speed_str = if self.downloaded == 0 || elapsed_secs <= 0.0 {
            "  --.-KB/s".to_string()
        } else if self.report_speed_bytes {
            format!("{:.0} B/s", speed)
        } else {
            format_speed_with_prefix(speed)
        };

        // ETA / elapsed time area (15 display columns, PROGRESS_ETA_LEN)
        const ETA_COLS: usize = 15;
        let eta_str = if done {
            let time_str = if elapsed_secs >= 10.0 {
                format_eta(elapsed_secs.round() as u64)
            } else {
                format!("{:.1}s", elapsed_secs)
            };
            let label = ut_core::i18n::translate_with_args("utwget.progress_elapsed", &[("time", time_str)]);
            let label_width = label.width();
            if label_width < ETA_COLS {
                format!("{}{}", label, " ".repeat(ETA_COLS - label_width))
            } else {
                label
            }
        } else if total > self.downloaded && elapsed_secs > 3.0 && speed > 1.0 {
            let remaining = total - self.downloaded;
            let eta_secs = (remaining as f64 / speed) as u64;
            let time_str = format_eta(eta_secs);
            let label = ut_core::i18n::translate_with_args("utwget.progress_eta", &[("time", time_str)]);
            let label_width = label.width();
            if label_width < ETA_COLS {
                format!("{}{}", label, " ".repeat(ETA_COLS - label_width))
            } else {
                label
            }
        } else {
            " ".repeat(ETA_COLS)
        };

        // Filename: truncate to max_filename_cols (display width), then pad
        let filename_padded = {
            let fname_width = self.filename.width();
            if fname_width > max_filename_cols {
                // Truncate by display width (handles CJK correctly)
                let mut truncated = String::new();
                let mut w = 0;
                for ch in self.filename.chars() {
                    let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
                    if w + cw > max_filename_cols {
                        break;
                    }
                    truncated.push(ch);
                    w += cw;
                }
                // Pad to max_filename_cols + 1
                let pad = max_filename_cols + 1 - w;
                format!("{}{}", truncated, " ".repeat(pad))
            } else {
                let pad = max_filename_cols + 1 - fname_width;
                format!("{}{}", self.filename, " ".repeat(pad))
            }
        };

        // Calculate bar_width so the total line fits exactly term_width columns.
        let non_bar_width = filename_padded.width()
            + pct_str.width()
            + size_padded.width()
            + speed_str.width()
            + eta_str.width();
        // bar includes 2 bracket chars + bar_width interior
        let bar_width = if term_width > non_bar_width + 2 {
            term_width - non_bar_width - 2
        } else {
            5
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

        // Assemble the line (exactly term_width display columns)
        let line = format!(
            "{}{}{}{}{}{}",
            filename_padded,
            pct_str,
            bar,
            size_padded,
            speed_str,
            eta_str,
        );

        // Safety net: if line is still wider than term_width (shouldn't happen),
        // pad with spaces to overwrite any residual characters.
        let line_width = line.width();
        if line_width < term_width {
            format!("{}{}", line, " ".repeat(term_width - line_width))
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
        let speed = self.sliding_speed();

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
        // `-c` resume: the bar starts at resume_from, not zero (report
        // 8.3-2: resume_from was stored but never used — percentage began
        // at 0% and speed was underestimated).
        self.initial_bytes = self.resume_from;
        self.samples.clear();
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
        // `-c` resume: the bar starts at resume_from, not zero (report
        // 8.3-2: resume_from was stored but never used — percentage began
        // at 0% and speed was underestimated).
        self.initial_bytes = self.resume_from;
        self.samples.clear();
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

        // Sliding-window sample for the speed estimate (8.3-2).
        self.samples.push_back((now, self.initial_bytes + self.downloaded));
        while self.samples.len() > 32 {
            self.samples.pop_front();
        }

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

