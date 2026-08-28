pub mod bar;
pub mod dot;
pub mod silent;
pub mod verbose;

pub use ut_core::ProgressStyle;

pub use verbose::VerboseProgress;
pub use dot::DotProgress;
pub use silent::SilentProgress;

use std::time::Duration;

pub trait ProgressDisplay: Send {
    fn begin(&mut self, url: &str, total_size: Option<u64>, resume_from: Option<u64>);
    fn begin_with_output_path(&mut self, url: &str, _output_path: &str, total_size: Option<u64>, resume_from: Option<u64>) {
        self.begin(url, total_size, resume_from);
    }
    fn update(&mut self, downloaded: u64, elapsed: Duration);
    fn finish(&mut self, status: FinishStatus);
    fn set_redirected(&mut self, new_url: &str);
    fn reset(&mut self);
    fn is_interactive(&self) -> bool;
}

#[derive(Debug)]
pub enum FinishStatus {
    Success { downloaded: u64, elapsed: Duration },
    Error(String),
    AlreadyExists,
    NotModified,
    Redirected(String),
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["K", "M", "G", "T", "P", "E"];

    if bytes < 1024 {
        return format!("{}", bytes);
    }

    let mut value = bytes as f64 / 1024.0;
    let mut unit_idx = 0;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }

    if value < 1000.0 {
        format!("{:.2}{}", value, UNITS[unit_idx])
    } else {
        format!("{:.0}{}", value, UNITS[unit_idx])
    }
}

pub fn format_speed(bytes_per_sec: f64) -> String {
    const UNITS: &[&str] = &[" B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
    const BIBYTE: f64 = 1024.0;

    let mut speed = bytes_per_sec;
    let mut unit_idx = 0;
    while speed >= BIBYTE && unit_idx < UNITS.len() - 1 {
        speed /= BIBYTE;
        unit_idx += 1;
    }
    if unit_idx == UNITS.len() - 1 && speed > 99.99 {
        speed = 99.99;
    }

    let precision = if speed >= 99.95 { 0 } else if speed >= 9.995 { 1 } else { 2 };
    format!("{:4.*}{}", precision, speed, UNITS[unit_idx])
}

/// Formats download speed with a 2-space prefix, matching GNU wget's
/// `"  %4.*f%s"` format used in the progress bar.
///
/// The result is always 10 characters wide for KB/s and above:
/// - 2 leading spaces
/// - 4-char wide number with variable precision
/// - 4-char unit string (KB/s, MB/s, etc.)
pub fn format_speed_with_prefix(bytes_per_sec: f64) -> String {
    const UNITS: &[&str] = &[" B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
    const BIBYTE: f64 = 1024.0;

    let mut speed = bytes_per_sec;
    let mut unit_idx = 0;
    while speed >= BIBYTE && unit_idx < UNITS.len() - 1 {
        speed /= BIBYTE;
        unit_idx += 1;
    }
    if unit_idx == UNITS.len() - 1 && speed > 99.99 {
        speed = 99.99;
    }

    let precision = if speed >= 99.95 { 0 } else if speed >= 9.995 { 1 } else { 2 };
    format!("  {:4.*}{}", precision, speed, UNITS[unit_idx])
}

/// Formats an ETA (estimated time of arrival) in a short human-readable form,
/// matching GNU wget's `eta_to_human_short()` function.
///
/// Format rules:
/// - `< 100s`: `"36s"`
/// - `< 6000s (100m)`: `"6m 51s"`
/// - `< 48h`: `"1h 23m"`
/// - `< 100d`: `"2d 5h"`
/// - `>= 100d`: `"365d"`
pub fn format_eta(secs: u64) -> String {
    if secs < 100 {
        format!("{}s", secs)
    } else if secs < 100 * 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 48 * 3600 {
        format!("{}h {}m", secs / 3600, (secs / 60) % 60)
    } else if secs < 100 * 86400 {
        format!("{}d {}h", secs / 86400, (secs / 3600) % 24)
    } else {
        format!("{}d", secs / 86400)
    }
}

pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 3600 {
        format!("{}h{:02}m{:02}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

pub fn create_progress_display(style: ProgressStyle, force_noscroll: bool) -> Box<dyn ProgressDisplay> {
    match style {
        ProgressStyle::Bar => Box::new(bar::BarProgress::new(force_noscroll)),
        ProgressStyle::Dot { bytes_per_dot, dots_per_line, spacing } => {
            Box::new(dot::DotProgress::new(bytes_per_dot, dots_per_line, spacing))
        }
        ProgressStyle::Verbose => Box::new(verbose::VerboseProgress::new()),
        ProgressStyle::Silent => Box::new(silent::SilentProgress),
    }
}
