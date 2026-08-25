pub mod bar;
pub mod dot;
pub mod silent;
pub mod verbose;

pub use ut_core::ProgressStyle;

use std::time::Duration;

pub trait ProgressDisplay: Send {
    fn begin(&mut self, url: &str, total_size: Option<u64>, resume_from: Option<u64>);
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
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{}K", bytes / KB)
    } else {
        format!("{}B", bytes)
    }
}

pub fn format_speed(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1}G/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    } else if bytes_per_sec >= 1024.0 * 1024.0 {
        format!("{:.1}M/s", bytes_per_sec / (1024.0 * 1024.0))
    } else if bytes_per_sec >= 1024.0 {
        format!("{:.0}K/s", bytes_per_sec / 1024.0)
    } else {
        format!("{:.0}B/s", bytes_per_sec)
    }
}
