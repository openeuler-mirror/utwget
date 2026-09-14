//! Unit tests for progress bar module.
//!
//! Tests for progress display, size formatting, and speed calculation.

use std::time::Duration;
use ut_progress::{format_size, format_speed, format_eta};

#[test]
fn test_format_size_bytes() {
    // GNU wget human_readable: no suffix for < 1024
    assert_eq!(format_size(0), "0");
    assert_eq!(format_size(100), "100");
    assert_eq!(format_size(1023), "1023");
}

#[test]
fn test_format_size_kilobytes() {
    // 2 decimal places when value < 1000 in current unit
    assert_eq!(format_size(1024), "1.00K");
    assert_eq!(format_size(1536), "1.50K");
    assert_eq!(format_size(10240), "10.00K");
    assert_eq!(format_size(102400), "100.00K");
}

#[test]
fn test_format_size_megabytes() {
    assert_eq!(format_size(1048576), "1.00M");
    assert_eq!(format_size(1572864), "1.50M");
}

#[test]
fn test_format_size_gigabytes() {
    assert_eq!(format_size(1073741824), "1.00G");
}

#[test]
fn test_format_speed_bytes() {
    // < 1024: " B/s" unit
    // Precision: >= 99.95 → 0 decimals, >= 9.995 → 1 decimal, < 9.995 → 2 decimals
    // Width: 4 chars total for the number
    assert_eq!(format_speed(0.0), "0.00 B/s");
    assert_eq!(format_speed(5.5), "5.50 B/s");
    assert_eq!(format_speed(50.0), "50.0 B/s");
    assert_eq!(format_speed(500.0), " 500 B/s");
}

#[test]
fn test_format_speed_kilobytes() {
    // 1.00-9.99: 2 decimals; 10.0-99.9: 1 decimal; >=100: 0 decimals
    assert_eq!(format_speed(1024.0), "1.00KB/s");
    assert_eq!(format_speed(10240.0), "10.0KB/s");
    assert_eq!(format_speed(102400.0), " 100KB/s");
}

#[test]
fn test_format_speed_megabytes() {
    assert_eq!(format_speed(1048576.0), "1.00MB/s");
    assert_eq!(format_speed(10485760.0), "10.0MB/s");
}

#[test]
fn test_format_eta_short() {
    // < 100s: "36s"
    assert_eq!(format_eta(0), "0s");
    assert_eq!(format_eta(36), "36s");
    assert_eq!(format_eta(99), "99s");
}

#[test]
fn test_format_eta_minutes() {
    // < 6000s (100m): "6m 51s"
    assert_eq!(format_eta(100), "1m 40s");
    assert_eq!(format_eta(411), "6m 51s");
    assert_eq!(format_eta(3600), "60m 0s");
    assert_eq!(format_eta(5999), "99m 59s");
}

#[test]
fn test_format_eta_hours() {
    // >= 6000s and < 172800s (48h): "1h 23m"
    assert_eq!(format_eta(6000), "1h 40m");
    assert_eq!(format_eta(7200), "2h 0m");
    assert_eq!(format_eta(86400), "24h 0m");
    assert_eq!(format_eta(172799), "47h 59m");
}

#[test]
fn test_format_eta_days() {
    // < 8640000s (100d): "2d 5h"
    assert_eq!(format_eta(172800), "2d 0h");
    assert_eq!(format_eta(194400), "2d 6h");
}

#[test]
fn test_progress_percentage() {
    fn calc_percentage(downloaded: u64, total: u64) -> u8 {
        if total == 0 {
            return 0;
        }
        ((downloaded as f64 / total as f64) * 100.0) as u8
    }

    assert_eq!(calc_percentage(0, 100), 0);
    assert_eq!(calc_percentage(50, 100), 50);
    assert_eq!(calc_percentage(100, 100), 100);
    assert_eq!(calc_percentage(0, 0), 0);
}

#[test]
fn test_eta_calculation() {
    fn calc_eta(downloaded: u64, total: u64, speed: u64) -> u64 {
        if speed == 0 || downloaded >= total {
            return 0;
        }
        (total - downloaded) / speed
    }

    assert_eq!(calc_eta(0, 1000, 100), 10);
    assert_eq!(calc_eta(500, 1000, 100), 5);
    assert_eq!(calc_eta(1000, 1000, 100), 0);
    assert_eq!(calc_eta(0, 1000, 0), 0);
}

// ============================================================================
// Dot mode remainder retention (report 8.3-1)
// ============================================================================

#[test]
fn dot_progress_counts_partial_dots_across_updates() {
    use ut_progress::dot::DotProgress;
    use ut_progress::ProgressDisplay;

    // bytes_per_dot default is 1KB (1024). Feed 1.5 dots worth of bytes in
    // two updates: 1500 then 600. Total 2100 → 2 dots should be emitted.
    let mut dot = DotProgress::with_defaults();
    dot.begin("http://x/", None, None);
    dot.update(1500, Duration::from_secs(1));
    assert_eq!(dot.dots_emitted(), 1, "1500 bytes → 1 dot");
    dot.update(2100, Duration::from_secs(2));
    // 600 bytes carry-over + 600 new = 1200 → but only 1024 counts: 1 more dot.
    assert_eq!(
        dot.dots_emitted(),
        2,
        "remainder must be retained across updates (M 8.3-1)"
    );
}
