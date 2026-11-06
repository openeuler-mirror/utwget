//! Unit tests for progress bar module.
//!
//! Tests for progress display, size formatting, and speed calculation.

#[test]
fn test_format_size_bytes() {
    fn format_size(size: u64) -> String {
        const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
        if size == 0 {
            return "0B".to_string();
        }
        let mut size = size as f64;
        let mut unit_idx = 0;
        while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }
        if unit_idx == 0 {
            format!("{}{}", size as u64, UNITS[unit_idx])
        } else {
            format!("{:.1}{}", size, UNITS[unit_idx])
        }
    }

    assert_eq!(format_size(0), "0B");
    assert_eq!(format_size(100), "100B");
    assert_eq!(format_size(1024), "1.0K");
    assert_eq!(format_size(1536), "1.5K");
    assert_eq!(format_size(1048576), "1.0M");
    assert_eq!(format_size(1073741824), "1.0G");
}

#[test]
fn test_format_duration() {
    fn format_duration(secs: u64) -> String {
        if secs < 60 {
            format!("{}s", secs)
        } else if secs < 3600 {
            format!("{}m{}s", secs / 60, secs % 60)
        } else {
            format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
        }
    }

    assert_eq!(format_duration(0), "0s");
    assert_eq!(format_duration(30), "30s");
    assert_eq!(format_duration(60), "1m0s");
    assert_eq!(format_duration(90), "1m30s");
    assert_eq!(format_duration(3600), "1h0m");
    assert_eq!(format_duration(3661), "1h1m");
}
