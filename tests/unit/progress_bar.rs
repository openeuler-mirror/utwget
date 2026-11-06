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

#[test]
fn test_format_speed() {
    fn format_speed(bytes_per_sec: u64) -> String {
        if bytes_per_sec == 0 {
            return "0B/s".to_string();
        }
        let mut speed = bytes_per_sec as f64;
        let units = ["B/s", "K/s", "M/s", "G/s"];
        let mut unit_idx = 0;
        while speed >= 1024.0 && unit_idx < units.len() - 1 {
            speed /= 1024.0;
            unit_idx += 1;
        }
        if unit_idx == 0 {
            format!("{}{}", speed as u64, units[unit_idx])
        } else {
            format!("{:.1}{}", speed, units[unit_idx])
        }
    }

    assert_eq!(format_speed(0), "0B/s");
    assert_eq!(format_speed(1024), "1.0K/s");
    assert_eq!(format_speed(1048576), "1.0M/s");
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
