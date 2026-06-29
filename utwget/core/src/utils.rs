//! Utility functions for utwget.
//!
//! This module provides various utility functions including filename
//! sanitization, size parsing, timestamp formatting, and rate limiting.

use crate::types::{CaseRestriction, RestrictOs};
use std::time::{Duration, Instant};

/// Creates a safe filename by replacing unsafe characters.
///
/// Replaces path separators with underscores and handles control
/// characters and Windows-forbidden characters.
///
/// # Arguments
///
/// * `name` - The original filename.
///
/// # Returns
///
/// A sanitized filename safe for use on the current platform.
///
/// # Example
///
/// ```
/// use ut_core::utils::safe_filename;
///
/// assert_eq!(safe_filename("file.txt"), "file.txt");
/// assert_eq!(safe_filename("path/to/file"), "path_to_file");
/// ```
pub fn safe_filename(name: &str) -> String {
    let mut result = String::with_capacity(name.len());

    for ch in name.chars() {
        match ch {
            '/' | '\\' => {
                result.push('_');
            }
            c if is_control_char(c) => {
                result.push_str(&format!("\\x{:02X}", c as u8));
            }
            c if cfg!(windows) && is_windows_forbidden(c) => {
                result.push('_');
            }
            c => {
                result.push(c);
            }
        }
    }

    result
}

/// Creates a safe filename with custom restrictions.
///
/// Applies OS-specific, control character, non-ASCII, and case restrictions
/// according to the provided parameters.
///
/// # Arguments
///
/// * `name` - The original filename.
/// * `os` - Operating system restrictions to apply.
/// * `ctrl` - Whether to escape control characters.
/// * `nonascii` - Whether to escape non-ASCII characters.
/// * `case` - Case restriction to apply.
///
/// # Returns
///
/// A sanitized filename with all restrictions applied.
pub fn safe_filename_with_restrictions(name: &str, os: RestrictOs, ctrl: bool, nonascii: bool, case: CaseRestriction) -> String {
    let mut result = String::with_capacity(name.len());

    for ch in name.chars() {
        if ch == '/' || ch == '\\' {
            result.push('_');
            continue;
        }
        if ctrl && is_control_char(ch) {
            result.push_str(&format!("\\x{:02X}", ch as u8));
            continue;
        }
        if nonascii && !ch.is_ascii() {
            result.push_str(&format!("\\x{{{:04X}}}", ch as u32));
            continue;
        }
        match os {
            RestrictOs::Windows => {
                if is_windows_forbidden(ch) {
                    result.push('_');
                } else {
                    result.push(ch);
                }
            }
            RestrictOs::Unix => {
                result.push(ch);
            }
        }
    }

    let result = match case {
        CaseRestriction::Lowercase => result.to_ascii_lowercase(),
        CaseRestriction::Uppercase => result.to_ascii_uppercase(),
        CaseRestriction::None => result,
    };

    if result.is_empty() {
        "_".to_string()
    } else {
        result
    }
}

/// Checks if a character is a control character.
fn is_control_char(ch: char) -> bool {
    ch.is_ascii_control()
}

/// Checks if a character is forbidden in Windows filenames.
fn is_windows_forbidden(ch: char) -> bool {
    matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        || (ch as u8) < 32
}

/// Formats a Unix timestamp as a human-readable string.
///
/// # Arguments
///
/// * `epoch_secs` - Unix timestamp in seconds.
///
/// # Returns
///
/// A string in "YYYY-MM-DD HH:MM:SS" format, or the raw number
/// if the timestamp is invalid.
///
/// # Example
///
/// ```
/// use ut_core::utils::format_timestamp;
///
/// assert_eq!(format_timestamp(0), "1970-01-01 00:00:00");
/// ```
pub fn format_timestamp(epoch_secs: i64) -> String {
    chrono::DateTime::from_timestamp(epoch_secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| epoch_secs.to_string())
}

/// Parses a size string with optional suffix.
///
/// Supports suffixes: K/k (kilobytes), M/m (megabytes), G/g (gigabytes),
/// T/t (terabytes). Values can be decimal.
///
/// # Arguments
///
/// * `s` - The size string (e.g., "10M", "1.5G").
///
/// # Returns
///
/// `Some(bytes)` if parsing succeeds, `None` otherwise.
///
/// # Example
///
/// ```
/// use ut_core::utils::parse_size_string;
///
/// assert_eq!(parse_size_string("1K"), Some(1024));
/// assert_eq!(parse_size_string("1.5M"), Some(1572864));
/// ```
pub fn parse_size_string(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, multiplier) = if let Some(suffix) = s.strip_suffix('K') {
        (suffix, 1024u64)
    } else if let Some(suffix) = s.strip_suffix('k') {
        (suffix, 1024u64)
    } else if let Some(suffix) = s.strip_suffix('M') {
        (suffix, 1024 * 1024)
    } else if let Some(suffix) = s.strip_suffix('m') {
        (suffix, 1024 * 1024)
    } else if let Some(suffix) = s.strip_suffix('G') {
        (suffix, 1024 * 1024 * 1024)
    } else if let Some(suffix) = s.strip_suffix('g') {
        (suffix, 1024 * 1024 * 1024)
    } else if let Some(suffix) = s.strip_suffix('T') {
        (suffix, 1024 * 1024 * 1024 * 1024)
    } else if let Some(suffix) = s.strip_suffix('t') {
        (suffix, 1024 * 1024 * 1024 * 1024)
    } else {
        (s, 1u64)
    };

    num_str.trim().parse::<f64>().ok().map(|n| (n * multiplier as f64) as u64)
}
