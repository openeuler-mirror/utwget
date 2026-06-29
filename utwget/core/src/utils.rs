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
