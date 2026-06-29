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
