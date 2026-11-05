//! Unit tests for utility functions.

use ut_core::utils::{safe_filename, parse_size_string, format_timestamp};
use ut_core::types::{RestrictOs, CaseRestriction};
use ut_core::utils::safe_filename_with_restrictions;

// ============================================================================
// safe_filename Tests
// ============================================================================

#[test]
fn test_safe_filename_simple() {
    assert_eq!(safe_filename("file.txt"), "file.txt");
}

#[test]
fn test_safe_filename_with_slash() {
    assert_eq!(safe_filename("path/to/file.txt"), "path_to_file.txt");
}

#[test]
fn test_safe_filename_with_backslash() {
    assert_eq!(safe_filename("path\\to\\file.txt"), "path_to_file.txt");
}

#[test]
fn test_safe_filename_multiple_slashes() {
    assert_eq!(safe_filename("a/b/c/d/file.txt"), "a_b_c_d_file.txt");
}

#[test]
fn test_safe_filename_no_extension() {
    assert_eq!(safe_filename("filename"), "filename");
}

#[test]
fn test_safe_filename_dots() {
    assert_eq!(safe_filename(".hidden"), ".hidden");
    assert_eq!(safe_filename(".."), "..");
}

#[test]
fn test_safe_filename_special_chars() {
    // Characters like ? * < > etc. should be preserved on Unix
    assert_eq!(safe_filename("file?name.txt"), "file?name.txt");
    assert_eq!(safe_filename("file*name.txt"), "file*name.txt");
}

#[test]
fn test_safe_filename_unicode() {
    assert_eq!(safe_filename("文件.txt"), "文件.txt");
    assert_eq!(safe_filename("файл.txt"), "файл.txt");
}

#[test]
fn test_safe_filename_empty() {
    assert_eq!(safe_filename(""), "");
}

#[test]
fn test_safe_filename_control_chars() {
    // Control characters should be escaped
    let result = safe_filename("file\x01name.txt");
    assert!(result.contains("\\x"));
}

// ============================================================================
// safe_filename_with_restrictions Tests
// ============================================================================

#[test]
fn test_safe_filename_restrictions_unix() {
    let result = safe_filename_with_restrictions(
        "file.txt",
        RestrictOs::Unix,
        false,
        false,
        CaseRestriction::None,
    );
    assert_eq!(result, "file.txt");
}

#[test]
fn test_safe_filename_restrictions_windows() {
    let result = safe_filename_with_restrictions(
        "file<name>.txt",
        RestrictOs::Windows,
        false,
        false,
        CaseRestriction::None,
    );
    // < is forbidden on Windows
    assert_eq!(result, "file_name_.txt");
}

#[test]
fn test_safe_filename_restrictions_lowercase() {
    let result = safe_filename_with_restrictions(
        "FILE.TXT",
        RestrictOs::Unix,
        false,
        false,
        CaseRestriction::Lowercase,
    );
    assert_eq!(result, "file.txt");
}

#[test]
fn test_safe_filename_restrictions_uppercase() {
    let result = safe_filename_with_restrictions(
        "file.txt",
        RestrictOs::Unix,
        false,
        false,
        CaseRestriction::Uppercase,
    );
    assert_eq!(result, "FILE.TXT");
}

#[test]
fn test_safe_filename_restrictions_ctrl_chars() {
    let result = safe_filename_with_restrictions(
        "file\x01name.txt",
        RestrictOs::Unix,
        true,
        false,
        CaseRestriction::None,
    );
    assert!(result.contains("\\x"));
}

#[test]
fn test_safe_filename_restrictions_nonascii() {
    let result = safe_filename_with_restrictions(
        "文件.txt",
        RestrictOs::Unix,
        false,
        true,
        CaseRestriction::None,
    );
    assert!(result.contains("\\x"));
}

#[test]
fn test_safe_filename_restrictions_empty() {
    let result = safe_filename_with_restrictions(
        "",
        RestrictOs::Unix,
        false,
        false,
        CaseRestriction::None,
    );
    assert_eq!(result, "_");
}

// ============================================================================
// parse_size_string Tests
// ============================================================================

#[test]
fn test_parse_size_string_bytes() {
    assert_eq!(parse_size_string("1024"), Some(1024));
    assert_eq!(parse_size_string("0"), Some(0));
    assert_eq!(parse_size_string("1"), Some(1));
}

#[test]
fn test_parse_size_string_kilobytes() {
    assert_eq!(parse_size_string("1K"), Some(1024));
    assert_eq!(parse_size_string("1k"), Some(1024));
    assert_eq!(parse_size_string("2K"), Some(2048));
    assert_eq!(parse_size_string("10K"), Some(10240));
}

#[test]
fn test_parse_size_string_megabytes() {
    assert_eq!(parse_size_string("1M"), Some(1024 * 1024));
    assert_eq!(parse_size_string("1m"), Some(1024 * 1024));
    assert_eq!(parse_size_string("5M"), Some(5 * 1024 * 1024));
}

#[test]
fn test_parse_size_string_gigabytes() {
    assert_eq!(parse_size_string("1G"), Some(1024 * 1024 * 1024));
    assert_eq!(parse_size_string("1g"), Some(1024 * 1024 * 1024));
    assert_eq!(parse_size_string("2G"), Some(2 * 1024 * 1024 * 1024));
}

#[test]
fn test_parse_size_string_terabytes() {
    let tb: u64 = 1024 * 1024 * 1024 * 1024;
    assert_eq!(parse_size_string("1T"), Some(tb));
    assert_eq!(parse_size_string("1t"), Some(tb));
}

#[test]
fn test_parse_size_string_decimal() {
    assert_eq!(parse_size_string("1.5K"), Some(1536));
    assert_eq!(parse_size_string("0.5M"), Some(512 * 1024));
    assert_eq!(parse_size_string("2.5G"), Some((2.5 * 1024.0 * 1024.0 * 1024.0) as u64));
}

#[test]
fn test_parse_size_string_with_whitespace() {
    assert_eq!(parse_size_string(" 1024 "), Some(1024));
    assert_eq!(parse_size_string(" 1K "), Some(1024));
}

#[test]
fn test_parse_size_string_invalid() {
    assert_eq!(parse_size_string(""), None);
    assert_eq!(parse_size_string("abc"), None);
    assert_eq!(parse_size_string("1X"), None); // Invalid suffix
}

#[test]
fn test_parse_size_string_large() {
    assert_eq!(parse_size_string("100M"), Some(100 * 1024 * 1024));
    assert_eq!(parse_size_string("1000K"), Some(1000 * 1024));
}
