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
