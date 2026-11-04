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
