//! Unit tests for Metalink downloader — path traversal protection.
//!
//! Tests `sanitize_metalink_filename()` which prevents arbitrary file
//! writes via crafted `<file name="...">` attributes in Metalink
//! documents (CVE-equivalent to GNU wget's `metalink_check_safe_path`).

use ut_metalink::downloader::sanitize_metalink_filename;

#[test]
fn test_normal_name_unchanged() {
    assert_eq!(sanitize_metalink_filename("file.iso"), "file.iso");
    assert_eq!(
        sanitize_metalink_filename("dir/file.iso"),
        "dir/file.iso",
    );
}

#[test]
fn test_strips_leading_slash() {
    // 绝对路径应被剥离前导斜杠，防止写入任意绝对位置
    assert_eq!(sanitize_metalink_filename("/etc/passwd"), "etc/passwd");
    assert_eq!(sanitize_metalink_filename("//etc/passwd"), "etc/passwd");
}

#[test]
fn test_rejects_parent_traversal() {
    // `..` 组件应被丢弃，防止逃逸 output_dir
    assert_eq!(
        sanitize_metalink_filename("../../etc/cron.d/evil"),
        "etc/cron.d/evil",
    );
    assert_eq!(
        sanitize_metalink_filename("../../../etc/passwd"),
        "etc/passwd",
    );
}

#[test]
fn test_rejects_backslash_traversal() {
    // 反斜杠（Windows 分隔符）也应被处理
    assert_eq!(sanitize_metalink_filename("..\\..\\evil"), "evil");
}

#[test]
fn test_empty_name_fallback() {
    assert_eq!(sanitize_metalink_filename(""), "unnamed");
    assert_eq!(sanitize_metalink_filename("/"), "unnamed");
    assert_eq!(sanitize_metalink_filename("///"), "unnamed");
    assert_eq!(sanitize_metalink_filename(".."), "unnamed");
    assert_eq!(sanitize_metalink_filename("../.."), "unnamed");
}

#[test]
fn test_strips_dot_components() {
    assert_eq!(sanitize_metalink_filename("./file.iso"), "file.iso");
    assert_eq!(
        sanitize_metalink_filename("dir/./file.iso"),
        "dir/file.iso",
    );
}
