//! Unit tests for HTML link converter — relative path construction.
//!
//! Tests `relative_path()` which computes a relative path from the
//! source file's directory to the target file, mirroring GNU wget's
//! `construct_relative()` (convert.c:411-447). This is essential for
//! `--convert-links` to produce working offline-browsable links.

use std::path::Path;

use ut_html::converter::relative_path;

#[test]
fn test_same_directory() {
    let result = relative_path(
        Path::new("example.com"),
        Path::new("example.com/page.html"),
    );
    assert_eq!(result, "page.html");
}

#[test]
fn test_subdirectory() {
    // 从父目录指向子目录：无需 `..`
    let result = relative_path(
        Path::new("example.com"),
        Path::new("example.com/sub/page.html"),
    );
    assert_eq!(result, "sub/page.html");
}

#[test]
fn test_parent_directory() {
    // 从子目录指向父目录：需要 `..`
    let result = relative_path(
        Path::new("example.com/sub"),
        Path::new("example.com/page.html"),
    );
    assert_eq!(result, "../page.html");
}

#[test]
fn test_sibling_directory() {
    // 从一个子目录指向另一个子目录：需要 `../other/`
    let result = relative_path(
        Path::new("example.com/sub"),
        Path::new("example.com/other/page.html"),
    );
    assert_eq!(result, "../other/page.html");
}

#[test]
fn test_deep_nesting() {
    // 深层嵌套：共享前缀 `a`，源还需上溯 2 级 (b, c)
    let result = relative_path(
        Path::new("example.com/a/b/c"),
        Path::new("example.com/a/x/y.html"),
    );
    assert_eq!(result, "../../x/y.html");
}
