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

// ============================================================================
// Fragment preservation in link conversion (report 8.4-4)
// ============================================================================

#[test]
fn convert_preserves_fragment_on_local_links() {
    // page1.html links to page2.html#section; page2 downloaded. After -k,
    // the link must become page2.html#section (fragment re-attached).
    let dir = std::env::temp_dir().join(format!("conv_frag_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let html = br#"<html><body><a href="http://x.com/page2.html#section">go</a></body></html>"#;
    std::fs::write(dir.join("page2.html"), b"<html>p2</html>").unwrap();
    let in_path = dir.join("page1.html");
    std::fs::write(&in_path, html).unwrap();

    let mut url_to_local = std::collections::HashMap::new();
    url_to_local.insert("http://x.com/page2.html".to_string(), "page2.html".to_string());

    let converter = ut_html::LinkConverter::new();
    let opts = ut_html::ConvertOptions {
        convert_to_relative: true,
        convert_file_only: false,
        nullify_base: false,
        backup_converted: false,
    };
    converter.convert_links_with_base(
        in_path.to_str().unwrap(),
        &url_to_local,
        &opts,
        Some("http://x.com/page1.html"),
    ).unwrap();

    let converted = std::fs::read_to_string(&in_path).unwrap();
    assert!(
        converted.contains("#section"),
        "fragment must survive conversion, got: {}",
        converted
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================================
// --convert-file-only basename rewriting (report 9.1-4)
// ============================================================================

#[test]
fn convert_file_only_rewrites_basename_only() {
    let dir = std::env::temp_dir().join(format!("conv_fo_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let html = br#"<html><body><a href="http://x.com/deep/dir/page2.html">go</a></body></html>"#;
    let in_path = dir.join("page1.html");
    std::fs::write(&in_path, html).unwrap();
    std::fs::write(dir.join("page2.html"), b"<html>p2</html>").unwrap();

    let mut url_to_local = std::collections::HashMap::new();
    // Local file is at the FLAT dir root, not deep/dir/.
    url_to_local.insert("http://x.com/deep/dir/page2.html".to_string(), "page2.html".to_string());

    let converter = ut_html::LinkConverter::new();
    let opts = ut_html::ConvertOptions {
        convert_to_relative: true,
        convert_file_only: true,
        nullify_base: false,
        backup_converted: false,
    };
    converter.convert_links_with_base(
        in_path.to_str().unwrap(),
        &url_to_local,
        &opts,
        Some("http://x.com/page1.html"),
    ).unwrap();

    let converted = std::fs::read_to_string(&in_path).unwrap();
    assert!(
        converted.contains(r#"href="page2.html""#),
        "basename-only rewrite expected, got: {}",
        converted
    );
    let _ = std::fs::remove_dir_all(&dir);
}
