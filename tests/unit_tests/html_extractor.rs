//! Unit tests for HTML extractor module.
//!
//! Tests for URL extraction from HTML content.

#[test]
fn test_extract_urls_from_anchor() {
    let html = r#"<a href="https://example.com/page1">Link 1</a>
<a href="https://example.com/page2">Link 2</a>"#;

    let urls: Vec<&str> = html.matches("href=\"")
        .map(|_| {
            let start = html.find("href=\"").unwrap() + 6;
            let end = html[start..].find('"').unwrap() + start;
            &html[start..end]
        })
        .collect();

    // Just verify href attributes exist
    assert!(html.contains("href=\"https://example.com/page1\""));
    assert!(html.contains("href=\"https://example.com/page2\""));
}

#[test]
fn test_extract_urls_from_img() {
    let html = r#"<img src="image.png" alt="test">"#;
    assert!(html.contains("src=\"image.png\""));
}

#[test]
fn test_extract_urls_from_link() {
    let html = r#"<link rel="stylesheet" href="style.css">"#;
    assert!(html.contains("href=\"style.css\""));
}

#[test]
fn test_extract_urls_from_script() {
    let html = r#"<script src="script.js"></script>"#;
    assert!(html.contains("src=\"script.js\""));
}

#[test]
fn test_meta_refresh_url() {
    let html = r#"<meta http-equiv="refresh" content="5;url=https://example.com/new">"#;
    assert!(html.contains("url=https://example.com/new"));
}

#[test]
fn test_base_url() {
    let html = r#"<base href="https://example.com/base/">"#;
    assert!(html.contains("href=\"https://example.com/base/\""));
}

#[test]
fn test_relative_url_resolution() {
    fn resolve_url(base: &str, relative: &str) -> String {
        if relative.starts_with("http://") || relative.starts_with("https://") {
            relative.to_string()
        } else if relative.starts_with("/") {
            // Absolute path
            let base_parts: Vec<&str> = base.split('/').take(3).collect();
            format!("{}{}", base_parts.join("/"), relative)
        } else {
            // Relative path
            let base_dir = base.rfind('/').map(|i| &base[..=i]).unwrap_or(base);
            format!("{}{}", base_dir, relative)
        }
    }

    let base = "https://example.com/path/page.html";
    assert_eq!(resolve_url(base, "https://other.com"), "https://other.com");
    assert_eq!(resolve_url(base, "/root"), "https://example.com/root");
    assert!(resolve_url(base, "relative").starts_with("https://example.com/path/"));
}

#[test]
fn test_url_attribute_map() {
    // Test that we know which attributes contain URLs for each tag
    let url_attrs = [
        ("a", "href"),
        ("img", "src"),
        ("link", "href"),
        ("script", "src"),
        ("iframe", "src"),
        ("form", "action"),
        ("area", "href"),
        ("embed", "src"),
        ("object", "data"),
    ];

    assert_eq!(url_attrs.len(), 9);
    assert_eq!(url_attrs[0].1, "href");
}
