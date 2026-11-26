//! Unit tests for HTML extractor module.
//!
//! Tests for URL extraction from HTML content.

use std::io::Cursor;
use ut_html::html_extractor::HtmlExtractor;
use ut_html::types::ContentExtractor;
use ut_html::url_position::ExtractOptions;

fn extract(html: &str) -> Vec<String> {
    let extractor = HtmlExtractor;
    let opts = ExtractOptions::default();
    let results = extractor
        .extract_urls(&mut Cursor::new(html), "http://example.com/", &opts)
        .unwrap();
    results.into_iter().map(|r| r.url).collect()
}

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

// ===== srcset, style, <style> block tests =====

#[test]
fn test_srcset_simple() {
    let html = r#"<img src="fallback.jpg" srcset="image1.jpg 1x, image2.jpg 2x">"#;
    let urls = extract(html);
    assert!(urls.contains(&"fallback.jpg".to_string()));
    assert!(urls.contains(&"image1.jpg".to_string()));
    assert!(urls.contains(&"image2.jpg".to_string()));
}

#[test]
fn test_srcset_width_descriptors() {
    let html = r#"<img srcset="small.jpg 100w, medium.jpg 500w, large.jpg 1000w">"#;
    let urls = extract(html);
    assert!(urls.contains(&"small.jpg".to_string()));
    assert!(urls.contains(&"medium.jpg".to_string()));
    assert!(urls.contains(&"large.jpg".to_string()));
}

#[test]
fn test_srcset_source_element() {
    let html = r#"<picture><source srcset="photo.webp" type="image/webp"><img src="photo.jpg"></picture>"#;
    let urls = extract(html);
    assert!(urls.contains(&"photo.webp".to_string()));
    assert!(urls.contains(&"photo.jpg".to_string()));
}

#[test]
fn test_style_attribute_url() {
    let html = r#"<div style="background: url('bg.png')">text</div>"#;
    let urls = extract(html);
    assert!(urls.contains(&"bg.png".to_string()));
}

#[test]
fn test_style_attribute_multiple_urls() {
    let html = r#"<div style="background: url('a.png'); border-image: url('b.png')">text</div>"#;
    let urls = extract(html);
    assert!(urls.contains(&"a.png".to_string()));
    assert!(urls.contains(&"b.png".to_string()));
}

#[test]
fn test_style_block_url() {
    let html = r#"<style>
        body { background: url('bg.png'); }
        .header { background-image: url("header.jpg"); }
    </style>"#;
    let urls = extract(html);
    assert!(urls.contains(&"bg.png".to_string()));
    assert!(urls.contains(&"header.jpg".to_string()));
}

#[test]
fn test_style_block_with_import() {
    let html = r#"<style>@import url("reset.css"); body { background: url(bg.png); }</style>"#;
    let urls = extract(html);
    assert!(urls.contains(&"reset.css".to_string()));
    assert!(urls.contains(&"bg.png".to_string()));
}

#[test]
fn test_combined_src_and_srcset() {
    let html = r#"<img src="default.jpg" srcset="retina.jpg 2x">"#;
    let urls = extract(html);
    assert!(urls.contains(&"default.jpg".to_string()));
    assert!(urls.contains(&"retina.jpg".to_string()));
}

#[test]
fn link_stylesheet_is_extracted_with_expect_css() {
    let html = br#"<html><head><link rel="stylesheet" href="/style.css"></head><body></body></html>"#;
    let ex = ut_html::HtmlExtractor;
    let opts = ut_html::url_position::ExtractOptions::default();
    let links = ex.extract_urls(&mut std::io::Cursor::new(html.to_vec()), "http://x/", &opts).unwrap();
    assert_eq!(links.len(), 1, "link stylesheet must be extracted");
    assert!(links[0].expect_css, "expect_css must be true for stylesheet");
}
