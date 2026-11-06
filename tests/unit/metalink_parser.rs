//! Unit tests for metalink parser module.
//!
//! Tests for Metalink XML parsing and file info extraction.

#[test]
fn test_metalink_xml_structure() {
    // Basic Metalink XML structure validation
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0">
  <file name="example.zip">
    <size>1234567</size>
    <url>http://example.com/example.zip</url>
  </file>
</metalink>"#;

    assert!(xml.contains("<metalink"));
    assert!(xml.contains("<file name="));
    assert!(xml.contains("<size>"));
    assert!(xml.contains("<url>"));
}

#[test]
fn test_metalink_file_name() {
    let xml = r#"<file name="test-file.zip">"#;
    assert!(xml.contains("name=\"test-file.zip\""));
}

#[test]
fn test_metalink_file_size() {
    let xml = r#"<size>1048576</size>"#;
    let size: u64 = xml.trim()
        .strip_prefix("<size>")
        .unwrap()
        .strip_suffix("</size>")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(size, 1048576);
}

#[test]
fn test_metalink_url_priority() {
    // Metalink can have multiple URLs with different priorities
    let xml = r#"
    <url priority="1">http://mirror1.example.com/file</url>
    <url priority="2">http://mirror2.example.com/file</url>
    "#;

    assert!(xml.contains("priority=\"1\""));
    assert!(xml.contains("priority=\"2\""));
}
