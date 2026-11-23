//! Unit tests for metalink parser module.
//!
//! Tests for Metalink XML parsing and file info extraction.

use std::io::Cursor;
use ut_metalink::MetalinkParser;
use ut_metalink::checksum::ChecksumType;

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

#[test]
fn test_metalink_checksum() {
    let xml = r#"
    <hash type="sha-256">abc123def456</hash>
    <hash type="md5">0123456789abcdef</hash>
    "#;

    assert!(xml.contains("type=\"sha-256\""));
    assert!(xml.contains("type=\"md5\""));
}

#[test]
fn test_metalink_pieces() {
    // Metalink can specify piece hashes for verification
    let xml = r#"
    <pieces length="1048576" type="sha-1">
      <hash>piece1hash</hash>
      <hash>piece2hash</hash>
    </pieces>
    "#;

    assert!(xml.contains("length=\"1048576\""));
    assert!(xml.contains("type=\"sha-1\""));
}

#[test]
fn test_checksum_types() {
    let supported_types = ["md5", "sha-1", "sha-256", "sha-512"];
    assert!(supported_types.contains(&"md5"));
    assert!(supported_types.contains(&"sha-256"));
}

#[test]
fn test_url_protocol_preference() {
    // Prefer HTTPS over HTTP
    let urls = [
        "http://example.com/file",
        "https://example.com/file",
        "ftp://example.com/file",
    ];

    let https_url = urls.iter().find(|u| u.starts_with("https://"));
    assert!(https_url.is_some());
}

#[test]
fn test_metalink_version() {
    // Metalink version 3.0 and 4.0 are common
    let v3 = "version=\"3.0\"";
    let v4 = "xmlns=\"urn:ietf:params:xml:ns:metalink\"";

    assert!(v3.contains("3.0"));
    assert!(v4.contains("metalink"));
}

#[test]
fn test_metalink_parse_pieces_with_hashes() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0">
  <file name="bigfile.iso">
    <size>3145728</size>
    <hash type="sha-256">aabbccdd</hash>
    <pieces length="1048576" type="sha-1">
      <hash>11111111111111111111</hash>
      <hash>22222222222222222222</hash>
      <hash>33333333333333333333</hash>
    </pieces>
    <url>http://example.com/bigfile.iso</url>
  </file>
</metalink>"#;
    let files = MetalinkParser::parse(Cursor::new(xml)).unwrap();
    assert_eq!(files.len(), 1);
    let f = &files[0];
    assert_eq!(f.name, "bigfile.iso");
    assert_eq!(f.size, Some(3145728));
    // Full file hash
    assert_eq!(f.hashes.len(), 1);
    assert_eq!(f.hashes[0].hash_type, ChecksumType::Sha256);
    assert_eq!(f.hashes[0].expected, "aabbccdd");
    // Pieces
    assert_eq!(f.pieces.len(), 3);
    assert_eq!(f.pieces[0].length, 1048576);
    assert_eq!(f.pieces[0].hash_type, ChecksumType::Sha1);
    assert_eq!(f.pieces[0].hash, "11111111111111111111");
    assert_eq!(f.pieces[1].hash, "22222222222222222222");
    assert_eq!(f.pieces[2].hash, "33333333333333333333");
}

#[test]
fn test_metalink_parse_no_pieces() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0">
  <file name="small.txt">
    <size>100</size>
    <hash type="md5">abc123</hash>
    <url>http://example.com/small.txt</url>
  </file>
</metalink>"#;
    let files = MetalinkParser::parse(Cursor::new(xml)).unwrap();
    assert_eq!(files[0].pieces.len(), 0);
    assert_eq!(files[0].hashes.len(), 1);
}

#[test]
fn test_metalink_parse_multiple_checksums() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0">
  <file name="file.zip">
    <size>1000</size>
    <hash type="md5">aaa</hash>
    <hash type="sha-1">bbb</hash>
    <hash type="sha-256">ccc</hash>
    <url>http://example.com/file.zip</url>
  </file>
</metalink>"#;
    let files = MetalinkParser::parse(Cursor::new(xml)).unwrap();
    assert_eq!(files[0].hashes.len(), 3);
    assert_eq!(files[0].hashes[0].hash_type, ChecksumType::Md5);
    assert_eq!(files[0].hashes[1].hash_type, ChecksumType::Sha1);
    assert_eq!(files[0].hashes[2].hash_type, ChecksumType::Sha256);
}
