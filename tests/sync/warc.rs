// WARC 测试 - 格式序列化、SHA1 digest 计算、CDX 索引行格式

// ========== WARC 格式序列化测试 ==========

#[test]
fn test_warc_version_string() {
    use ut_warc::format::WARC_VERSION;
    assert_eq!(WARC_VERSION, "WARC/1.1");
}

#[test]
fn test_warc_header_serialize_all_types() {
    use ut_warc::format::{WarcHeader, WarcRecordType};
    let types = vec![
        (WarcRecordType::Warcinfo, "warcinfo"),
        (WarcRecordType::Response, "response"),
        (WarcRecordType::Resource, "resource"),
        (WarcRecordType::Request, "request"),
        (WarcRecordType::Metadata, "metadata"),
        (WarcRecordType::Conversion, "conversion"),
        (WarcRecordType::Continuation, "continuation"),
    ];
    for (record_type, expected_str) in types {
        let header = WarcHeader {
            record_type,
            record_id: "<urn:uuid:test>".into(),
            date: "2025-06-09T00:00:00Z".into(),
            content_length: 0,
            concurrent_to: Vec::new(),
            content_type: "application/http;msgtype=response".into(),
            target_uri: String::new(),
            gzip_compressed: false,
            truncated: None,
            wagon: None,
        };
        let bytes = header.serialize();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(&format!("WARC-Type: {}", expected_str)));
    }
}

#[test]
fn test_warc_header_with_target_uri() {
    use ut_warc::format::{WarcHeader, WarcRecordType};
    let header = WarcHeader {
        record_type: WarcRecordType::Resource,
        record_id: "<urn:uuid:abc>".into(),
        date: "2025-01-01T00:00:00Z".into(),
        content_length: 50,
        concurrent_to: Vec::new(),
        content_type: "text/html".into(),
        target_uri: "http://example.com/page".into(),
        gzip_compressed: false,
        truncated: None,
        wagon: None,
    };
    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("WARC-Target-URI: http://example.com/page\r\n"));
    assert!(text.contains("Content-Length: 50\r\n"));
    assert!(text.contains("Content-Type: text/html\r\n"));
    assert!(text.contains("WARC-Record-ID: <urn:uuid:abc>\r\n"));
    assert!(text.contains("WARC-Date: 2025-01-01T00:00:00Z\r\n"));
}

#[test]
fn test_warc_header_with_concurrent_to() {
    use ut_warc::format::{WarcHeader, WarcRecordType};
    let header = WarcHeader {
        record_type: WarcRecordType::Metadata,
        record_id: "<urn:uuid:meta>".into(),
        date: "2025-06-09T12:00:00Z".into(),
        content_length: 100,
        concurrent_to: vec!["<urn:uuid:req>".into(), "<urn:uuid:res>".into()],
        content_type: "application/warc-fields".into(),
        target_uri: "http://example.com/".into(),
        gzip_compressed: false,
        truncated: Some("time".into()),
        wagon: None,
    };
    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("WARC-Concurrent-To: <urn:uuid:req>"));
    assert!(text.contains("WARC-Concurrent-To: <urn:uuid:res>"));
    assert!(text.contains("WARC-Truncated: time"));
}

#[test]
fn test_warc_header_gzip_compressed() {
    use ut_warc::format::{WarcHeader, WarcRecordType};
    let header = WarcHeader {
        record_type: WarcRecordType::Response,
        record_id: "<urn:uuid:g>".into(),
        date: "2025-01-01T00:00:00Z".into(),
        content_length: 200,
        concurrent_to: Vec::new(),
        content_type: "application/gzip".into(),
        target_uri: String::new(),
        gzip_compressed: true,
        truncated: None,
        wagon: None,
    };
    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("WARC-Payload-Digest: sha1:"));
}

#[test]
fn test_warc_header_terminates_with_double_crlf() {
    use ut_warc::format::{WarcHeader, WarcRecordType};
    let header = WarcHeader {
        record_type: WarcRecordType::Resource,
        record_id: "<urn:uuid:x>".into(),
        date: "2025-01-01T00:00:00Z".into(),
        content_length: 0,
        concurrent_to: Vec::new(),
        content_type: "text/plain".into(),
        target_uri: String::new(),
        gzip_compressed: false,
        truncated: None,
        wagon: None,
    };
    let bytes = header.serialize();
    assert!(bytes.ends_with(b"\r\n\r\n"));
}

#[test]
fn test_default_content_type() {
    use ut_warc::format::default_content_type;
    assert_eq!(default_content_type(false), "application/http;msgtype=response");
    assert_eq!(default_content_type(true), "application/gzip");
}

#[test]
fn test_record_separator() {
    use ut_warc::format::record_separator;
    assert_eq!(record_separator(), b"\r\n\r\n");
}

// ========== SHA1 digest 计算测试 ==========

#[test]
fn test_warc_sha1_empty_input() {
    use ut_warc::digest::compute_sha1;
    let hash = compute_sha1(b"");
    assert_eq!(hash, "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn test_warc_sha1_sha1_known_vector() {
    use ut_warc::digest::compute_sha1;
    let hash = compute_sha1(b"abc");
    assert_eq!(hash, "sha1:a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn test_warc_sha1_format_prefix() {
    use ut_warc::digest::compute_sha1;
    let hash = compute_sha1(b"test");
    assert!(hash.starts_with("sha1:"));
    let hex = &hash[5..];
    assert_eq!(hex.len(), 40);
}

#[test]
fn test_warc_sha1_large_input() {
    use ut_warc::digest::compute_sha1;
    let data = vec![0u8; 10000];
    let hash = compute_sha1(&data);
    assert!(hash.starts_with("sha1:"));
    assert_eq!(hash.len(), 45);
}

#[test]
fn test_warc_digest_incremental() {
    use ut_warc::WarcDigest;
    let mut digest = WarcDigest::new();
    digest.update(b"hello ");
    digest.update(b"world");
    let result = digest.finalize();
    assert!(result.starts_with("sha1:"));
}

#[test]
fn test_warc_compute_file_sha1() {
    use ut_warc::digest::compute_file_sha1;
    let path = std::path::Path::new("/tmp/wget_sha1_test.txt");
    std::fs::write(path, b"test content").unwrap();
    let hash = compute_file_sha1(path).unwrap();
    assert!(hash.starts_with("sha1:"));
    let _ = std::fs::remove_file(path);
}

// ========== CDX 索引行格式测试 ==========

#[test]
fn test_warc_format_date() {
    use ut_warc::format_date;
    use chrono::{TimeZone, Utc};
    let dt = Utc.with_ymd_and_hms(2025, 6, 9, 12, 0, 0).single().unwrap();
    assert_eq!(format_date(dt), "2025-06-09T12:00:00Z");
}

#[test]
fn test_warc_format_record_id() {
    use ut_warc::format_record_id;
    let id = format_record_id().unwrap();
    assert!(id.starts_with("<urn:uuid:"));
    assert!(id.ends_with(">"));
    // UUID format: <urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx>
    // Length: 2 (angle brackets) + 9 (urn:uuid:) + 36 (UUID) = 47
    assert_eq!(id.len(), 47);
}

#[test]
fn test_warc_cdx_line_field_count() {
    use ut_warc::WarcWriterImpl;
    use ut_warc::WarcWriter;
    
    let dir = std::env::temp_dir().join("wget_test_cdx_fields");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("test_fields.warc");
    {
        let mut writer = WarcWriterImpl::new(path.clone(), false, false, None, true).unwrap();
        let now = chrono::Utc::now();
        writer.write_resource("http://a.com/index.html", "text/html", b"<html></html>", now).unwrap();
        writer.write_resource("http://b.com/style.css", "text/css", b"body {}", now).unwrap();
    }
    let cdx_path = dir.join("test_fields.warc.cdx");
    let cdx_content = std::fs::read_to_string(&cdx_path).unwrap();
    let lines: Vec<&str> = cdx_content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3);
    for line in &lines[1..] {
        let fields: Vec<&str> = line.split(' ').collect();
        // CDX line has 12 fields based on the format in add_cdx_entry
        assert_eq!(fields.len(), 12);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_warc_cdx_url_field() {
    use ut_warc::WarcWriterImpl;
    use ut_warc::WarcWriter;
    
    let dir = std::env::temp_dir().join("wget_test_cdx_url");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("url.warc");
    {
        let mut writer = WarcWriterImpl::new(path.clone(), false, false, None, true).unwrap();
        let now = chrono::Utc::now();
        writer.write_resource("http://example.com/page.html", "text/html", b"data", now).unwrap();
    }
    let cdx_path = dir.join("url.warc.cdx");
    let cdx_content = std::fs::read_to_string(&cdx_path).unwrap();
    let data_lines: Vec<&str> = cdx_content.lines().filter(|l| !l.is_empty() && l.contains("example.com")).collect();
    assert_eq!(data_lines.len(), 1);
    assert!(data_lines[0].starts_with("http://example.com/page.html"));
    let _ = std::fs::remove_dir_all(&dir);
}
