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
