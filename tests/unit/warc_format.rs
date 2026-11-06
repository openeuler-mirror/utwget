// WARC format 模块单元测试
// 测试 WARC 头部序列化、日期格式化、record ID 生成

use ut_warc::*;

// ========== WARC 头部序列化测试 ==========

#[test]
fn test_warc_version() {
    // 验证 WARC 版本字符串
    assert_eq!(format::WARC_VERSION, "WARC/1.1");
}

#[test]
fn test_warc_header_serialize_basic() {
    // 基本头部序列化
    let header = format::WarcHeader {
        record_type: format::WarcRecordType::Resource,
        record_id: "<urn:uuid:test-id>".to_string(),
        date: "2025-06-17T00:00:00Z".to_string(),
        content_length: 100,
        concurrent_to: vec![],
        content_type: "text/html".to_string(),
        target_uri: "http://example.com/".to_string(),
        gzip_compressed: false,
        truncated: None,
        wagon: None,
    };

    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();

    // 验证基本字段
    assert!(text.starts_with("WARC/1.1\r\n"));
    assert!(text.contains("WARC-Type: resource\r\n"));
    assert!(text.contains("WARC-Date: 2025-06-17T00:00:00Z\r\n"));
    assert!(text.contains("WARC-Record-ID: <urn:uuid:test-id>\r\n"));
    assert!(text.contains("Content-Type: text/html\r\n"));
    assert!(text.contains("Content-Length: 100\r\n"));
    assert!(text.contains("WARC-Target-URI: http://example.com/\r\n"));
}

#[test]
fn test_warc_header_serialize_all_record_types() {
    // 测试所有记录类型
    let types = [
        (format::WarcRecordType::Warcinfo, "warcinfo"),
        (format::WarcRecordType::Response, "response"),
        (format::WarcRecordType::Resource, "resource"),
        (format::WarcRecordType::Request, "request"),
        (format::WarcRecordType::Metadata, "metadata"),
        (format::WarcRecordType::Conversion, "conversion"),
        (format::WarcRecordType::Continuation, "continuation"),
    ];

    for (record_type, expected_str) in types {
        let header = format::WarcHeader {
            record_type,
            record_id: "<urn:uuid:test>".to_string(),
            date: "2025-06-17T00:00:00Z".to_string(),
            content_length: 0,
            concurrent_to: vec![],
            content_type: "application/octet-stream".to_string(),
            target_uri: String::new(),
            gzip_compressed: false,
            truncated: None,
            wagon: None,
        };

        let bytes = header.serialize();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(&format!("WARC-Type: {}\r\n", expected_str)));
    }
}
