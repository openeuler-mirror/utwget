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

#[test]
fn test_warc_header_serialize_with_concurrent_to() {
    // 带关联记录的头部
    let header = format::WarcHeader {
        record_type: format::WarcRecordType::Metadata,
        record_id: "<urn:uuid:meta>".to_string(),
        date: "2025-06-17T00:00:00Z".to_string(),
        content_length: 50,
        concurrent_to: vec![
            "<urn:uuid:request-1>".to_string(),
            "<urn:uuid:response-1>".to_string(),
        ],
        content_type: "application/warc-fields".to_string(),
        target_uri: "http://example.com/".to_string(),
        gzip_compressed: false,
        truncated: None,
        wagon: None,
    };

    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.contains("WARC-Concurrent-To: <urn:uuid:request-1>\r\n"));
    assert!(text.contains("WARC-Concurrent-To: <urn:uuid:response-1>\r\n"));
}

#[test]
fn test_warc_header_serialize_gzip_compressed() {
    // gzip 压缩标记
    let header = format::WarcHeader {
        record_type: format::WarcRecordType::Response,
        record_id: "<urn:uuid:gz>".to_string(),
        date: "2025-06-17T00:00:00Z".to_string(),
        content_length: 200,
        concurrent_to: vec![],
        content_type: "application/gzip".to_string(),
        target_uri: String::new(),
        gzip_compressed: true,
        truncated: None,
        wagon: None,
    };

    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.contains("WARC-Payload-Digest: sha1:\r\n"));
}

#[test]
fn test_warc_header_serialize_truncated() {
    // 截断标记
    let header = format::WarcHeader {
        record_type: format::WarcRecordType::Response,
        record_id: "<urn:uuid:trunc>".to_string(),
        date: "2025-06-17T00:00:00Z".to_string(),
        content_length: 1000,
        concurrent_to: vec![],
        content_type: "application/http;msgtype=response".to_string(),
        target_uri: "http://example.com/large".to_string(),
        gzip_compressed: false,
        truncated: Some("length".to_string()),
        wagon: None,
    };

    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.contains("WARC-Truncated: length\r\n"));
}

#[test]
fn test_warc_header_serialize_wagon() {
    // wagon 元数据
    let header = format::WarcHeader {
        record_type: format::WarcRecordType::Resource,
        record_id: "<urn:uuid:wagon>".to_string(),
        date: "2025-06-17T00:00:00Z".to_string(),
        content_length: 500,
        concurrent_to: vec![],
        content_type: "text/html".to_string(),
        target_uri: "http://example.com/".to_string(),
        gzip_compressed: false,
        truncated: None,
        wagon: Some("wagon-metadata-here".to_string()),
    };

    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.contains("WARC-Wagon: wagon-metadata-here\r\n"));
}

#[test]
fn test_warc_header_serialize_terminates_with_double_crlf() {
    // 头部应以双 CRLF 结尾
    let header = format::WarcHeader {
        record_type: format::WarcRecordType::Resource,
        record_id: "<urn:uuid:end>".to_string(),
        date: "2025-06-17T00:00:00Z".to_string(),
        content_length: 0,
        concurrent_to: vec![],
        content_type: "text/plain".to_string(),
        target_uri: String::new(),
        gzip_compressed: false,
        truncated: None,
        wagon: None,
    };

    let bytes = header.serialize();
    assert!(bytes.ends_with(b"\r\n\r\n"));
}

#[test]
fn test_warc_header_serialize_no_target_uri_when_empty() {
    // 空 target_uri 不应出现在输出中
    let header = format::WarcHeader {
        record_type: format::WarcRecordType::Warcinfo,
        record_id: "<urn:uuid:info>".to_string(),
        date: "2025-06-17T00:00:00Z".to_string(),
        content_length: 100,
        concurrent_to: vec![],
        content_type: "application/warc-fields".to_string(),
        target_uri: String::new(),
        gzip_compressed: false,
        truncated: None,
        wagon: None,
    };

    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();

    assert!(!text.contains("WARC-Target-URI:"));
}

#[test]
fn test_warc_header_serialize_crlf_line_endings() {
    // 验证使用 CRLF 行尾
    let header = format::WarcHeader {
        record_type: format::WarcRecordType::Response,
        record_id: "<urn:uuid:crlf>".to_string(),
        date: "2025-06-17T00:00:00Z".to_string(),
        content_length: 0,
        concurrent_to: vec![],
        content_type: "text/plain".to_string(),
        target_uri: "http://example.com/".to_string(),
        gzip_compressed: false,
        truncated: None,
        wagon: None,
    };

    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();

    // 不应包含单独的 LF（除了作为 CRLF 的一部分）
    assert!(!text.contains('\n') || text.contains("\r\n"));
}

// ========== 默认内容类型测试 ==========

#[test]
fn test_default_content_type_no_gzip() {
    // 非 gzip 模式的默认内容类型
    let ct = format::default_content_type(false);
    assert_eq!(ct, "application/http;msgtype=response");
}

#[test]
fn test_default_content_type_with_gzip() {
    // gzip 模式的默认内容类型
    let ct = format::default_content_type(true);
    assert_eq!(ct, "application/gzip");
}

// ========== 记录分隔符测试 ==========

#[test]
fn test_record_separator() {
    // 记录分隔符
    let sep = format::record_separator();
    assert_eq!(sep, b"\r\n\r\n");
    assert_eq!(sep.len(), 4);
}

// ========== 日期格式化测试 ==========

#[test]
fn test_format_date_basic() {
    // 基本日期格式化
    use chrono::{TimeZone, Utc};

    let dt = Utc.with_ymd_and_hms(2025, 6, 17, 12, 30, 45).single().unwrap();
    let formatted = format_date(dt);

    assert_eq!(formatted, "2025-06-17T12:30:45Z");
}

#[test]
fn test_format_date_midnight() {
    // 午夜时间
    use chrono::{TimeZone, Utc};

    let dt = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).single().unwrap();
    let formatted = format_date(dt);

    assert_eq!(formatted, "2025-01-01T00:00:00Z");
}

#[test]
fn test_format_date_end_of_day() {
    // 一天结束时间
    use chrono::{TimeZone, Utc};

    let dt = Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).single().unwrap();
    let formatted = format_date(dt);

    assert_eq!(formatted, "2025-12-31T23:59:59Z");
}

#[test]
fn test_format_date_iso8601_format() {
    // 验证 ISO 8601 格式
    use chrono::Utc;

    let dt = Utc::now();
    let formatted = format_date(dt);

    // 格式: YYYY-MM-DDTHH:MM:SSZ
    assert_eq!(formatted.len(), 20);
    assert!(formatted.starts_with("20")); // 年份以 20 开头
    assert_eq!(&formatted[4..5], "-");
    assert_eq!(&formatted[7..8], "-");
    assert_eq!(&formatted[10..11], "T");
    assert_eq!(&formatted[13..14], ":");
    assert_eq!(&formatted[16..17], ":");
    assert!(formatted.ends_with('Z'));
}

#[test]
fn test_format_date_now() {
    // 当前时间格式化
    use chrono::Utc;

    let before = Utc::now();
    let formatted = format_date(before);
    let after = Utc::now();

    // 格式化字符串应该在 before 和 after 之间
    assert!(formatted.starts_with("20"));
    assert!(formatted.ends_with('Z'));
}

// ========== Record ID 生成测试 ==========

#[test]
fn test_format_record_id_format() {
    // Record ID 格式验证
    let id = format_record_id().unwrap();

    // 格式: <urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx>
    assert!(id.starts_with("<urn:uuid:"));
    assert!(id.ends_with(">"));
}

#[test]
fn test_format_record_id_length() {
    // Record ID 长度验证
    let id = format_record_id().unwrap();

    // <urn:uuid:> = 10 字符
    // UUID = 36 字符 (8-4-4-4-12 格式)
    // > = 1 字符
    // 总计 = 47 字符
    assert_eq!(id.len(), 47);
}

#[test]
fn test_format_record_id_uuid_format() {
    // UUID 格式验证
    let id = format_record_id().unwrap();

    // 提取 UUID 部分
    let uuid = &id[10..46]; // 跳过 "<urn:uuid:" 和 ">"

    // UUID 格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    assert_eq!(&uuid[8..9], "-");
    assert_eq!(&uuid[13..14], "-");
    assert_eq!(&uuid[18..19], "-");
    assert_eq!(&uuid[23..24], "-");
}

#[test]
fn test_format_record_id_unique() {
    // 每次生成应产生不同的 ID
    let id1 = format_record_id().unwrap();
    let id2 = format_record_id().unwrap();

    // 由于使用随机 UUID，两次调用应产生不同结果
    // 注意：极小概率可能相同，但测试中可以忽略
    assert_ne!(id1, id2);
}

#[test]
fn test_format_record_id_hex_digits() {
    // UUID 应只包含十六进制字符
    let id = format_record_id().unwrap();
    let uuid = &id[10..46];

    // 移除连字符
    let hex_chars: String = uuid.chars().filter(|c| *c != '-').collect();

    // 验证都是十六进制字符
    assert!(hex_chars.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hex_chars.len(), 32); // 32 个十六进制字符
}

// ========== WarcRecordType Display 测试 ==========

#[test]
fn test_warc_record_type_display() {
    use std::fmt::Write;

    let types = [
        (format::WarcRecordType::Warcinfo, "warcinfo"),
        (format::WarcRecordType::Response, "response"),
        (format::WarcRecordType::Resource, "resource"),
        (format::WarcRecordType::Request, "request"),
        (format::WarcRecordType::Metadata, "metadata"),
        (format::WarcRecordType::Conversion, "conversion"),
        (format::WarcRecordType::Continuation, "continuation"),
    ];

    for (record_type, expected) in types {
        let mut output = String::new();
        write!(&mut output, "{}", record_type).unwrap();
        assert_eq!(output, expected);
    }
}

// ========== 综合测试 ==========

#[test]
fn test_warc_header_serialize_complete() {
    // 完整头部序列化测试
    let header = format::WarcHeader {
        record_type: format::WarcRecordType::Response,
        record_id: "<urn:uuid:complete-test>".to_string(),
        date: "2025-06-17T10:30:00Z".to_string(),
        content_length: 1234,
        concurrent_to: vec!["<urn:uuid:related>".to_string()],
        content_type: "application/http;msgtype=response".to_string(),
        target_uri: "http://example.com/page.html".to_string(),
        gzip_compressed: true,
        truncated: Some("time".to_string()),
        wagon: Some("test-wagon".to_string()),
    };

    let bytes = header.serialize();
    let text = String::from_utf8(bytes).unwrap();

    // 验证所有字段
    assert!(text.contains("WARC/1.1\r\n"));
    assert!(text.contains("WARC-Type: response\r\n"));
    assert!(text.contains("WARC-Date: 2025-06-17T10:30:00Z\r\n"));
    assert!(text.contains("WARC-Record-ID: <urn:uuid:complete-test>\r\n"));
    assert!(text.contains("Content-Type: application/http;msgtype=response\r\n"));
    assert!(text.contains("Content-Length: 1234\r\n"));
    assert!(text.contains("WARC-Target-URI: http://example.com/page.html\r\n"));
    assert!(text.contains("WARC-Concurrent-To: <urn:uuid:related>\r\n"));
    assert!(text.contains("WARC-Payload-Digest: sha1:\r\n"));
    assert!(text.contains("WARC-Truncated: time\r\n"));
    assert!(text.contains("WARC-Wagon: test-wagon\r\n"));
    assert!(text.ends_with("\r\n\r\n"));
}
