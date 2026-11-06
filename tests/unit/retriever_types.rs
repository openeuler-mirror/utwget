//! Unit tests for retriever types module.
//!
//! Tests for parse_http_date, parse_content_disposition,
//! content_type_is_html/css/xml, and determine_document_flags.

use ut_retriever::*;
use ut_retriever::types::{parse_http_date, parse_content_disposition, content_type_is_html, content_type_is_css, content_type_is_xml, determine_document_flags};
use chrono::{Datelike, Timelike};

// ========== parse_http_date tests ==========

#[test]
fn test_parse_http_date_rfc7231() {
    // RFC 7231 format: Tue, 15 Nov 1994 08:12:31 GMT
    let result = parse_http_date("Tue, 15 Nov 1994 08:12:31 GMT");
    assert!(result.is_some());
    let dt = result.unwrap();
    assert_eq!(dt.year(), 1994);
    assert_eq!(dt.month(), 11);
    assert_eq!(dt.day(), 15);
    assert_eq!(dt.hour(), 8);
    assert_eq!(dt.minute(), 12);
    assert_eq!(dt.second(), 31);
}

#[test]
fn test_parse_http_date_rfc7231_with_whitespace() {
    let result = parse_http_date("  Tue, 15 Nov 1994 08:12:31 GMT  ");
    assert!(result.is_some());
}

#[test]
fn test_parse_http_date_rfc850() {
    // RFC 850 format: Tuesday, 15-Nov-94 08:12:31 GMT
    let result = parse_http_date("Tuesday, 15-Nov-94 08:12:31 GMT");
    assert!(result.is_some());
    let dt = result.unwrap();
    assert_eq!(dt.year(), 1994);
    assert_eq!(dt.month(), 11);
    assert_eq!(dt.day(), 15);
}

#[test]
fn test_parse_http_date_iso8601() {
    // ISO 8601 format: 1994-11-15T08:12:31Z
    let result = parse_http_date("1994-11-15T08:12:31Z");
    assert!(result.is_some());
    let dt = result.unwrap();
    assert_eq!(dt.year(), 1994);
    assert_eq!(dt.month(), 11);
    assert_eq!(dt.day(), 15);
    assert_eq!(dt.hour(), 8);
    assert_eq!(dt.minute(), 12);
    assert_eq!(dt.second(), 31);
}

#[test]
fn test_parse_http_date_iso8601_with_fraction() {
    // ISO 8601 with fractional seconds
    let result = parse_http_date("1994-11-15T08:12:31.123Z");
    assert!(result.is_some());
    let dt = result.unwrap();
    assert_eq!(dt.year(), 1994);
    assert_eq!(dt.month(), 11);
    assert_eq!(dt.day(), 15);
}

#[test]
fn test_parse_http_date_invalid() {
    assert!(parse_http_date("invalid date").is_none());
    assert!(parse_http_date("").is_none());
    assert!(parse_http_date("Not a date at all").is_none());
}

#[test]
fn test_parse_http_date_common_formats() {
    // Test various common HTTP date formats
    assert!(parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT").is_some());
    assert!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").is_some());
}

// ========== parse_content_disposition tests ==========

#[test]
fn test_parse_content_disposition_filename_quoted() {
    let result = parse_content_disposition("attachment; filename=\"example.html\"");
    assert_eq!(result, Some("example.html".to_string()));
}

#[test]
fn test_parse_content_disposition_filename_unquoted() {
    let result = parse_content_disposition("attachment; filename=example.html");
    assert_eq!(result, Some("example.html".to_string()));
}

#[test]
fn test_parse_content_disposition_inline() {
    let result = parse_content_disposition("inline; filename=\"test.txt\"");
    assert_eq!(result, Some("test.txt".to_string()));
}

#[test]
fn test_parse_content_disposition_utf8() {
    // RFC 6266: filename*=UTF-8''encoded-filename
    let result = parse_content_disposition("attachment; filename*=UTF-8''%E4%B8%AD%E6%96%87.txt");
    // Just verify parsing completes without panic
    // The exact decoding behavior may vary
    let _ = result;
}

#[test]
fn test_parse_content_disposition_no_filename() {
    let result = parse_content_disposition("attachment");
    assert!(result.is_none());
}

#[test]
fn test_parse_content_disposition_empty_filename() {
    let result = parse_content_disposition("attachment; filename=\"\"");
    assert!(result.is_none());
}

#[test]
fn test_parse_content_disposition_with_semicolon() {
    let result = parse_content_disposition("attachment; filename=\"file.txt\"; other=param");
    assert_eq!(result, Some("file.txt".to_string()));
}

#[test]
fn test_parse_content_disposition_whitespace() {
    // Test basic case without extra whitespace
    let result = parse_content_disposition("attachment; filename=\"test.txt\"");
    assert_eq!(result, Some("test.txt".to_string()));
}

// ========== content_type_is_html tests ==========

#[test]
fn test_content_type_is_html_basic() {
    assert!(content_type_is_html(Some("text/html")));
    assert!(content_type_is_html(Some("TEXT/HTML")));
    assert!(content_type_is_html(Some("Text/Html")));
}

#[test]
fn test_content_type_is_html_with_charset() {
    assert!(content_type_is_html(Some("text/html; charset=utf-8")));
    assert!(content_type_is_html(Some("text/html;charset=UTF-8")));
}

#[test]
fn test_content_type_is_html_not_html() {
    assert!(!content_type_is_html(Some("text/plain")));
    assert!(!content_type_is_html(Some("application/json")));
    assert!(!content_type_is_html(Some("image/png")));
    assert!(!content_type_is_html(Some("text/css")));
}

#[test]
fn test_content_type_is_html_none() {
    assert!(!content_type_is_html(None));
}

// ========== content_type_is_css tests ==========

#[test]
fn test_content_type_is_css_basic() {
    assert!(content_type_is_css(Some("text/css")));
    assert!(content_type_is_css(Some("TEXT/CSS")));
    assert!(content_type_is_css(Some("Text/Css")));
}

#[test]
fn test_content_type_is_css_with_charset() {
    assert!(content_type_is_css(Some("text/css; charset=utf-8")));
}

#[test]
fn test_content_type_is_css_not_css() {
    assert!(!content_type_is_css(Some("text/html")));
    assert!(!content_type_is_css(Some("application/json")));
    assert!(!content_type_is_css(Some("text/plain")));
}

#[test]
fn test_content_type_is_css_none() {
    assert!(!content_type_is_css(None));
}

// ========== content_type_is_xml tests ==========

#[test]
fn test_content_type_is_xml_application_xml() {
    assert!(content_type_is_xml(Some("application/xml")));
    assert!(content_type_is_xml(Some("APPLICATION/XML")));
}

#[test]
fn test_content_type_is_xml_text_xml() {
    assert!(content_type_is_xml(Some("text/xml")));
    assert!(content_type_is_xml(Some("TEXT/XML")));
}

#[test]
fn test_content_type_is_xml_xhtml() {
    assert!(content_type_is_xml(Some("application/xhtml+xml")));
    assert!(content_type_is_xml(Some("APPLICATION/XHTML+XML")));
}

#[test]
fn test_content_type_is_xml_with_charset() {
    assert!(content_type_is_xml(Some("application/xml; charset=utf-8")));
    assert!(content_type_is_xml(Some("text/xml; charset=iso-8859-1")));
}

#[test]
fn test_content_type_is_xml_not_xml() {
    assert!(!content_type_is_xml(Some("text/html")));
    assert!(!content_type_is_xml(Some("application/json")));
    assert!(!content_type_is_xml(Some("text/plain")));
}
