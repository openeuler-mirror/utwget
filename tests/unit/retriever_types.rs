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
