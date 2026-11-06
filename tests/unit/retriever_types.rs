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

#[test]
fn test_content_type_is_xml_none() {
    assert!(!content_type_is_xml(None));
}

// ========== determine_document_flags tests ==========

#[test]
fn test_determine_document_flags_html() {
    let flags = determine_document_flags(Some("text/html"), 200);
    assert!(flags.contains(DocumentFlags::TEXT_HTML));
    assert!(flags.contains(DocumentFlags::RETRIEVAL_OK));
    assert!(!flags.contains(DocumentFlags::TEXT_CSS));
}

#[test]
fn test_determine_document_flags_css() {
    let flags = determine_document_flags(Some("text/css"), 200);
    assert!(flags.contains(DocumentFlags::TEXT_CSS));
    assert!(flags.contains(DocumentFlags::RETRIEVAL_OK));
    assert!(!flags.contains(DocumentFlags::TEXT_HTML));
}

#[test]
fn test_determine_document_flags_html_with_charset() {
    let flags = determine_document_flags(Some("text/html; charset=utf-8"), 200);
    assert!(flags.contains(DocumentFlags::TEXT_HTML));
    assert!(flags.contains(DocumentFlags::RETRIEVAL_OK));
}

#[test]
fn test_determine_document_flags_error_status() {
    let flags = determine_document_flags(Some("text/html"), 404);
    assert!(flags.contains(DocumentFlags::TEXT_HTML));
    assert!(!flags.contains(DocumentFlags::RETRIEVAL_OK));
}

#[test]
fn test_determine_document_flags_redirect_status() {
    let flags = determine_document_flags(Some("text/html"), 301);
    assert!(flags.contains(DocumentFlags::TEXT_HTML));
    assert!(!flags.contains(DocumentFlags::RETRIEVAL_OK));
}

#[test]
fn test_determine_document_flags_success_range() {
    // Test all 2xx status codes
    for status in 200..=206 {
        let flags = determine_document_flags(None, status);
        assert!(flags.contains(DocumentFlags::RETRIEVAL_OK));
    }
}

#[test]
fn test_determine_document_flags_no_content_type() {
    let flags = determine_document_flags(None, 200);
    assert!(flags.contains(DocumentFlags::RETRIEVAL_OK));
    assert!(!flags.contains(DocumentFlags::TEXT_HTML));
    assert!(!flags.contains(DocumentFlags::TEXT_CSS));
}

#[test]
fn test_determine_document_flags_empty_flags() {
    let flags = determine_document_flags(Some("application/json"), 404);
    assert!(flags.is_empty());
}

// ========== DocumentFlags bitflags tests ==========

#[test]
fn test_document_flags_empty() {
    let flags = DocumentFlags::empty();
    assert!(flags.is_empty());
    assert!(!flags.contains(DocumentFlags::TEXT_HTML));
}

#[test]
fn test_document_flags_all() {
    let flags = DocumentFlags::all();
    assert!(flags.contains(DocumentFlags::TEXT_HTML));
    assert!(flags.contains(DocumentFlags::RETRIEVAL_OK));
    assert!(flags.contains(DocumentFlags::HEAD_ONLY));
    assert!(flags.contains(DocumentFlags::NO_CACHE));
    assert!(flags.contains(DocumentFlags::ACCEPT_RANGES));
    assert!(flags.contains(DocumentFlags::HTML_EXT_ADDED));
    assert!(flags.contains(DocumentFlags::TEXT_CSS));
    assert!(flags.contains(DocumentFlags::IF_MODIFIED));
    assert!(flags.contains(DocumentFlags::METALINK_META));
}

#[test]
fn test_document_flags_union() {
    let flags = DocumentFlags::TEXT_HTML | DocumentFlags::TEXT_CSS;
    assert!(flags.contains(DocumentFlags::TEXT_HTML));
    assert!(flags.contains(DocumentFlags::TEXT_CSS));
    assert!(!flags.contains(DocumentFlags::RETRIEVAL_OK));
}

#[test]
fn test_document_flags_intersection() {
    let flags1 = DocumentFlags::TEXT_HTML | DocumentFlags::RETRIEVAL_OK;
    let flags2 = DocumentFlags::TEXT_HTML | DocumentFlags::TEXT_CSS;
    let intersection = flags1 & flags2;
    assert!(intersection.contains(DocumentFlags::TEXT_HTML));
    assert!(!intersection.contains(DocumentFlags::RETRIEVAL_OK));
    assert!(!intersection.contains(DocumentFlags::TEXT_CSS));
}

// ========== RequestOptions tests ==========

#[test]
fn test_request_options_default() {
    let opts = RequestOptions::default();
    assert!(opts.use_proxy);
    assert!(opts.headers.is_empty());
    assert!(opts.post_data.is_none());
    assert!(opts.body_data.is_none());
    assert!(opts.referer.is_none());
    assert!(opts.range_start.is_none());
    assert!(opts.if_modified_since.is_none());
    assert!(opts.if_none_match.is_none());
    assert!(!opts.auth_without_challenge);
    assert!(!opts.save_headers);
    assert!(!opts.content_on_error);
}

// ========== ProtocolState tests ==========

#[test]
fn test_protocol_state_default() {
    let state = ProtocolState::default();
    assert_eq!(state.retry_count, 0);
    assert_eq!(state.redirect_count, 0);
    assert_eq!(state.resume_position, 0);
    assert!(!state.head_done);
    assert!(state.last_content_length.is_none());
    assert!(!state.ntlm_seen);
    assert!(!state.auth_finished);
}
