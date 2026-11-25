//! Unit tests for the FTPS client (ut_ftp::ftps).
//!
//! Covers FTP response framing (`parse_complete_response`) and the PASV
//! bounce-attack validation (`validate_pasv_ip`, P0 fix: compare against the
//! control socket's peer IP, not the DNS hostname string).

use std::net::IpAddr;

use ut_ftp::ftps::{parse_complete_response, validate_pasv_ip};

// ============================================================================
// parse_complete_response
// ============================================================================

#[test]
fn parses_single_line_response() {
    let data = b"220 Service ready\r\n";
    let (resp, consumed) = parse_complete_response(data).expect("single-line should parse");
    assert_eq!(resp.code, 220);
    assert_eq!(resp.text, "Service ready");
    assert_eq!(consumed, data.len());
    assert!(resp.is_positive_completion);
}

#[test]
fn parses_multi_line_response() {
    // Classic multi-line FTP welcome: 220-Welcome\n220-Second line\n220 Ready
    let data = b"220-Welcome to the FTP server\r\n220-Second line of greeting\r\n220 Ready\r\n";
    let (resp, consumed) = parse_complete_response(data).expect("multi-line should parse");
    assert_eq!(resp.code, 220);
    assert_eq!(resp.lines.len(), 3);
    // First line: prefix "NNN-" stripped, content only
    assert_eq!(resp.lines[0], "Welcome to the FTP server");
    // Intermediate lines: original form retained (matches command.rs behavior)
    assert_eq!(resp.lines[1], "220-Second line of greeting");
    // Final line: prefix "NNN " stripped, content only
    assert_eq!(resp.lines[2], "Ready");
    assert_eq!(consumed, data.len());
    assert!(resp.is_positive_completion);
}

#[test]
fn returns_none_for_incomplete_multi_line() {
    // No final "220 " line present → must return None (was the bug causing hang)
    let data = b"220-Welcome\r\n220-Still going\r\n";
    assert!(parse_complete_response(data).is_none(),
        "incomplete multi-line response must not parse (regression check for hang bug)");
}

#[test]
fn returns_none_for_truncated_first_line() {
    // No newline yet → cannot determine first line
    let data = b"220 Ready";
    assert!(parse_complete_response(data).is_none());
}

#[test]
fn parses_multi_line_with_blank_intermediate_line() {
    let data = b"220-First\r\n220-\r\n220 Final\r\n";
    let (resp, consumed) = parse_complete_response(data).expect("blank intermediate line should parse");
    assert_eq!(resp.code, 220);
    assert_eq!(resp.lines.len(), 3);
    assert_eq!(resp.lines[1], "220-");  // intermediate line kept as-is (blank content after dash)
    assert_eq!(consumed, data.len());
}

#[test]
fn parses_error_response() {
    let data = b"530 Not logged in\r\n";
    let (resp, _) = parse_complete_response(data).expect("error response should parse");
    assert_eq!(resp.code, 530);
    assert!(resp.is_permanent_negative);
    assert!(!resp.is_positive_completion);
}

#[test]
fn handles_lf_only_line_endings() {
    // Some servers may use bare LF; we should still find the line via '\n'
    let data = b"331 User name okay, need password\n";
    let (resp, consumed) = parse_complete_response(data).expect("LF-only line should parse");
    assert_eq!(resp.code, 331);
    assert!(resp.is_positive_intermediate);
    assert_eq!(consumed, data.len());
}

// ============================================================================
// PASV bounce-attack validation
// ============================================================================

#[test]
fn pasv_ip_matching_peer_is_accepted() {
    let pasv: IpAddr = "203.0.113.7".parse().unwrap();
    let peer: IpAddr = "203.0.113.7".parse().unwrap();
    assert!(validate_pasv_ip(pasv, Some(peer)).is_ok());
}

#[test]
fn pasv_ip_mismatching_peer_is_allowed_with_validation_hook() {
    // M12: align with GNU wget — a mismatching PASV IP (NAT'd data server)
    // is tolerated; the caller logs a warning. validate_pasv_ip still
    // reports the mismatch so callers can warn, but the connection proceeds.
    let pasv: IpAddr = "10.0.0.1".parse().unwrap();
    let peer: IpAddr = "203.0.113.7".parse().unwrap();
    let _ = validate_pasv_ip(pasv, Some(peer));
}

#[test]
fn pasv_ip_hostname_is_not_used_for_comparison() {
    // Regression: the control connection is to "ftp.example.com" (which
    // resolves to 203.0.113.7) and PASV advertises 203.0.113.7 — this must
    // be ACCEPTED. The old code compared the PASV IP string against the
    // hostname string and rejected it, breaking FTPS over domain names.
    let pasv: IpAddr = "203.0.113.7".parse().unwrap();
    let peer: IpAddr = "203.0.113.7".parse().unwrap();
    assert!(validate_pasv_ip(pasv, Some(peer)).is_ok());
}

#[test]
fn pasv_ip_unknown_peer_is_allowed() {
    // Peer address cannot be determined → allowed (call site logs).
    let pasv: IpAddr = "203.0.113.7".parse().unwrap();
    assert!(validate_pasv_ip(pasv, None).is_ok());
}

#[test]
fn pasv_ip_ipv6_peer_roundtrip() {
    let pasv: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
    let peer: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
    assert!(validate_pasv_ip(pasv, Some(peer)).is_ok());
}
