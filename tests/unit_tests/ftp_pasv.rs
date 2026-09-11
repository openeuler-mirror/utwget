//! Tests for FTP data connection helpers (ut_ftp::data_conn).
//!
//! Regression coverage for M9: PASV responses WITHOUT parentheses
//! (common on old/embedded servers) are accepted, matching GNU wget's
//! digit-scan behavior (ftp-basic.c:652-654).

use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};

use ut_ftp::data_conn::parse_pasv_response;

fn addr(o: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(o[0], o[1], o[2], o[3]), port))
}

#[test]
fn pasv_parenthesized_form() {
    let a = parse_pasv_response("227 Entering Passive Mode (127,0,0,1,20,30)").unwrap();
    assert_eq!(a, addr([127, 0, 0, 1], 20 * 256 + 30));
}

#[test]
fn pasv_parenless_form_accepted() {
    // Regression (M9): wget accepts paren-less PASV responses.
    let a = parse_pasv_response("227 Entering Passive Mode 10,0,0,1,20,30").unwrap();
    assert_eq!(a, addr([10, 0, 0, 1], 20 * 256 + 30));
}

#[test]
fn pasv_parenless_leading_text() {
    let a = parse_pasv_response("227 Entering passive mode. Host: 192,168,1,5,200,1").unwrap();
    assert_eq!(a, addr([192, 168, 1, 5], 200 * 256 + 1));
}

#[test]
fn pasv_parenthesized_takes_priority() {
    // If both forms exist, the parenthesized one wins (first match).
    let a = parse_pasv_response("227 OK (1,2,3,4,5,6) ignored 9,9,9,9,9,9").unwrap();
    assert_eq!(a, addr([1, 2, 3, 4], 5 * 256 + 6));
}

#[test]
fn pasv_parenless_run_terminated_by_other_digits() {
    // The digit scan must stop at a non-comma boundary; the FIRST valid
    // 6-number run wins.
    let a = parse_pasv_response("227 mode 12,34 end (5,6,7,8,9,10)").unwrap();
    assert_eq!(a, addr([5, 6, 7, 8], 9 * 256 + 10));
}

#[test]
fn pasv_garbage_rejected() {
    assert!(parse_pasv_response("227 huh?").is_err());
    assert!(parse_pasv_response("227 1,2,3").is_err());
    assert!(parse_pasv_response("227 300,0,0,1,20,30").is_err()); // out of u8 range
}

#[test]
fn pasv_empty_parens_rejected() {
    assert!(parse_pasv_response("227 ()").is_err());
}
