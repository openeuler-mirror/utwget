//! Unit tests for the DNS/SSRF helper functions (ut_retriever::dns).
//!
//! Regression coverage for H-2: `--block-private-redirects` was bypassable
//! with IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1` classified as plain
//! V6 → loopback check missed → connected to 127.0.0.1 anyway).

use std::net::IpAddr;

use ut_retriever::dns::is_private_ip;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// ============================================================================
// Public / non-private addresses (must NOT be flagged)
// ============================================================================

#[test]
fn public_ipv4_not_private() {
    assert!(!is_private_ip(&ip("8.8.8.8")));
    assert!(!is_private_ip(&ip("1.1.1.1")));
    assert!(!is_private_ip(&ip("93.184.216.34")));
}

#[test]
fn public_ipv6_not_private() {
    assert!(!is_private_ip(&ip("2001:4860:4860::8888")));
    assert!(!is_private_ip(&ip("2606:4700::1111")));
}

// ============================================================================
// RFC 1918 + loopback + link-local (must be flagged)
// ============================================================================

#[test]
fn rfc1918_ranges_flagged() {
    assert!(is_private_ip(&ip("10.0.0.1")));
    assert!(is_private_ip(&ip("172.16.0.1")));
    assert!(is_private_ip(&ip("192.168.1.1")));
}

#[test]
fn ipv4_loopback_and_link_local_flagged() {
    assert!(is_private_ip(&ip("127.0.0.1")));
    assert!(is_private_ip(&ip("127.8.8.8")));
    assert!(is_private_ip(&ip("169.254.169.254"))); // cloud metadata
    assert!(is_private_ip(&ip("0.0.0.0")));
    assert!(is_private_ip(&ip("255.255.255.255")));
}

#[test]
fn cgnat_range_flagged() {
    assert!(is_private_ip(&ip("100.64.0.1")));
    assert!(is_private_ip(&ip("100.127.255.254")));
    // 100.64.0.0/10 boundaries
    assert!(is_private_ip(&ip("100.100.100.100")));
    assert!(!is_private_ip(&ip("100.128.0.1"))); // outside /10
    assert!(!is_private_ip(&ip("99.64.0.1"))); // outside
}

#[test]
fn ipv6_specials_flagged() {
    assert!(is_private_ip(&ip("::1")));
    assert!(is_private_ip(&ip("::")));
    assert!(is_private_ip(&ip("fe80::1"))); // link-local
    assert!(is_private_ip(&ip("fd00::1"))); // unique-local
    assert!(is_private_ip(&ip("fc00::1"))); // unique-local
    assert!(is_private_ip(&ip("ff02::1"))); // multicast
}

// ============================================================================
// Regression: IPv4-mapped IPv6 must classify as its embedded IPv4 (H-2)
// ============================================================================

#[test]
fn ipv4_mapped_loopback_flagged() {
    // The exact bypass payload from the review: ::ffff:127.0.0.1
    assert!(is_private_ip(&ip("::ffff:127.0.0.1")));
}

#[test]
fn ipv4_mapped_metadata_flagged() {
    // Cloud-metadata redirect payload in mapped form.
    assert!(is_private_ip(&ip("::ffff:169.254.169.254")));
}

#[test]
fn ipv4_mapped_rfc1918_flagged() {
    assert!(is_private_ip(&ip("::ffff:10.0.0.1")));
    assert!(is_private_ip(&ip("::ffff:192.168.0.1")));
    assert!(is_private_ip(&ip("::ffff:172.16.0.1")));
}

#[test]
fn ipv4_mapped_public_not_flagged() {
    // Mapped public addresses stay public (no over-blocking).
    assert!(!is_private_ip(&ip("::ffff:8.8.8.8")));
}

#[test]
fn ipv4_mapped_cgnat_flagged() {
    assert!(is_private_ip(&ip("::ffff:100.64.0.1")));
}

#[test]
fn ipv4_compatible_loopback_flagged() {
    // Deprecated IPv4-compatible form ::a.b.c.d (first 96 bits zero).
    assert!(is_private_ip(&ip("::127.0.0.1")));
    assert!(is_private_ip(&ip("::10.0.0.1")));
}

#[test]
fn ipv4_mapped_normalization_excludes_special_v6() {
    // :: and ::1 must still be flagged via the V6 branch.
    assert!(is_private_ip(&ip("::")));
    assert!(is_private_ip(&ip("::1")));
}

// ============================================================================
// TLS config cache signature completeness (M18) — behavioral note
// ============================================================================

// The cache-signature fix is exercised indirectly: TlsConfig::from_core
// copies crl_file/pinned_pubkey, and RustlsConnector::new() keys its cache
// on config_signature(). Two TlsConfigs differing only in pinned_pubkey now
// produce distinct cache entries. Direct unit-testing of the private cache
// requires constructing rustls stores; the differential property is covered
// by the pinnedpubkey e2e behavior (pin enforced even with
// --no-check-certificate), which would fail with a cache collision.
