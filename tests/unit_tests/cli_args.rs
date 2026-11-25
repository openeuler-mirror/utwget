//! Unit tests for CLI argument application (apply_args).
//!
//! Verifies that command-line options are correctly mapped onto the
//! `Config` structure, including TLS-related flags.

use clap::Parser as _;
use ut_core::Config;
use utwget_cli::app::apply_args;
use utwget_cli::args::Args;

// ============================================================================
// TLS options
// ============================================================================

#[test]
fn apply_args_no_check_certificate_disables_verification() {
    let mut config = Config::default();
    let args = Args::try_parse_from(["utwget", "--no-check-certificate"]).unwrap();
    apply_args(&mut config, &args);
    assert_eq!(
        config.tls.check_certificate,
        ut_core::CheckCertMode::Off,
        "--no-check-certificate must set CheckCertMode::Off"
    );
}

#[test]
fn apply_args_default_keeps_certificate_verification() {
    let mut config = Config::default();
    let args = Args::try_parse_from(["utwget", "http://example.com/file"]).unwrap();
    apply_args(&mut config, &args);
    assert_eq!(config.tls.check_certificate, ut_core::CheckCertMode::On);
}

#[test]
fn apply_args_check_certificate_enables_verification() {
    let mut config = Config::default();
    // Explicit positive flag (no-op vs default, but must not disable).
    let args = Args::try_parse_from(["utwget", "--check-certificate", "http://example.com/"]).unwrap();
    apply_args(&mut config, &args);
    assert_eq!(config.tls.check_certificate, ut_core::CheckCertMode::On);
}

#[test]
fn apply_args_ca_certificate_sets_path() {
    let mut config = Config::default();
    let args = Args::try_parse_from([
        "utwget", "--ca-certificate", "/tmp/opencode/ca.pem", "http://example.com/",
    ])
    .unwrap();
    apply_args(&mut config, &args);
    assert_eq!(
        config.tls.ca_cert,
        Some(std::path::PathBuf::from("/tmp/opencode/ca.pem"))
    );
}

#[test]
fn apply_args_no_check_certificate_survives_wgetrc_overrides() {
    // Regression: wgetrc may set check_certificate=on, but CLI must win
    // (apply_args runs after wgetrc application, see cli/main.rs).
    let mut config = Config::default();
    config.tls.check_certificate = ut_core::CheckCertMode::On;
    let args = Args::try_parse_from(["utwget", "--no-check-certificate", "http://example.com/"]).unwrap();
    apply_args(&mut config, &args);
    assert_eq!(config.tls.check_certificate, ut_core::CheckCertMode::Off);
}

// ============================================================================
// Exit-code mapping: structured DNS errors (arch 6.3-1)
// ============================================================================

#[test]
fn dns_errors_map_to_network_fail_without_string_matching() {
    use ut_core::WgetError;
    use utwget_cli::app::ExitStatus;

    // Previously: WgetError::Other("DNS resolution error: ...") was classified
    // by msg.contains("DNS") — a wording change silently flipped the exit
    // code between 1 (generic error) and 4 (network failure). The structured
    // variants map deterministically.
    assert_eq!(
        ExitStatus::from_error(&WgetError::DnsResolution("x".into())),
        ExitStatus::NetworkFail
    );
    assert_eq!(
        ExitStatus::from_error(&WgetError::DnsTimeout),
        ExitStatus::NetworkFail
    );
    assert_eq!(
        ExitStatus::from_error(&WgetError::HostNotFound("h".into())),
        ExitStatus::NetworkFail
    );
    // A generic Other must stay a generic error (never network) regardless
    // of its message content.
    assert_eq!(
        ExitStatus::from_error(&WgetError::Other("DNS-something-unrelated".into())),
        ExitStatus::Error
    );
    assert_eq!(
        ExitStatus::from_error(&WgetError::TlsInitFailed),
        ExitStatus::SslAuthFail
    );
}
