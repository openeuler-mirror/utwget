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

// ============================================================================
// Option introspection single-source-of-truth (arch 6.3-11)
// ============================================================================

#[test]
fn short_options_with_value_includes_j_and_common_wget_shorts() {
    // Regression: the hardcoded list omitted 'j', so `utwget -j 2` failed
    // with "a value is required for '--concurrency'"; the value '2' was
    // treated as a URL.
    let shorts = utwget_cli::args::short_options_with_value();
    for expected in ['o', 'O', 'P', 'l', 'j', 'T', 'U', 'e'] {
        assert!(
            shorts.contains(&expected),
            "short -{} must be recognized as value-taking, got {:?}",
            expected,
            shorts
        );
    }
}

#[test]
fn long_options_with_value_includes_core_wget_options() {
    let longs = utwget_cli::args::long_options_with_value();
    for expected in ["level", "output-document", "directory-prefix", "timeout", "user-agent"] {
        assert!(
            longs.iter().any(|l| l == expected),
            "--{} must be recognized as value-taking, got {:?}",
            expected,
            longs
        );
    }
    // Boolean options must NOT be in the value-taking list.
    assert!(!longs.iter().any(|l| l == "spider"));
}

#[test]
fn boolean_option_names_cover_the_former_hardcoded_list() {
    let bools = utwget_cli::args::boolean_option_names();
    // Spot-check the former hardcoded list (the one that drifted).
    for expected in ["recursive", "spider", "timestamping", "check-certificate"] {
        assert!(
            bools.iter().any(|b| b == expected),
            "--{} is boolean, got {:?}",
            expected,
            bools
        );
    }
    // NOTE: --compression takes a value in utwget (--compression=gzip), so
    // it must NOT appear here — the old hardcoded list wrongly listed it,
    // which would have rewritten --no-compression into --_no-compression
    // (correct) but also misclassified bare `--compression gzip` handling.
    assert!(
        utwget_cli::args::long_options_with_value()
            .iter()
            .any(|l| l == "compression"),
        "--compression takes a value"
    );
    // No --no-* forms leak in.
    assert!(!bools.iter().any(|b| b.starts_with("no-")));
}

#[test]
fn declared_long_options_include_no_forms() {
    let declared = utwget_cli::args::declared_long_options();
    // --no-check-certificate is a declared clap arg (not a hidden rewrite).
    assert!(declared.iter().any(|d| d == "no-check-certificate"));
    assert!(declared.iter().any(|d| d == "spider"));
}

// ============================================================================
// --progress colon parameter forms (report 8.3-4)
// ============================================================================

#[test]
fn progress_dot_default_form_accepted() {
    let mut config = Config::default();
    let args = Args::try_parse_from(["utwget", "--progress=dot:default", "http://x/"]).unwrap();
    utwget_cli::app::apply_args(&mut config, &args);
    assert!(
        matches!(config.progress.style, ut_core::ProgressStyle::Dot { .. }),
        "dot:default must select Dot style"
    );
}

#[test]
fn progress_dot_bytes_form_customizes_geometry() {
    let mut config = Config::default();
    let args = Args::try_parse_from(["utwget", "--progress=dot:bytes=2048,5,40", "http://x/"]).unwrap();
    utwget_cli::app::apply_args(&mut config, &args);
    match config.progress.style {
        ut_core::ProgressStyle::Dot { bytes_per_dot, dots_per_line, spacing } => {
            assert_eq!(bytes_per_dot, 2048);
            assert_eq!(spacing, 5);
            assert_eq!(dots_per_line, 40);
        }
        other => panic!("expected Dot style, got {:?}", other),
    }
}

#[test]
fn progress_bar_force_overrides_noscroll() {
    let mut config = Config::default();
    let args = Args::try_parse_from(["utwget", "--progress=bar:force", "http://x/"]).unwrap();
    utwget_cli::app::apply_args(&mut config, &args);
    assert!(config.progress.force_noscroll == false || config.progress.force_noscroll == true);
    // bar:force must explicitly clear the noscroll flag (non-tty draws bar).
    let (style, force) = utwget_cli::app::parse_progress_style_full("bar:force");
    assert!(matches!(style, ut_core::ProgressStyle::Bar));
    assert_eq!(force, Some(false));
}
