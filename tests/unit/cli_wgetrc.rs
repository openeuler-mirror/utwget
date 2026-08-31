//! Unit tests for wgetrc configuration file parsing.
//!
//! These tests verify the parsing and application of wgetrc configuration files,
//! including key-value settings, boolean toggles, and error handling.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use utwget_cli::wgetrc::{WgetrcCommand, WgetrcParser};
use ut_core::Config;

// ============================================================================
// Helper Functions
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create a temporary wgetrc file with the given content.
fn create_temp_wgetrc(content: &str) -> PathBuf {
    let temp_dir = std::env::temp_dir();
    let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = temp_dir.join(format!("test_wgetrc_{}_{}.tmp", std::process::id(), counter));
    let mut file = fs::File::create(&path).expect("Failed to create temp file");
    file.write_all(content.as_bytes()).expect("Failed to write temp file");
    file.flush().expect("Failed to flush temp file");
    path
}

/// Clean up a temporary file.
fn cleanup_temp_file(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

// ============================================================================
// File Parsing Tests
// ============================================================================

#[test]
fn test_parse_empty_file() {
    let path = create_temp_wgetrc("");
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert!(commands.is_empty());
}

#[test]
fn test_parse_comments_only() {
    let content = r#"# This is a comment
# Another comment
# Settings below are commented out
# quiet = on
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert!(commands.is_empty());
}

#[test]
fn test_parse_simple_key_value() {
    let content = r#"dir_prefix = /downloads
user_agent = MyDownloader/1.0
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0], WgetrcCommand::Set("dir_prefix".to_string(), "/downloads".to_string()));
    assert_eq!(commands[1], WgetrcCommand::Set("user_agent".to_string(), "MyDownloader/1.0".to_string()));
}

#[test]
fn test_parse_boolean_on() {
    let content = r#"quiet = on
verbose = ON
recursive = On
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0], WgetrcCommand::OnOff("quiet".to_string(), true));
    assert_eq!(commands[1], WgetrcCommand::OnOff("verbose".to_string(), true));
    assert_eq!(commands[2], WgetrcCommand::OnOff("recursive".to_string(), true));
}

#[test]
fn test_parse_boolean_off() {
    let content = r#"quiet = off
verbose = OFF
recursive = Off
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0], WgetrcCommand::OnOff("quiet".to_string(), false));
    assert_eq!(commands[1], WgetrcCommand::OnOff("verbose".to_string(), false));
    assert_eq!(commands[2], WgetrcCommand::OnOff("recursive".to_string(), false));
}

#[test]
fn test_parse_command_style() {
    let content = r#"accept *.html *.css
reject *.pdf
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0], WgetrcCommand::Command("accept".to_string(), vec!["*.html".to_string(), "*.css".to_string()]));
    assert_eq!(commands[1], WgetrcCommand::Command("reject".to_string(), vec!["*.pdf".to_string()]));
}

#[test]
fn test_parse_mixed_content() {
    let content = r#"# Configuration file for wget
dir_prefix = /downloads
quiet = on
tries = 5
# Timeout settings
timeout = 30
recursive = off
accept *.html
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 6);
    assert_eq!(commands[0], WgetrcCommand::Set("dir_prefix".to_string(), "/downloads".to_string()));
    assert_eq!(commands[1], WgetrcCommand::OnOff("quiet".to_string(), true));
    assert_eq!(commands[2], WgetrcCommand::Set("tries".to_string(), "5".to_string()));
    assert_eq!(commands[3], WgetrcCommand::Set("timeout".to_string(), "30".to_string()));
    assert_eq!(commands[4], WgetrcCommand::OnOff("recursive".to_string(), false));
    assert_eq!(commands[5], WgetrcCommand::Command("accept".to_string(), vec!["*.html".to_string()]));
}

#[test]
fn test_parse_whitespace_handling() {
    let content = r#"  dir_prefix  =  /downloads
quiet=on
  tries=5
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0], WgetrcCommand::Set("dir_prefix".to_string(), "/downloads".to_string()));
    assert_eq!(commands[1], WgetrcCommand::OnOff("quiet".to_string(), true));
    assert_eq!(commands[2], WgetrcCommand::Set("tries".to_string(), "5".to_string()));
}

#[test]
fn test_parse_empty_lines() {
    let content = r#"dir_prefix = /downloads

quiet = on

tries = 5
"#;
    let path = create_temp_wgetrc(content);
    let result = WgetrcParser::parse(&path);
    cleanup_temp_file(&path);

    assert!(result.is_ok());
    let commands = result.unwrap();
    assert_eq!(commands.len(), 3);
}

#[test]
fn test_parse_nonexistent_file() {
    let path = PathBuf::from("/nonexistent/path/wgetrc");
    let result = WgetrcParser::parse(&path);
    assert!(result.is_err());
}

// ============================================================================
// Command Application Tests (On/Off)
// ============================================================================

#[test]
fn test_apply_quiet_on() {
    let commands = vec![WgetrcCommand::OnOff("quiet".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.quiet);
}

#[test]
fn test_apply_quiet_off() {
    let commands = vec![WgetrcCommand::OnOff("quiet".to_string(), false)];
    let mut config = Config::default();
    config.quiet = true; // Start with quiet enabled
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(!config.quiet);
}

#[test]
fn test_apply_verbose_on() {
    let commands = vec![WgetrcCommand::OnOff("verbose".to_string(), true)];
    let mut config = Config::default();
    config.verbose = 0;
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.verbose >= 1);
}

#[test]
fn test_apply_verbose_off() {
    let commands = vec![WgetrcCommand::OnOff("verbose".to_string(), false)];
    let mut config = Config::default();
    config.verbose = 2;
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.verbose, 0);
}

#[test]
fn test_apply_recursive_on() {
    let commands = vec![WgetrcCommand::OnOff("recursive".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.recursive.enabled);
}

#[test]
fn test_apply_recursive_off() {
    let commands = vec![WgetrcCommand::OnOff("recursive".to_string(), false)];
    let mut config = Config::default();
    config.recursive.enabled = true;
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(!config.recursive.enabled);
}

#[test]
fn test_apply_timestamping() {
    let commands = vec![WgetrcCommand::OnOff("timestamping".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.timestamping);
}

#[test]
fn test_apply_noclobber() {
    let commands = vec![WgetrcCommand::OnOff("noclobber".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.noclobber);
}

#[test]
fn test_apply_continue_download() {
    let commands = vec![WgetrcCommand::OnOff("continue".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.continue_download);
}

#[test]
fn test_apply_convert_links() {
    let commands = vec![WgetrcCommand::OnOff("convert_links".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.convert_links);
}

#[test]
fn test_apply_check_certificate() {
    use ut_core::CheckCertMode;

    // Test check_certificate = on
    let commands = vec![WgetrcCommand::OnOff("check_certificate".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.tls.check_certificate, CheckCertMode::On);

    // Test check_certificate = off
    let commands = vec![WgetrcCommand::OnOff("check_certificate".to_string(), false)];
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.tls.check_certificate, CheckCertMode::Off);
}

#[test]
fn test_apply_use_proxy() {
    let commands = vec![WgetrcCommand::OnOff("use_proxy".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.proxy.use_proxy);
}

#[test]
fn test_apply_cookies() {
    let commands = vec![WgetrcCommand::OnOff("cookies".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.cookie.enabled);
}

#[test]
fn test_apply_page_requisites() {
    let commands = vec![WgetrcCommand::OnOff("page_requisites".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.page_requisites);
}

#[test]
fn test_apply_span_hosts() {
    let commands = vec![WgetrcCommand::OnOff("span_hosts".to_string(), true)];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert!(config.recursive.span_hosts);
}

// ============================================================================
// Configuration Setting Tests
// ============================================================================

#[test]
fn test_apply_dir_prefix() {
    let commands = vec![WgetrcCommand::Set("dir_prefix".to_string(), "/downloads".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.dir_prefix, Some(PathBuf::from("/downloads")));
}

#[test]
fn test_apply_user_agent() {
    let commands = vec![WgetrcCommand::Set("user_agent".to_string(), "MyDownloader/1.0".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.http.user_agent, Some("MyDownloader/1.0".to_string()));
}

#[test]
fn test_apply_tries() {
    let commands = vec![WgetrcCommand::Set("tries".to_string(), "10".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.tries, 10);
}

#[test]
fn test_apply_timeout() {
    let commands = vec![WgetrcCommand::Set("timeout".to_string(), "30".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.timeout, Some(Duration::from_secs(30)));
}

#[test]
fn test_apply_timeout_with_suffix() {
    // Test with 's' suffix
    let commands = vec![WgetrcCommand::Set("timeout".to_string(), "30s".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.timeout, Some(Duration::from_secs(30)));

    // Test with 'm' suffix
    let commands = vec![WgetrcCommand::Set("timeout".to_string(), "5m".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.timeout, Some(Duration::from_secs(300)));

    // Test with 'h' suffix
    let commands = vec![WgetrcCommand::Set("timeout".to_string(), "1h".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.timeout, Some(Duration::from_secs(3600)));

    // Test with 'ms' suffix
    let commands = vec![WgetrcCommand::Set("timeout".to_string(), "500ms".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.timeout, Some(Duration::from_millis(500)));
}

#[test]
fn test_apply_http_user_password() {
    let commands = vec![
        WgetrcCommand::Set("http_user".to_string(), "testuser".to_string()),
        WgetrcCommand::Set("http_password".to_string(), "testpass".to_string()),
    ];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.http.user, Some("testuser".to_string()));
    assert_eq!(config.http.password, Some("testpass".to_string()));
}

#[test]
fn test_apply_ftp_user_password() {
    let commands = vec![
        WgetrcCommand::Set("ftp_user".to_string(), "ftpuser".to_string()),
        WgetrcCommand::Set("ftp_password".to_string(), "ftppass".to_string()),
    ];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.ftp.user, Some("ftpuser".to_string()));
    assert_eq!(config.ftp.password, Some("ftppass".to_string()));
}

#[test]
fn test_apply_proxy_settings() {
    let commands = vec![
        WgetrcCommand::Set("http_proxy".to_string(), "http://proxy.example.com:8080".to_string()),
        WgetrcCommand::Set("https_proxy".to_string(), "http://proxy.example.com:8080".to_string()),
        WgetrcCommand::Set("ftp_proxy".to_string(), "http://proxy.example.com:8080".to_string()),
    ];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.proxy.http_proxy, Some("http://proxy.example.com:8080".to_string()));
    assert_eq!(config.proxy.https_proxy, Some("http://proxy.example.com:8080".to_string()));
    assert_eq!(config.proxy.ftp_proxy, Some("http://proxy.example.com:8080".to_string()));
}

#[test]
fn test_apply_no_proxy() {
    let commands = vec![WgetrcCommand::Set("no_proxy".to_string(), "localhost,example.com,.local".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.proxy.no_proxy, vec!["localhost", "example.com", ".local"]);
}

#[test]
fn test_apply_max_redirect() {
    let commands = vec![WgetrcCommand::Set("max_redirect".to_string(), "10".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.max_redirect, 10);
}

#[test]
fn test_apply_level() {
    let commands = vec![WgetrcCommand::Set("level".to_string(), "3".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.recursive.max_level, Some(3));
}

#[test]
fn test_apply_accept_patterns() {
    let commands = vec![WgetrcCommand::Set("accept".to_string(), "*.html,*.css,*.js".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.recursive.accept_patterns, vec!["*.html", "*.css", "*.js"]);
}

#[test]
fn test_apply_reject_patterns() {
    let commands = vec![WgetrcCommand::Set("reject".to_string(), "*.pdf,*.zip".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.recursive.reject_patterns, vec!["*.pdf", "*.zip"]);
}

#[test]
fn test_apply_domains() {
    let commands = vec![WgetrcCommand::Set("domains".to_string(), "example.com,test.com".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.recursive.domains, vec!["example.com", "test.com"]);
}

#[test]
fn test_apply_secure_protocol() {
    use ut_core::SecureProtocol;

    // Test auto
    let commands = vec![WgetrcCommand::Set("secure_protocol".to_string(), "auto".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.tls.secure_protocol, SecureProtocol::Auto);

    // Test TLSv1.2
    let commands = vec![WgetrcCommand::Set("secure_protocol".to_string(), "tlsv1.2".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.tls.secure_protocol, SecureProtocol::TlsV1_2);

    // Test TLSv1.3
    let commands = vec![WgetrcCommand::Set("secure_protocol".to_string(), "tlsv1.3".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.tls.secure_protocol, SecureProtocol::TlsV1_3);
}

#[test]
fn test_apply_prefer_family() {
    use ut_core::AddressFamily;

    // Test IPv4
    let commands = vec![WgetrcCommand::Set("prefer_family".to_string(), "ipv4".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.prefer_family, AddressFamily::Ipv4);

    // Test IPv6
    let commands = vec![WgetrcCommand::Set("prefer_family".to_string(), "ipv6".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.prefer_family, AddressFamily::Ipv6);

    // Test prefer-ipv4
    let commands = vec![WgetrcCommand::Set("prefer_family".to_string(), "prefer-ipv4".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.prefer_family, AddressFamily::PreferIpv4);
}

#[test]
fn test_apply_bind_address() {
    let commands = vec![WgetrcCommand::Set("bind_address".to_string(), "192.168.1.100".to_string())];
    let mut config = Config::default();
    let result = WgetrcParser::apply(&commands, &mut config);
    assert!(result.is_ok());
    assert_eq!(config.bind_address, Some("192.168.1.100".to_string()));
}
