// 基础下载集成测试 - 不依赖外部服务器，只测试内部模块逻辑

use std::io::Cursor;

// ========== CLI 入口点测试 ==========

#[test]
fn test_cli_args_version_flag() {
    use clap::Parser;
    use utwget_cli::args::Args;
    let args = Args::try_parse_from(["utwget", "--version"]);
    assert!(args.is_ok());
    let args = args.unwrap();
    assert!(args.version);
}

#[test]
fn test_cli_args_help_flag() {
    use clap::Parser;
    use utwget_cli::args::Args;
    let args = Args::try_parse_from(["utwget", "--help"]);
    assert!(args.is_ok());
    let args = args.unwrap();
    assert!(args.help);
}

#[test]
fn test_cli_args_help_short() {
    use clap::Parser;
    use utwget_cli::args::Args;
    let args = Args::try_parse_from(["utwget", "-h"]);
    assert!(args.is_ok());
    let args = args.unwrap();
    assert!(args.help);
}

#[test]
fn test_cli_args_quiet_verbose_conflict() {
    use clap::Parser;
    use utwget_cli::args::Args;
    let result = Args::try_parse_from(["utwget", "-q", "-v"]);
    assert!(result.is_err());
}

#[test]
fn test_cli_args_recursive_defaults() {
    use clap::Parser;
    use utwget_cli::args::Args;
    let args = Args::try_parse_from(["utwget", "-r", "http://example.com/"]).unwrap();
    assert!(args.recursive);
    assert_eq!(args.level, 5);
}

#[test]
fn test_cli_build_config_default() {
    use clap::Parser;
    use utwget_cli::args::Args;
    use utwget_cli::app::build_config;
    let args = Args::try_parse_from(["utwget", "http://example.com/"]).unwrap();
    let config = build_config(&args);
    assert!(!config.quiet);
    assert_eq!(config.tries, 20);
    assert_eq!(config.max_redirect, 20);
    assert!(!config.recursive.enabled);
}

#[test]
fn test_cli_build_config_quiet() {
    use clap::Parser;
    use utwget_cli::args::Args;
    use utwget_cli::app::build_config;
    let args = Args::try_parse_from(["utwget", "-q", "http://example.com/"]).unwrap();
    let config = build_config(&args);
    assert!(config.quiet);
    assert_eq!(config.verbose, 0);
}

// ========== ParsedUrl 测试 ==========

#[test]
fn test_parsed_url_http_default_port() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("http://example.com/path").unwrap();
    assert_eq!(url.scheme.as_str(), "http");
    assert_eq!(url.host, "example.com");
    assert_eq!(url.port, 80);
    assert_eq!(url.path, "/path");
}

#[test]
fn test_parsed_url_https_with_port() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("https://host:8443/a/b").unwrap();
    assert_eq!(url.scheme.as_str(), "https");
    assert_eq!(url.port, 8443);
    assert_eq!(url.path, "/a/b");
}

#[test]
fn test_parsed_url_ftp() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("ftp://ftp.example.com/pub/file.txt").unwrap();
    assert_eq!(url.scheme.as_str(), "ftp");
    assert_eq!(url.port, 21);
}

#[test]
fn test_parsed_url_with_credentials() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("https://user:pass@example.com/secret").unwrap();
    assert_eq!(url.user.as_deref(), Some("user"));
    assert_eq!(url.password.as_deref(), Some("pass"));
}

#[test]
fn test_parsed_url_with_query_and_fragment() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("http://host/page?key=val#section").unwrap();
    assert_eq!(url.query.as_deref(), Some("key=val"));
    assert_eq!(url.fragment.as_deref(), Some("section"));
}

#[test]
fn test_parsed_url_display_omits_default_port() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("http://example.com:80/path").unwrap();
    let display = url.to_string();
    assert!(!display.contains(":80"));
}

#[test]
fn test_parsed_url_display_includes_nondefault_port() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("http://example.com:8080/path").unwrap();
    let display = url.to_string();
    assert!(display.contains(":8080"));
}

#[test]
fn test_parsed_url_merge_relative() {
    use ut_core::ParsedUrl;
    let base = ParsedUrl::parse("http://example.com/dir/page.html").unwrap();
    let merged = base.merge("sub.html").unwrap();
    assert_eq!(merged.path, "/dir/sub.html");
    assert_eq!(merged.host, "example.com");
}

#[test]
fn test_parsed_url_merge_absolute_path() {
    use ut_core::ParsedUrl;
    let base = ParsedUrl::parse("http://example.com/dir/page.html").unwrap();
    let merged = base.merge("/other").unwrap();
    assert_eq!(merged.path, "/other");
}

#[test]
fn test_parsed_url_to_filename_no_host() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("http://example.com/dir/file.html").unwrap();
    let path = url.to_filename(true);
    assert_eq!(path.to_string_lossy(), "file.html");
}
