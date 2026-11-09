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
