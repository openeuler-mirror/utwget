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
