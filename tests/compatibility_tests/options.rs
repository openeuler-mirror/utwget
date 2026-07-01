// 命令行选项兼容性测试
//
// 测试 utwget 与原 wget 的命令行选项解析一致性

use crate::compatibility_tests::common::{TestContext, CommandComparison};

/// 对比命令行选项行为
fn compare_options(ctx: &TestContext, args: &[&str]) -> CommandComparison {
    let wget_result = ctx.run_wget(args).expect("Failed to run wget");
    let utwget_result = ctx.run_utwget(args).expect("Failed to run utwget");

    CommandComparison {
        wget: wget_result,
        utwget: utwget_result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== 帮助选项 ==========

    #[test]
    fn test_help_long() {
        let ctx = TestContext::new("help").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["--help"]);

        // 帮助信息应该输出到 stdout，退出码为 0
        assert!(comparison.wget.success);
        assert!(comparison.utwget.success);
        assert!(!comparison.wget.stdout.is_empty());
        assert!(!comparison.utwget.stdout.is_empty());
    }

    #[test]
    fn test_help_short() {
        let ctx = TestContext::new("help_short").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-h"]);

        assert!(comparison.wget.success);
        assert!(comparison.utwget.success);
    }

    // ========== 版本选项 ==========

    #[test]
    fn test_version_long() {
        let ctx = TestContext::new("version").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["--version"]);

        assert!(comparison.wget.success);
        assert!(comparison.utwget.success);
        assert!(comparison.wget.stdout.contains("GNU Wget"));
        // utwget 版本输出
        assert!(comparison.utwget.stdout.contains("utwget"),
            "utwget version should contain 'utwget'");
        assert!(comparison.utwget.stdout.contains("Rust"),
            "utwget version should mention Rust");
    }

    #[test]
    fn test_version_short() {
        let ctx = TestContext::new("version_short").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-V"]);

        assert!(comparison.wget.success);
        assert!(comparison.utwget.success);
    }

    // ========== 输出选项 ==========

    #[test]
    fn test_output_file() {
        let ctx = TestContext::new("output").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-O", "test.txt", "http://example.com/"]);

        // 没有实际下载，只验证选项解析
        println!("wget stderr: {}", comparison.wget.stderr);
        println!("utwget stderr: {}", comparison.utwget.stderr);
    }

    #[test]
    fn test_output_document() {
        let ctx = TestContext::new("output_doc").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["--output-document=test.txt", "http://example.com/"]);

        println!("wget stderr: {}", comparison.wget.stderr);
        println!("utwget stderr: {}", comparison.utwget.stderr);
    }

    #[test]
    fn test_directory_prefix() {
        let ctx = TestContext::new("dir_prefix").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-P", "downloads", "http://example.com/"]);

        println!("wget stderr: {}", comparison.wget.stderr);
        println!("utwget stderr: {}", comparison.utwget.stderr);
    }

    // ========== 日志选项 ==========

    #[test]
    fn test_quiet() {
        let ctx = TestContext::new("quiet").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-q", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    #[test]
    fn test_verbose() {
        let ctx = TestContext::new("verbose").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-v", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    #[test]
    fn test_debug() {
        let ctx = TestContext::new("debug").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-d", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    // ========== 递归选项 ==========

    #[test]
    fn test_recursive() {
        let ctx = TestContext::new("recursive").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-r", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    #[test]
    fn test_level() {
        let ctx = TestContext::new("level").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-r", "-l", "2", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    #[test]
    fn test_mirror() {
        let ctx = TestContext::new("mirror").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-m", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    // ========== 超时选项 ==========

    #[test]
    fn test_timeout() {
        let ctx = TestContext::new("timeout").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-T", "30", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    #[test]
    fn test_connect_timeout() {
        let ctx = TestContext::new("connect_timeout").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["--connect-timeout=10", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    #[test]
    fn test_read_timeout() {
        let ctx = TestContext::new("read_timeout").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["--read-timeout=30", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    // ========== 重试选项 ==========

    #[test]
    fn test_tries() {
        let ctx = TestContext::new("tries").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["-t", "3", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    #[test]
    fn test_retry_connrefused() {
        let ctx = TestContext::new("retry_connrefused").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["--retry-connrefused", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    // ========== 认证选项 ==========

    #[test]
    fn test_http_user_password() {
        let ctx = TestContext::new("auth").expect("Failed to create context");
        let comparison = compare_options(&ctx,
            &["--http-user=user", "--http-password=pass", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    #[test]
    fn test_user_password() {
        let ctx = TestContext::new("auth_generic").expect("Failed to create context");
        let comparison = compare_options(&ctx,
            &["--user=user", "--password=pass", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    // ========== 代理选项 ==========

    #[test]
    fn test_no_proxy() {
        let ctx = TestContext::new("no_proxy").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["--no-proxy", "http://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    // ========== HTTPS 选项 ==========

    #[test]
    fn test_no_check_certificate() {
        let ctx = TestContext::new("no_cert").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["--no-check-certificate", "https://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    #[test]
    fn test_secure_protocol() {
        let ctx = TestContext::new("secure_proto").expect("Failed to create context");
        let comparison = compare_options(&ctx,
            &["--secure-protocol=TLSv1.2", "https://example.com/"]);

        println!("wget exit: {}", comparison.wget.exit_code);
        println!("utwget exit: {}", comparison.utwget.exit_code);
    }

    // ========== 复合短选项 ==========

    #[test]
    fn test_compound_short_options() {
        let ctx = TestContext::new("compound").expect("Failed to create context");

        // -nc = --no-clobber
        let comparison = compare_options(&ctx, &["-nc", "http://example.com/"]);
        println!("-nc: wget={}, utwget={}", comparison.wget.exit_code, comparison.utwget.exit_code);

        // -nd = --no-directories
        let comparison = compare_options(&ctx, &["-nd", "http://example.com/"]);
        println!("-nd: wget={}, utwget={}", comparison.wget.exit_code, comparison.utwget.exit_code);

        // -nH = --no-host-directories
        let comparison = compare_options(&ctx, &["-nH", "http://example.com/"]);
        println!("-nH: wget={}, utwget={}", comparison.wget.exit_code, comparison.utwget.exit_code);

        // -np = --no-parent
        let comparison = compare_options(&ctx, &["-np", "http://example.com/"]);
        println!("-np: wget={}, utwget={}", comparison.wget.exit_code, comparison.utwget.exit_code);
    }

    // ========== 无效选项测试 ==========

    #[test]
    fn test_invalid_option() {
        let ctx = TestContext::new("invalid").expect("Failed to create context");
        let comparison = compare_options(&ctx, &["--invalid-option"]);

        // 两者都应该失败
        assert!(!comparison.wget.success);
        assert!(!comparison.utwget.success);
    }

    // ========== 冲突选项测试 ==========

    #[test]
    fn test_conflicting_options() {
        let ctx = TestContext::new("conflict").expect("Failed to create context");

        // -q 和 -v 冲突
        let comparison = compare_options(&ctx, &["-q", "-v", "http://example.com/"]);

        // 两者都应该报告错误
        println!("wget stderr: {}", comparison.wget.stderr);
        println!("utwget stderr: {}", comparison.utwget.stderr);
    }
}
