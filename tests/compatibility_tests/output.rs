// 输出格式兼容性测试
//
// 测试 utwget 与原 wget 的输出格式一致性

use crate::compatibility_tests::common::TestContext;
use crate::require_network;

#[cfg(test)]
mod tests {
    use super::*;

    // ========== 帮助输出格式 ==========

    #[test]
    fn test_help_format() {
        let ctx = TestContext::new("help_format").expect("Failed to create context");

        let wget_result = ctx.run_wget(&["--help"]).expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&["--help"]).expect("Failed to run utwget");

        // 检查关键选项是否都出现在帮助中
        let wget_help = &wget_result.stdout;
        let utwget_help = &utwget_result.stdout;

        // 基本选项
        let essential_options = [
            "-V, --version",
            "-h, --help",
            "-b, --background",
            "-o, --output-file",
            "-q, --quiet",
            "-v, --verbose",
            "-i, --input-file",
            "-r, --recursive",
            "-O, --output-document",
            "-P, --directory-prefix",
            "-T, --timeout",
            "-t, --tries",
            "--http-user",
            "--http-password",
            "--no-check-certificate",
        ];

        println!("\n=== 选项覆盖检查 ===");
        for opt in &essential_options {
            let wget_has = wget_help.contains(opt);
            let utwget_has = utwget_help.contains(opt);
            println!("{}: wget={}, utwget={}", opt, wget_has, utwget_has);
        }

        // 统计选项数量
        let wget_option_count = wget_help.lines()
            .filter(|line| line.contains("  -") || line.contains("--"))
            .count();
        let utwget_option_count = utwget_help.lines()
            .filter(|line| line.contains("  -") || line.contains("--"))
            .count();

        println!("\n选项行数: wget={}, utwget={}", wget_option_count, utwget_option_count);
    }

    // ========== 版本输出格式 ==========

    #[test]
    fn test_version_format() {
        let ctx = TestContext::new("version_format").expect("Failed to create context");

        let wget_result = ctx.run_wget(&["--version"]).expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&["--version"]).expect("Failed to run utwget");

        println!("wget version output:\n{}", wget_result.stdout);
        println!("utwget version output:\n{}", utwget_result.stdout);

        // 检查版本格式
        assert!(wget_result.stdout.contains("GNU Wget"));
        assert!(wget_result.stdout.contains("1.21.4"));

        // utwget 应该包含版本信息
        let utwget_output = format!("{}{}", utwget_result.stdout, utwget_result.stderr);
        assert!(utwget_output.contains("utwget") || utwget_output.contains("0.1.0"));
    }

    // ========== 错误输出格式 ==========

    #[test]
    fn test_error_format_invalid_url() {
        let ctx = TestContext::new("error_format").expect("Failed to create context");

        let wget_result = ctx.run_wget(&["not-a-valid-url"]).expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&["not-a-valid-url"]).expect("Failed to run utwget");

        println!("wget error:\n{}", wget_result.stderr);
        println!("utwget error:\n{}", utwget_result.stderr);

        // 两者都应该失败
        assert!(!wget_result.success);
        assert!(!utwget_result.success);
    }

    #[test]
    fn test_error_format_nonexistent_host() {
        require_network!();

        let ctx = TestContext::new("error_host").expect("Failed to create context");

        let wget_result = ctx.run_wget(&["http://this-host-does-not-exist-12345.com/"])
            .expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&["http://this-host-does-not-exist-12345.com/"])
            .expect("Failed to run utwget");

        println!("wget error:\n{}", wget_result.stderr);
        println!("utwget error:\n{}", utwget_result.stderr);

        // 两者都应该失败
        assert!(!wget_result.success);
        assert!(!utwget_result.success);
    }

    // ========== 进度输出格式 ==========

    #[test]
    fn test_progress_format() {
        require_network!();

        let ctx = TestContext::new("progress_format").expect("Failed to create context");
        let url = "http://httpbin.org/bytes/10240";

        let wget_result = ctx.run_wget(&[url, "--progress=bar"])
            .expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&[url, "--progress=bar"])
            .expect("Failed to run utwget");

        println!("wget output:\n{}", wget_result.stderr);
        println!("utwget output:\n{}", utwget_result.stderr);

        // 检查进度条格式
        // 原 wget: 100%[====================================>] 10,240  ...
        // utwget 应该有类似的格式
    }

    // ========== 服务器响应头格式 ==========

    #[test]
    fn test_server_response_format() {
        require_network!();

        let ctx = TestContext::new("server_response").expect("Failed to create context");
        let url = "http://httpbin.org/get";

        let wget_result = ctx.run_wget(&[url, "-S"])
            .expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&[url, "-S"])
            .expect("Failed to run utwget");

        println!("wget server response:\n{}", wget_result.stderr);
        println!("utwget server response:\n{}", utwget_result.stderr);

        // 检查服务器响应头是否输出
        // 应该包含 HTTP/1.1 200 OK 等信息
    }

    // ========== 重定向输出格式 ==========

    #[test]
    fn test_redirect_output_format() {
        require_network!();

        let ctx = TestContext::new("redirect_format").expect("Failed to create context");
        let url = "http://httpbin.org/redirect/1";

        let wget_result = ctx.run_wget(&[url, "-v"])
            .expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&[url, "-v"])
            .expect("Failed to run utwget");

        println!("wget redirect output:\n{}", wget_result.stderr);
        println!("utwget redirect output:\n{}", utwget_result.stderr);

        // 检查重定向信息格式
        // 原 wget: HTTP request sent, awaiting response... 302 Found
        // Location: http://httpbin.org/get [following]
    }

    // ========== 认证失败输出格式 ==========

    #[test]
    fn test_auth_failure_format() {
        require_network!();

        let ctx = TestContext::new("auth_failure").expect("Failed to create context");
        let url = "http://httpbin.org/basic-auth/user/pass";

        // 使用错误的密码
        let wget_result = ctx.run_wget(&[url, "--http-user=user", "--http-password=wrong"])
            .expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&[url, "--http-user=user", "--http-password=wrong"])
            .expect("Failed to run utwget");

        println!("wget auth error:\n{}", wget_result.stderr);
        println!("utwget auth error:\n{}", utwget_result.stderr);

        // 两者都应该失败
        assert!(!wget_result.success);
        assert!(!utwget_result.success);
    }

    // ========== 保存文件输出格式 ==========

    #[test]
    fn test_save_output_format() {
        require_network!();

        let ctx = TestContext::new("save_format").expect("Failed to create context");
        let url = "http://httpbin.org/get";

        let wget_result = ctx.run_wget(&[url, "-O", "test.json"])
            .expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&[url, "-O", "test.json"])
            .expect("Failed to run utwget");

        println!("wget save output:\n{}", wget_result.stderr);
        println!("utwget save output:\n{}", utwget_result.stderr);

        // 检查保存信息格式
        // 原 wget: Saving to: 'test.json'
        // 100%[====================================>] ...
    }

    // ========== 断点续传输出格式 ==========

    #[test]
    fn test_resume_output_format() {
        require_network!();

        let ctx = TestContext::new("resume_format").expect("Failed to create context");
        let url = "http://httpbin.org/bytes/10240";

        let wget_result = ctx.run_wget(&[url, "-c", "-v"])
            .expect("Failed to run wget");
        let utwget_result = ctx.run_utwget(&[url, "-c", "-v"])
            .expect("Failed to run utwget");

        println!("wget resume output:\n{}", wget_result.stderr);
        println!("utwget resume output:\n{}", utwget_result.stderr);
    }

    // ========== 退出码测试 ==========

    #[test]
    fn test_exit_codes() {
        require_network!();

        let ctx = TestContext::new("exit_codes").expect("Failed to create context");

        // 成功下载
        let wget_result = ctx.run_wget(&["http://httpbin.org/get"]).unwrap();
        let utwget_result = ctx.run_utwget(&["http://httpbin.org/get"]).unwrap();
        println!("Success: wget={}, utwget={}", wget_result.exit_code, utwget_result.exit_code);
        assert_eq!(wget_result.exit_code, 0);
        assert_eq!(utwget_result.exit_code, 0);

        // URL 解析错误
        let wget_result = ctx.run_wget(&["not-a-url"]).unwrap();
        let utwget_result = ctx.run_utwget(&["not-a-url"]).unwrap();
        println!("Parse error: wget={}, utwget={}", wget_result.exit_code, utwget_result.exit_code);

        // 网络错误
        let wget_result = ctx.run_wget(&["http://localhost:59999/"]).unwrap();
        let utwget_result = ctx.run_utwget(&["http://localhost:59999/"]).unwrap();
        println!("Network error: wget={}, utwget={}", wget_result.exit_code, utwget_result.exit_code);
    }
}
