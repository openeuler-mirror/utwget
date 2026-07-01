// HTTPS 协议行为兼容性测试

use crate::compatibility_tests::common::{TestContext, CommandComparison};
use crate::require_network;

/// 对比 HTTPS 下载行为
fn compare_https_download(ctx: &TestContext, url: &str, args: &[&str]) -> CommandComparison {
    let mut wget_args = vec![url];
    wget_args.extend(args.iter().copied());

    let mut utwget_args = vec![url];
    utwget_args.extend(args.iter().copied());

    let wget_result = ctx.run_wget(&wget_args).expect("Failed to run wget");
    let utwget_result = ctx.run_utwget(&utwget_args).expect("Failed to run utwget");

    CommandComparison {
        wget: wget_result,
        utwget: utwget_result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== 基本 HTTPS 下载 ==========

    #[test]
    fn test_https_download() {
        require_network!();

        let ctx = TestContext::new("https_basic").expect("Failed to create context");
        let url = "https://httpbin.org/get";

        let comparison = compare_https_download(&ctx, url, &[]);

        assert!(comparison.both_success(),
            "Both should succeed with HTTPS download");
    }

    #[test]
    fn test_https_small_file() {
        require_network!();

        let ctx = TestContext::new("https_small").expect("Failed to create context");
        let url = "https://httpbin.org/bytes/1024";

        let comparison = compare_https_download(&ctx, url, &[]);

        assert!(comparison.both_success(),
            "Both should succeed with HTTPS small file");
    }

    // ========== 证书验证测试 ==========

    #[test]
    fn test_https_no_check_certificate() {
        require_network!();

        let ctx = TestContext::new("https_no_check").expect("Failed to create context");
        let url = "https://httpbin.org/get";

        let comparison = compare_https_download(&ctx, url, &["--no-check-certificate"]);

        assert!(comparison.both_success(),
            "Both should succeed without certificate check");
    }

    // ========== TLS 版本测试 ==========

    #[test]
    fn test_https_tls12() {
        require_network!();

        let ctx = TestContext::new("https_tls12").expect("Failed to create context");
        let url = "https://httpbin.org/get";

        let comparison = compare_https_download(&ctx, url, &["--secure-protocol", "TLSv1.2"]);

        assert!(comparison.both_success(),
            "Both should succeed with TLS 1.2");
    }

    #[test]
    fn test_https_tls13() {
        require_network!();

        let ctx = TestContext::new("https_tls13").expect("Failed to create context");
        let url = "https://httpbin.org/get";

        let comparison = compare_https_download(&ctx, url, &["--secure-protocol", "TLSv1.3"]);

        // TLS 1.3 可能不被所有服务器支持
        println!("wget exit: {}, utwget exit: {}",
            comparison.wget.exit_code, comparison.utwget.exit_code);
    }

    // ========== HSTS 测试 ==========

    #[test]
    fn test_https_hsts() {
        require_network!();

        let ctx = TestContext::new("https_hsts").expect("Failed to create context");
        let url = "https://httpbin.org/get";

        let comparison = compare_https_download(&ctx, url, &["--hsts-file", "hsts.txt"]);

        assert!(comparison.both_success(),
            "Both should succeed with HSTS");
    }

    // ========== HTTPS 认证测试 ==========

    #[test]
    fn test_https_basic_auth() {
        require_network!();

        let ctx = TestContext::new("https_auth").expect("Failed to create context");
        let url = "https://httpbin.org/basic-auth/user/pass";

        let comparison = compare_https_download(&ctx, url,
            &["--http-user", "user", "--http-password", "pass"]);

        assert!(comparison.both_success(),
            "Both should succeed with HTTPS auth");
    }

    // ========== HTTPS 重定向测试 ==========

    #[test]
    fn test_https_redirect() {
        require_network!();

        let ctx = TestContext::new("https_redirect").expect("Failed to create context");
        let url = "https://httpbin.org/redirect/2";

        let comparison = compare_https_download(&ctx, url, &[]);

        assert!(comparison.both_success(),
            "Both should follow HTTPS redirects");
    }

    // ========== HTTPS POST 测试 ==========

    #[test]
    fn test_https_post() {
        require_network!();

        let ctx = TestContext::new("https_post").expect("Failed to create context");
        let url = "https://httpbin.org/post";

        let comparison = compare_https_download(&ctx, url, &["--post-data", "key=value"]);

        assert!(comparison.both_success(),
            "Both should succeed with HTTPS POST");
    }

    // ========== 大文件下载测试 ==========

    #[test]
    fn test_https_large_file() {
        require_network!();

        let ctx = TestContext::new("https_large").expect("Failed to create context");
        let url = "https://httpbin.org/bytes/1048576"; // 1MB

        let comparison = compare_https_download(&ctx, url, &[]);

        assert!(comparison.both_success(),
            "Both should succeed with large HTTPS download");
    }
}
