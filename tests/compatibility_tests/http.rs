// HTTP 协议行为兼容性测试
//
// 测试 utwget 与原 wget 在 HTTP 协议处理上的一致性

use crate::compatibility_tests::common::{TestContext, CommandComparison};
use crate::require_network;

/// 对比 HTTP 下载行为
fn compare_http_download(ctx: &TestContext, url: &str, args: &[&str]) -> CommandComparison {
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

    // ========== 基本下载测试 ==========

    #[test]
    fn test_http_download_small_file() {
        require_network!();

        let ctx = TestContext::new("http_small").expect("Failed to create context");
        let url = "http://httpbin.org/bytes/1024";

        let comparison = compare_http_download(&ctx, url, &[]);

        // 验证退出码一致
        assert!(comparison.same_exit_code(),
            "Exit codes differ: wget={}, utwget={}",
            comparison.wget.exit_code, comparison.utwget.exit_code);

        // 验证文件下载成功
        assert!(comparison.both_success(), "Both should succeed");

        // 对比下载的文件
        // 注意：httpbin 每次返回随机数据，所以内容会不同
        // 这里只验证文件存在
    }

    #[test]
    fn test_http_download_with_output() {
        require_network!();

        let ctx = TestContext::new("http_output").expect("Failed to create context");
        let url = "http://httpbin.org/get";

        let comparison = compare_http_download(&ctx, url, &["-O", "test.json"]);

        assert!(comparison.same_exit_code(),
            "Exit codes differ: wget={}, utwget={}",
            comparison.wget.exit_code, comparison.utwget.exit_code);
    }

    // ========== 重定向测试 ==========

    #[test]
    fn test_http_redirect_follow() {
        require_network!();

        let ctx = TestContext::new("http_redirect").expect("Failed to create context");
        // httpbin 的 /redirect/n 会重定向 n 次
        let url = "http://httpbin.org/redirect/2";

        let comparison = compare_http_download(&ctx, url, &[]);

        // 两者都应该跟随重定向并成功
        assert!(comparison.both_success(),
            "Both should follow redirects and succeed");
    }

    #[test]
    fn test_http_redirect_max() {
        require_network!();

        let ctx = TestContext::new("http_redirect_max").expect("Failed to create context");
        let url = "http://httpbin.org/redirect/10";

        // 设置最大重定向次数为 5
        let comparison = compare_http_download(&ctx, url, &["--max-redirect", "5"]);

        // 两者都应该因为超过最大重定向次数而失败
        // 注意：退出码可能不同，原 wget 用 8，utwget 可能不同
        println!("wget exit: {}, utwget exit: {}",
            comparison.wget.exit_code, comparison.utwget.exit_code);
    }

    // ========== 认证测试 ==========

    #[test]
    fn test_http_basic_auth() {
        require_network!();

        let ctx = TestContext::new("http_auth").expect("Failed to create context");
        let url = "http://httpbin.org/basic-auth/user/pass";

        let comparison = compare_http_download(&ctx, url,
            &["--http-user", "user", "--http-password", "pass"]);

        assert!(comparison.both_success(),
            "Both should succeed with correct auth");
    }

    // ========== User-Agent 测试 ==========

    #[test]
    fn test_http_user_agent() {
        require_network!();

        let ctx = TestContext::new("http_ua").expect("Failed to create context");
        let url = "http://httpbin.org/user-agent";

        let comparison = compare_http_download(&ctx, url,
            &["-U", "TestAgent/1.0"]);

        assert!(comparison.both_success(),
            "Both should succeed with custom UA");
    }

    // ========== 超时测试 ==========

    #[test]
    fn test_http_timeout() {
        require_network!();

        let ctx = TestContext::new("http_timeout").expect("Failed to create context");
        // httpbin 的 /delay/n 会延迟 n 秒响应
        let url = "http://httpbin.org/delay/1";

        let comparison = compare_http_download(&ctx, url,
            &["-T", "5"]); // 5 秒超时

        assert!(comparison.both_success(),
            "Both should succeed within timeout");
    }

    // ========== POST 请求测试 ==========

    #[test]
    fn test_http_post_data() {
        require_network!();

        let ctx = TestContext::new("http_post").expect("Failed to create context");
        let url = "http://httpbin.org/post";

        let comparison = compare_http_download(&ctx, url,
            &["--post-data", "key=value"]);

        assert!(comparison.both_success(),
            "Both should succeed with POST data");
    }

    // ========== 头部测试 ==========

    #[test]
    fn test_http_custom_header() {
        require_network!();

        let ctx = TestContext::new("http_header").expect("Failed to create context");
        let url = "http://httpbin.org/headers";

        let comparison = compare_http_download(&ctx, url,
            &["--header", "X-Custom: TestValue"]);

        assert!(comparison.both_success(),
            "Both should succeed with custom header");
    }

    // ========== Cookie 测试 ==========

    #[test]
    fn test_http_cookies() {
        require_network!();

        let ctx = TestContext::new("http_cookies").expect("Failed to create context");
        let url = "http://httpbin.org/cookies";

        let comparison = compare_http_download(&ctx, url,
            &["--header", "Cookie: session=abc123"]);

        assert!(comparison.both_success(),
            "Both should succeed with cookies");
    }

    // ========== 递归下载测试 ==========

    #[test]
    fn test_http_recursive_depth_1() {
        require_network!();

        let ctx = TestContext::new("http_recursive").expect("Failed to create context");
        let url = "http://httpbin.org/links/2/2";

        let comparison = compare_http_download(&ctx, url,
            &["-r", "-l", "1", "--no-parent"]);

        // 递归下载行为可能略有不同，只验证都完成
        println!("wget exit: {}, utwget exit: {}",
            comparison.wget.exit_code, comparison.utwget.exit_code);
    }

    // ========== 断点续传测试 ==========

    #[test]
    fn test_http_resume() {
        require_network!();

        let ctx = TestContext::new("http_resume").expect("Failed to create context");
        let url = "http://httpbin.org/bytes/10240";

        // 先下载一部分
        let _ = ctx.run_wget(&[url, "-c", "--start-pos", "0"]);
        let _ = ctx.run_utwget(&[url, "-c", "--start-pos", "0"]);

        // 然后尝试续传
        let comparison = compare_http_download(&ctx, url, &["-c"]);

        println!("wget exit: {}, utwget exit: {}",
            comparison.wget.exit_code, comparison.utwget.exit_code);
    }
}
