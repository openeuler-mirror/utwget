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

#[test]
fn test_parsed_url_to_filename_with_host() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("http://example.com/dir/file.html").unwrap();
    // Default wget behavior: just use the filename, not the full path
    let path = url.to_filename(false);
    assert_eq!(path.to_string_lossy(), "file.html");
}

#[test]
fn test_parsed_url_parse_error_no_scheme() {
    use ut_core::ParsedUrl;
    let result = ParsedUrl::parse("example.com/path");
    assert!(result.is_err());
}

#[test]
fn test_parsed_url_ipv6() {
    use ut_core::ParsedUrl;
    let url = ParsedUrl::parse("http://[::1]:8080/path").unwrap();
    assert_eq!(url.host, "::1");
    assert_eq!(url.port, 8080);
}

// ========== Config 默认值测试 ==========

#[test]
fn test_config_default_values() {
    use ut_core::Config;
    let config = Config::default();
    assert_eq!(config.tries, 20);
    assert!(!config.quiet);
    assert!(!config.background);
    assert!(!config.recursive.enabled);
    assert!(!config.noclobber);
    assert!(!config.continue_download);
    assert!(!config.timestamping);
    assert_eq!(config.max_redirect, 20);
    assert!(config.cookie.enabled);
    assert!(config.proxy.use_proxy);
    assert!(!config.http.https_only);
    assert!(config.ftp.passive);
}

#[test]
fn test_config_http_defaults() {
    use ut_core::Config;
    let config = Config::default();
    assert!(config.http.keep_alive);
    assert_eq!(config.http.default_page, "index.html");
    assert!(config.http.method.is_none());
    assert!(config.http.post_data.is_none());
}

// ========== CookieJar 测试 ==========

#[test]
fn test_cookie_jar_parse_set_cookie_basic() {
    use ut_core::CookieJar;
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("session=abc123; Path=/; Domain=example.com", "example.com", "/page");
    assert_eq!(jar.len(), 1);
}

#[test]
fn test_cookie_jar_match_request() {
    use ut_core::{CookieJar, Scheme};
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("lang=zh; Path=/; Domain=example.com", "example.com", "/");
    let cookies = jar.match_request("example.com", "/index.html", Scheme::Http);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "lang");
}

#[test]
fn test_cookie_jar_secure_only_matches_https() {
    use ut_core::{CookieJar, Scheme};
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("token=secret; Secure; Path=/", "example.com", "/");
    let http_cookies = jar.match_request("example.com", "/", Scheme::Http);
    assert_eq!(http_cookies.len(), 0);
    let https_cookies = jar.match_request("example.com", "/", Scheme::Https);
    assert_eq!(https_cookies.len(), 1);
}

#[test]
fn test_cookie_jar_serialize_for_header() {
    use ut_core::{CookieJar, Scheme};
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("a=1; Path=/", "example.com", "/");
    jar.parse_set_cookie("b=2; Path=/", "example.com", "/");
    let header = jar.serialize_for_header("example.com", "/", Scheme::Http);
    assert!(header.is_some());
    let val = header.unwrap();
    assert!(val.contains("a=1"));
    assert!(val.contains("b=2"));
}

#[test]
fn test_cookie_jar_path_match() {
    use ut_core::{CookieJar, Scheme};
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("sid=xyz; Path=/admin", "example.com", "/admin");
    let cookies = jar.match_request("example.com", "/admin/dashboard", Scheme::Http);
    assert_eq!(cookies.len(), 1);
}

#[test]
fn test_cookie_jar_load_from_netscape_format() {
    use ut_core::CookieJar;
    let data = "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t9999999999\tname\tvalue\n";
    let mut jar = CookieJar::new();
    jar.load_from_reader(data.as_bytes()).unwrap();
    assert_eq!(jar.len(), 1);
}

#[test]
fn test_cookie_jar_save_to_writer() {
    use ut_core::CookieJar;
    let mut jar = CookieJar::new();
    jar.parse_set_cookie(
        "name=value; Domain=example.com; Path=/; Expires=Wed, 09 Jun 2100 00:00:00 GMT",
        "example.com",
        "/",
    );
    let mut output = Vec::new();
    jar.save_to_writer(&mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("# Netscape HTTP Cookie File"));
    assert!(text.contains("name"));
}

#[test]
fn test_cookie_jar_remove_expired() {
    use ut_core::CookieJar;
    let mut jar = CookieJar::new();
    jar.parse_set_cookie("old=1; Max-Age=0; Domain=example.com", "example.com", "/");
    jar.remove_expired();
    assert_eq!(jar.len(), 0);
}

// ========== RobotParser 测试 ==========

#[test]
fn test_robot_parser_basic() {
    use ut_core::RobotParser;
    let content = r#"
User-agent: *
Disallow: /private/
Allow: /private/public/
"#;
    let mut parser = RobotParser::new("utwget");
    parser.load("example.com", content);
    assert_eq!(parser.is_allowed("example.com", "http://example.com/page"), Some(true));
    assert_eq!(parser.is_allowed("example.com", "http://example.com/private/secret"), Some(false));
    assert_eq!(parser.is_allowed("example.com", "http://example.com/private/public/ok"), Some(true));
}

#[test]
fn test_robot_parser_specific_agent() {
    use ut_core::RobotParser;
    let content = r#"
User-agent: *
Disallow: /

User-agent: Googlebot
Disallow: /
Allow: /search/
"#;
    let mut parser = RobotParser::new("Googlebot");
    parser.load("example.com", content);
    // /search/ path is allowed, /search?q=test has path /search which doesn't match /search/
    // Use a path that starts with /search/ instead
    assert_eq!(parser.is_allowed("example.com", "http://example.com/search/results?q=test"), Some(true));
    assert_eq!(parser.is_allowed("example.com", "http://example.com/other"), Some(false));
}

#[test]
fn test_robot_parser_crawl_delay() {
    use ut_core::RobotParser;
    let content = r#"
User-agent: utwget
Crawl-delay: 5
"#;
    let mut parser = RobotParser::new("utwget");
    parser.load("example.com", content);
    assert_eq!(parser.crawl_delay("example.com"), Some(5.0));
}

#[test]
fn test_robot_parser_sitemap() {
    use ut_core::RobotParser;
    let content = r#"
User-agent: *
Sitemap: https://example.com/sitemap.xml
"#;
    let mut parser = RobotParser::new("utwget");
    parser.load("example.com", content);
    let sitemaps = parser.sitemaps("example.com");
    assert_eq!(sitemaps.len(), 1);
    assert_eq!(sitemaps[0], "https://example.com/sitemap.xml");
}

#[test]
fn test_robot_parser_empty_disallow_allows_all() {
    use ut_core::RobotParser;
    let content = "User-agent: *\nDisallow:\n";
    let mut parser = RobotParser::new("utwget");
    parser.load("example.com", content);
    assert_eq!(parser.is_allowed("example.com", "http://example.com/anything"), Some(true));
}

// ========== UrlFilter 测试 ==========

#[test]
fn test_composite_filter_all_must_pass() {
    use ut_core::regex_filter::{CompositeFilter, PatternAcceptFilter, UrlFilter};
    let mut composite = CompositeFilter::new();
    composite.add(PatternAcceptFilter::new(vec!["*.html".into()]));
    composite.add(PatternAcceptFilter::new(vec!["*".into()]));
    assert!(composite.is_accepted("", "page.html"));
    assert!(!composite.is_accepted("", "image.png"));
}

#[test]
fn test_domain_filter_includes_subdomains() {
    use ut_core::regex_filter::{DomainFilter, UrlFilter};
    let filter = DomainFilter::new(vec!["example.com".into()], vec![]);
    assert!(filter.is_accepted("http://sub.example.com/page", ""));
    assert!(!filter.is_accepted("http://other.org/page", ""));
}

#[test]
fn test_domain_filter_exclude() {
    use ut_core::regex_filter::{DomainFilter, UrlFilter};
    let filter = DomainFilter::new(vec!["example.com".into()], vec!["bad.example.com".into()]);
    assert!(filter.is_accepted("http://example.com/", ""));
    assert!(!filter.is_accepted("http://bad.example.com/", ""));
    assert!(filter.is_accepted("http://good.example.com/", ""));
}

#[test]
fn test_blacklist_filter_dedup() {
    use ut_core::regex_filter::{BlacklistFilter, UrlFilter};
    let mut filter = BlacklistFilter::new();
    assert!(filter.is_accepted("http://example.com/a", ""));
    filter.insert("http://example.com/a");
    assert!(!filter.is_accepted("http://example.com/a", ""));
    assert!(filter.is_accepted("http://example.com/b", ""));
}

#[test]
fn test_parent_filter_allows_child_paths() {
    use ut_core::regex_filter::{ParentFilter, UrlFilter};
    let filter = ParentFilter::new(true, "http://example.com/dir/");
    assert!(filter.is_accepted("http://example.com/dir/page.html", ""));
    assert!(filter.is_accepted("http://example.com/dir/sub/page.html", ""));
}

// ========== HstsStore 测试 ==========

#[test]
fn test_hsts_store_basic() {
    use ut_core::HstsStore;
    let mut store = HstsStore::new();
    store.add("example.com", true, 31536000);
    assert_eq!(store.len(), 1);
    assert!(store.lookup("example.com").is_some());
}

#[test]
fn test_hsts_should_upgrade_http_to_https() {
    use ut_core::{HstsStore, Scheme};
    let mut store = HstsStore::new();
    store.add("secure.example.com", true, 31536000);
    let upgraded = store.should_upgrade("secure.example.com", Scheme::Http);
    assert_eq!(upgraded, Scheme::Https);
}

#[test]
fn test_hsts_should_not_upgrade_if_not_in_store() {
    use ut_core::{HstsStore, Scheme};
    let store = HstsStore::new();
    let scheme = store.should_upgrade("unknown.com", Scheme::Http);
    assert_eq!(scheme, Scheme::Http);
}

#[test]
fn test_hsts_max_age_zero_removes() {
    use ut_core::HstsStore;
    let mut store = HstsStore::new();
    store.add("example.com", true, 31536000);
    assert_eq!(store.len(), 1);
    store.add("example.com", true, 0);
    assert_eq!(store.len(), 0);
}

#[test]
fn test_hsts_include_subdomains() {
    use ut_core::HstsStore;
    let mut store = HstsStore::new();
    store.add("example.com", true, 31536000);
    assert!(store.lookup("sub.example.com").is_some());
}

#[test]
fn test_hsts_save_and_load() {
    use ut_core::HstsStore;
    use std::path::PathBuf;
    let path = PathBuf::from("/tmp/wget_test_hsts.json");
    let mut store = HstsStore::new();
    store.add("example.com", true, 31536000);
    store.save_to_file(&path).unwrap();
    let mut loaded = HstsStore::new();
    loaded.load_from_file(&path).unwrap();
    assert!(loaded.lookup("example.com").is_some());
    let _ = std::fs::remove_file(&path);
}

// ========== NetrcDb 测试 ==========

#[test]
fn test_netrc_lookup_specific_host() {
    use ut_core::NetrcDb;
    let mut db = NetrcDb::new();
    db.load_from_str(r#"
machine ftp.example.com
login myuser
password mypass
"#);
    let creds = db.lookup("ftp.example.com").unwrap();
    assert_eq!(creds.username, "myuser");
    assert_eq!(creds.password, "mypass");
}

#[test]
fn test_netrc_default_fallback() {
    use ut_core::NetrcDb;
    let mut db = NetrcDb::new();
    db.load_from_str(r#"
default
login anonymous
password user@example.com
"#);
    let creds = db.lookup("unknown.host").unwrap();
    assert_eq!(creds.username, "anonymous");
}

#[test]
fn test_netrc_empty_db() {
    use ut_core::NetrcDb;
    let db = NetrcDb::new();
    assert!(db.is_empty());
    assert!(db.lookup("any.host").is_none());
}

#[test]
fn test_netrc_multiple_machines() {
    use ut_core::NetrcDb;
    let mut db = NetrcDb::new();
    db.load_from_str(r#"
machine host1.com
login user1
password pass1
machine host2.com
login user2
password pass2
"#);
    let c1 = db.lookup("host1.com").unwrap();
    assert_eq!(c1.username, "user1");
    let c2 = db.lookup("host2.com").unwrap();
    assert_eq!(c2.username, "user2");
}

// ========== utils 测试 ==========

#[test]
fn test_safe_filename_basic() {
    use ut_core::utils::safe_filename;
    assert_eq!(safe_filename("file.txt"), "file.txt");
    assert_eq!(safe_filename("path/to/file"), "path_to_file");
}

#[test]
fn test_safe_filename_control_chars() {
    use ut_core::utils::safe_filename;
    let result = safe_filename("file\x01name.txt");
    assert!(!result.contains("\x01"));
}

#[test]
fn test_parse_size_string_basic() {
    use ut_core::utils::parse_size_string;
    assert_eq!(parse_size_string("1024"), Some(1024));
    assert_eq!(parse_size_string("1K"), Some(1024));
    assert_eq!(parse_size_string("1M"), Some(1024 * 1024));
    assert_eq!(parse_size_string("1G"), Some(1024 * 1024 * 1024));
    assert_eq!(parse_size_string("1T"), Some(1024 * 1024 * 1024 * 1024));
}

#[test]
fn test_parse_size_string_float() {
    use ut_core::utils::parse_size_string;
    assert_eq!(parse_size_string("1.5K"), Some(1536));
    assert_eq!(parse_size_string("2.5M"), Some(2621440));
}

#[test]
fn test_parse_size_string_edge_cases() {
    use ut_core::utils::parse_size_string;
    assert_eq!(parse_size_string(""), None);
    assert_eq!(parse_size_string("0"), Some(0));
    assert_eq!(parse_size_string("  512  "), Some(512));
}

#[test]
fn test_format_timestamp() {
    use ut_core::utils::format_timestamp;
    assert_eq!(format_timestamp(0), "1970-01-01 00:00:00");
}

// ========== HtmlExtractor 测试 ==========

#[test]
fn test_html_extractor_simple_links() {
    use ut_html::{HtmlExtractor, ContentExtractor};
    use ut_html::ExtractOptions;
    let html = r#"<html><body>
<a href="http://example.com/page1">Link1</a>
<img src="/images/logo.png">
<script src="app.js"></script>
</body></html>"#;
    let extractor = HtmlExtractor;
    let opts = ExtractOptions::default();
    let mut cursor = Cursor::new(html.as_bytes());
    let results = extractor.extract_urls(&mut cursor, "http://example.com/", &opts).unwrap();
    assert!(results.len() >= 3);
    assert!(results.iter().any(|p| p.url == "http://example.com/page1"));
    assert!(results.iter().any(|p| p.url == "/images/logo.png" && p.inline));
}

#[test]
fn test_html_extractor_skip_javascript_data() {
    use ut_html::{HtmlExtractor, ContentExtractor};
    use ut_html::ExtractOptions;
    let html = r#"<html><body>
<a href="javascript:void(0)">JS</a>
<a href="data:text/html,test">Data</a>
<a href="http://example.com/real">Real</a>
</body></html>"#;
    let extractor = HtmlExtractor;
    let opts = ExtractOptions::default();
    let mut cursor = Cursor::new(html.as_bytes());
    let results = extractor.extract_urls(&mut cursor, "http://example.com/", &opts).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://example.com/real");
}

#[test]
fn test_html_extractor_meta_refresh() {
    use ut_html::{HtmlExtractor, ContentExtractor};
    use ut_html::ExtractOptions;
    let html = r#"<html><head>
<meta http-equiv="refresh" content="5;url=http://example.com/redirect">
</head></html>"#;
    let extractor = HtmlExtractor;
    let opts = ExtractOptions::default();
    let mut cursor = Cursor::new(html.as_bytes());
    let results = extractor.extract_urls(&mut cursor, "http://example.com/", &opts).unwrap();
    assert!(results.iter().any(|p| matches!(p.link_type, ut_html::url_position::LinkType::RefreshRedirect)));
}

#[test]
fn test_html_extractor_ignore_tags() {
    use ut_html::{HtmlExtractor, ContentExtractor};
    use ut_html::ExtractOptions;
    let html = r#"<html><body>
<a href="http://example.com/a">Link</a>
<img src="http://example.com/img.png">
</body></html>"#;
    let mut opts = ExtractOptions::default();
    opts.ignore_tags = vec!["a".to_string()];
    let extractor = HtmlExtractor;
    let mut cursor = Cursor::new(html.as_bytes());
    let results = extractor.extract_urls(&mut cursor, "http://example.com/", &opts).unwrap();
    assert!(results.iter().any(|p| p.attr_name.as_deref() == Some("src")));
    assert!(!results.iter().any(|p| p.attr_name.as_deref() == Some("href")));
}

#[test]
fn test_html_extractor_content_kind() {
    use ut_html::{HtmlExtractor, ContentExtractor};
    let extractor = HtmlExtractor;
    assert!(matches!(extractor.content_kind(), ut_html::types::ContentKind::Html));
}

// ========== CssExtractor 测试 ==========

#[test]
fn test_css_extractor_url_tokens() {
    use ut_html::{CssExtractor, ContentExtractor};
    use ut_html::ExtractOptions;
    let css = r#"
body { background: url(http://example.com/bg.png); }
.logo { content: url('/images/logo.svg'); }
"#;
    let extractor = CssExtractor;
    let opts = ExtractOptions::default();
    let mut cursor = Cursor::new(css.as_bytes());
    let results = extractor.extract_urls(&mut cursor, "http://example.com/", &opts).unwrap();
    assert!(results.iter().any(|p| p.url == "http://example.com/bg.png"));
    assert!(results.iter().any(|p| p.url == "/images/logo.svg"));
}

#[test]
fn test_css_extractor_import() {
    use ut_html::{CssExtractor, ContentExtractor};
    use ut_html::ExtractOptions;
    let css = r#"
@import url("http://example.com/styles/reset.css");
body { background: url(/bg.png); }
"#;
    let extractor = CssExtractor;
    let opts = ExtractOptions::default();
    let mut cursor = Cursor::new(css.as_bytes());
    let results = extractor.extract_urls(&mut cursor, "http://example.com/", &opts).unwrap();
    let imports: Vec<_> = results.iter().filter(|p| matches!(p.link_type, ut_html::url_position::LinkType::CssImport)).collect();
    assert_eq!(imports.len(), 1);
}

#[test]
fn test_css_extractor_skip_data_urls() {
    use ut_html::{CssExtractor, ContentExtractor};
    use ut_html::ExtractOptions;
    let css = r#"
.icon { background: url(data:image/png;base64,ABC); }
.link { background: url(http://example.com/img.png); }
"#;
    let extractor = CssExtractor;
    let opts = ExtractOptions::default();
    let mut cursor = Cursor::new(css.as_bytes());
    let results = extractor.extract_urls(&mut cursor, "http://example.com/", &opts).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://example.com/img.png");
}

#[test]
fn test_css_extractor_content_kind() {
    use ut_html::{CssExtractor, ContentExtractor};
    let extractor = CssExtractor;
    assert!(matches!(extractor.content_kind(), ut_html::types::ContentKind::Css));
}

// ========== ContentExtractor trait 接口一致性 ==========

#[test]
fn test_extractors_implement_content_extractor() {
    use ut_html::{ContentExtractor, HtmlExtractor, CssExtractor};
    use ut_html::ExtractOptions;
    let html = b"<html><body><a href='/'>home</a></body></html>";
    let opts = ExtractOptions::default();
    let mut html_cursor = Cursor::new(html.as_slice());
    let _ = HtmlExtractor.extract_urls(&mut html_cursor, "", &opts).unwrap();
    let mut css_cursor = Cursor::new(b"body { background: url(/bg.png); }".as_slice());
    let _ = CssExtractor.extract_urls(&mut css_cursor, "", &opts).unwrap();
}

// ========== HttpRequest 序列化测试 ==========

#[test]
fn test_http_request_serialize_get() {
    use ut_core::types::HttpMethod;
    use ut_http::HttpRequest;
    let mut req = HttpRequest::new(HttpMethod::Get, "/path".into(), "example.com".into());
    req.header("Host", "example.com");
    req.header("Accept", "*/*");
    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("GET /path HTTP/1.1\r\n"));
    assert!(text.contains("Host: example.com\r\n"));
    assert!(text.ends_with("\r\n\r\n"));
}

#[test]
fn test_http_request_serialize_post_with_body() {
    use ut_core::types::HttpMethod;
    use ut_http::HttpRequest;
    let mut req = HttpRequest::new(HttpMethod::Post, "/api".into(), "example.com".into());
    req.header("Content-Type", "application/json");
    req.body = Some(b"{}".to_vec());
    req.header("Content-Length", "2");
    let bytes = req.serialize().unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("POST /api HTTP/1.1\r\n"));
    assert!(text.ends_with("\r\n\r\n{}"));
}

#[test]
fn test_http_request_header_case_insensitive() {
    use ut_core::types::HttpMethod;
    use ut_http::HttpRequest;
    let mut req = HttpRequest::new(HttpMethod::Get, "/".into(), "host".into());
    req.header("X-Custom", "value");
    assert_eq!(req.get_header("x-custom"), Some("value"));
    req.remove_header("X-Custom");
    assert_eq!(req.get_header("x-custom"), None);
}

// ========== HttpResponse 解析测试 ==========

#[test]
fn test_http_response_parse_head() {
    use ut_http::response::parse_response_head;
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello";
    let resp = parse_response_head(raw).unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.headers.get("Content-Type"), Some("text/html"));
    assert_eq!(resp.headers.content_length(), Some(5));
}

#[test]
fn test_http_response_classification() {
    use ut_http::HttpResponse;
    assert!(HttpResponse::new("HTTP/1.1".into(), 200, "OK".into()).is_success());
    assert!(HttpResponse::new("HTTP/1.1".into(), 301, "Moved".into()).is_redirect());
    assert!(HttpResponse::new("HTTP/1.1".into(), 404, "Not Found".into()).is_client_error());
    assert!(HttpResponse::new("HTTP/1.1".into(), 500, "Error".into()).is_server_error());
    assert!(HttpResponse::new("HTTP/1.1".into(), 304, "Not Modified".into()).not_modified());
}

// ========== HeaderMap 测试 ==========

#[test]
fn test_header_map_basic_operations() {
    use ut_http::HeaderMap;
    let mut hm = HeaderMap::new();
    hm.insert("Content-Type", "text/html");
    hm.insert("Content-Length", "42");
    assert_eq!(hm.get("content-type"), Some("text/html"));
    assert!(hm.contains("CONTENT-LENGTH"));
    assert_eq!(hm.content_length(), Some(42));
    hm.remove("Content-Length");
    assert_eq!(hm.content_length(), None);
}

#[test]
fn test_header_map_set_cookies_multiple() {
    use ut_http::HeaderMap;
    let mut hm = HeaderMap::new();
    hm.insert("Set-Cookie", "a=1");
    hm.insert("Set-Cookie", "b=2");
    let all = hm.set_cookies();
    assert_eq!(all.len(), 2);
}

#[test]
fn test_header_map_is_chunked() {
    use ut_http::HeaderMap;
    let mut hm = HeaderMap::new();
    hm.insert("Transfer-Encoding", "chunked");
    assert!(hm.is_chunked());
}

// ========== BasicAuthenticator 测试 ==========

#[test]
fn test_basic_auth_encode() {
    use ut_http::auth::basic::BasicAuthenticator;
    use ut_http::auth::{Authenticator, AuthChallenge, AuthScheme};
    use ut_core::types::Credentials;
    let mut auth = BasicAuthenticator;
    let challenge = AuthChallenge {
        scheme: AuthScheme::Basic,
        realm: None, nonce: None, opaque: None, qop: None,
        algorithm: None, charset: None, userhash: None,
        stale: None, domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "alice".into(), password: "secret".into() };
    let result = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    let header = result.unwrap();
    assert!(header.starts_with("Basic "));
}

#[test]
fn test_basic_auth_supports_preemptive() {
    use ut_http::auth::basic::BasicAuthenticator;
    use ut_http::auth::Authenticator;
    let auth = BasicAuthenticator;
    assert!(auth.supports_preemptive());
}

// ========== DigestAuthenticator 测试 ==========

#[test]
fn test_digest_auth_md5_known_vector() {
    use ut_http::auth::digest::DigestAuthenticator;
    use ut_http::auth::{Authenticator, AuthChallenge, AuthScheme};
    use ut_core::types::Credentials;
    let mut auth = DigestAuthenticator::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Digest,
        realm: Some("testrealm@host.com".into()),
        nonce: Some("dcd98b7102dd2f0e8b11d0f600bfb0c093".into()),
        opaque: Some("5ccc069c403ebaf9f0171e9517a40e".into()),
        qop: Some("auth".into()),
        algorithm: Some("MD5".into()),
        charset: None, userhash: None, stale: None,
        domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "Mufasa".into(), password: "Circle Of Life".into() };
    let result = auth.authenticate(&challenge, &creds, "GET", "/dir/index.html", None).unwrap();
    assert!(result.is_some());
    let header = result.unwrap();
    assert!(header.starts_with("Digest "));
    assert!(header.contains("username=\"Mufasa\""));
    assert!(header.contains("response=\""));
}
