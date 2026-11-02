//! Unit tests for robots.txt parsing.

use ut_core::robots::RobotParser;

// ============================================================================
// Basic Parsing Tests
// ============================================================================

#[test]
fn test_robots_new() {
    let parser = RobotParser::new("wget");
    // Parser should be created without error
    let _ = parser;
}

#[test]
fn test_parse_empty() {
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", "");

    // Empty robots.txt should allow everything
    assert_eq!(parser.is_allowed("example.com", "http://example.com/any/path"), Some(true));
}

#[test]
fn test_parse_allow_all() {
    let content = "User-agent: *\nDisallow:";
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    assert_eq!(parser.is_allowed("example.com", "http://example.com/path"), Some(true));
}

#[test]
fn test_parse_disallow_all() {
    let content = "User-agent: *\nDisallow: /";
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    assert_eq!(parser.is_allowed("example.com", "http://example.com/path"), Some(false));
}

#[test]
fn test_parse_disallow_specific_path() {
    let content = r#"
User-agent: *
Disallow: /admin/
Disallow: /private/
"#;
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    // Public paths should be allowed
    assert_eq!(parser.is_allowed("example.com", "http://example.com/public/file"), Some(true));

    // Disallowed paths should be blocked
    assert_eq!(parser.is_allowed("example.com", "http://example.com/admin/secret"), Some(false));
    assert_eq!(parser.is_allowed("example.com", "http://example.com/private/data"), Some(false));
}

// ============================================================================
// User-Agent Matching Tests
// ============================================================================

#[test]
fn test_user_agent_wildcard() {
    let content = r#"
User-agent: *
Disallow: /global/
"#;
    let mut parser = RobotParser::new("mybot");
    parser.load("example.com", content);

    assert_eq!(parser.is_allowed("example.com", "http://example.com/global/file"), Some(false));
}

#[test]
fn test_user_agent_specific() {
    let content = r#"
User-agent: googlebot
Disallow: /search/

User-agent: *
Disallow: /admin/
"#;
    let mut parser = RobotParser::new("googlebot");
    parser.load("example.com", content);

    // googlebot-specific rule should apply
    assert_eq!(parser.is_allowed("example.com", "http://example.com/search/"), Some(false));
    // Admin is not in googlebot's rules, so allowed
    assert_eq!(parser.is_allowed("example.com", "http://example.com/admin/"), Some(true));
}

#[test]
fn test_user_agent_case_insensitive() {
    let content = r#"
User-agent: GoogleBot
Disallow: /search/
"#;
    let mut parser = RobotParser::new("googlebot");
    parser.load("example.com", content);

    assert_eq!(parser.is_allowed("example.com", "http://example.com/search/"), Some(false));
}

#[test]
fn test_user_agent_not_matching() {
    let content = r#"
User-agent: googlebot
Disallow: /
"#;
    let mut parser = RobotParser::new("mybot");
    parser.load("example.com", content);

    // Rules for googlebot should not apply to mybot
    // Since there's no matching user-agent, everything is allowed
    assert_eq!(parser.is_allowed("example.com", "http://example.com/path"), Some(true));
}

// ============================================================================
// Allow Directive Tests
// ============================================================================

#[test]
fn test_allow_override_disallow() {
    let content = r#"
User-agent: *
Disallow: /tmp/
Allow: /tmp/public/
"#;
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    // Disallowed path
    assert_eq!(parser.is_allowed("example.com", "http://example.com/tmp/secret"), Some(false));
    // Allowed exception
    assert_eq!(parser.is_allowed("example.com", "http://example.com/tmp/public/file"), Some(true));
}

#[test]
fn test_allow_specific() {
    let content = r#"
User-agent: *
Disallow: /
Allow: /public/
"#;
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    assert_eq!(parser.is_allowed("example.com", "http://example.com/private/file"), Some(false));
    assert_eq!(parser.is_allowed("example.com", "http://example.com/public/file"), Some(true));
}

// ============================================================================
// Path Matching Tests
// ============================================================================

#[test]
fn test_path_exact_match() {
    let content = r#"
User-agent: *
Disallow: /admin
"#;
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    // Exact match
    assert_eq!(parser.is_allowed("example.com", "http://example.com/admin"), Some(false));
    // Prefix match (path starts with /admin)
    assert_eq!(parser.is_allowed("example.com", "http://example.com/admin/page"), Some(false));
}

#[test]
fn test_path_with_trailing_slash() {
    let content = r#"
User-agent: *
Disallow: /admin/
"#;
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    // /admin without trailing slash is allowed
    assert_eq!(parser.is_allowed("example.com", "http://example.com/admin"), Some(true));
    // /admin/ and subpaths are disallowed
    assert_eq!(parser.is_allowed("example.com", "http://example.com/admin/"), Some(false));
    assert_eq!(parser.is_allowed("example.com", "http://example.com/admin/page"), Some(false));
}

#[test]
fn test_path_with_query() {
    let content = r#"
User-agent: *
Disallow: /search
"#;
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    // Query string should not affect matching
    assert_eq!(parser.is_allowed("example.com", "http://example.com/search?q=test"), Some(false));
}

#[test]
fn test_path_wildcard() {
    let content = r#"
User-agent: *
Disallow: *
"#;
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    // Wildcard should disallow everything
    assert_eq!(parser.is_allowed("example.com", "http://example.com/any/path"), Some(false));
}

// ============================================================================
// Crawl Delay Tests
// ============================================================================

#[test]
fn test_crawl_delay() {
    let content = r#"
User-agent: *
Crawl-delay: 5
"#;
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    assert_eq!(parser.crawl_delay("example.com"), Some(5.0));
}

#[test]
fn test_crawl_delay_specific_agent() {
    let content = r#"
User-agent: googlebot
Crawl-delay: 10

User-agent: *
Crawl-delay: 5
"#;
    let mut parser = RobotParser::new("googlebot");
    parser.load("example.com", content);

    assert_eq!(parser.crawl_delay("example.com"), Some(10.0));
}

#[test]
fn test_crawl_delay_not_set() {
    let content = "User-agent: *\nDisallow:";
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    assert_eq!(parser.crawl_delay("example.com"), None);
}

// ============================================================================
// Sitemap Tests
// ============================================================================

#[test]
fn test_sitemap() {
    let content = r#"
User-agent: *
Sitemap: https://example.com/sitemap.xml
"#;
    let mut parser = RobotParser::new("wget");
    parser.load("example.com", content);

    let sitemaps = parser.sitemaps("example.com");
    assert_eq!(sitemaps.len(), 1);
    assert_eq!(sitemaps[0], "https://example.com/sitemap.xml");
}
