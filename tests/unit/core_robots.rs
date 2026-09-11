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
