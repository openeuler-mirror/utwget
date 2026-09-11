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
