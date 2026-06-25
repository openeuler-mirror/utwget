use crate::url::ParsedUrl;
use std::collections::HashMap;

/// A single rule from a robots.txt file, specifying whether a path is allowed or disallowed.
#[derive(Debug, Clone)]
pub struct RobotRule {
    /// The path pattern this rule applies to.
    pub path: String,
    /// Whether the path is allowed (`true`) or disallowed (`false`).
    pub allow: bool,
}

/// A group of rules in a robots.txt file that apply to one or more user agents.
#[derive(Debug, Clone)]
pub struct RobotGroup {
    /// The list of user agents this group applies to.
    pub user_agents: Vec<String>,
    /// The ordered list of allow/disallow rules.
    pub rules: Vec<RobotRule>,
    /// The crawl delay (in seconds) required by this group, if any.
    pub crawl_delay: Option<f64>,
    /// Links to sitemaps declared in this group.
    pub sitemaps: Vec<String>,
}
