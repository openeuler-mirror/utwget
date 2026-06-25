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
