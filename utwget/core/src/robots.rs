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

/// The complete set of parsed directives from a robots.txt file.
#[derive(Debug, Clone)]
pub struct RobotSpecs {
    /// The groups (User-agent blocks) parsed from the file.
    pub groups: Vec<RobotGroup>,
}

/// Parses robots.txt content and caches the results per host.
///
/// Supports the following directives:
/// - `User-agent`
/// - `Disallow`
/// - `Allow`
/// - `Crawl-delay`
/// - `Sitemap`
#[derive(Debug, Clone, Default)]
pub struct RobotParser {
    /// Cache mapping hostnames (lowercased) to their parsed `RobotSpecs`.
    specs_cache: HashMap<String, RobotSpecs>,
    /// The user agent string used when matching agent-specific groups.
    user_agent: String,
}

impl RobotParser {
    /// Creates a new `RobotParser` with the given user agent string.
    pub fn new(user_agent: &str) -> Self {
        RobotParser {
            specs_cache: HashMap::new(),
            user_agent: user_agent.to_string(),
        }
    }

    /// Sets the user agent string used for matching agent-specific groups.
    pub fn set_user_agent(&mut self, agent: &str) {
        self.user_agent = agent.to_string();
    }

    /// Parses the raw text of a robots.txt file into a `RobotSpecs`.
    ///
    /// Lines starting with `#` are treated as comments and ignored. If no
    /// `User-agent` directives are found, a single catch-all group (`*`) with
    /// no rules is returned.
    ///
    /// # Arguments
    /// * `content` - The raw text content of a robots.txt file
    ///
    /// # Returns
    /// A `RobotSpecs` containing all parsed groups and their rules.
    pub fn parse(&mut self, content: &str) -> RobotSpecs {
        let mut groups: Vec<RobotGroup> = Vec::new();
        let mut current_group: Option<RobotGroup> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (directive, value) = match line.split_once(':') {
                Some(pair) => (pair.0.trim(), pair.1.trim()),
                None => continue,
            };

            let directive_lc = directive.to_ascii_lowercase();

            match directive_lc.as_str() {
                "user-agent" => {
                    if let Some(group) = current_group.take() {
                        groups.push(group);
                    }
                    current_group = Some(RobotGroup {
                        user_agents: vec![value.to_string()],
                        rules: Vec::new(),
                        crawl_delay: None,
                        sitemaps: Vec::new(),
                    });
                }
                "disallow" => {
                    if let Some(ref mut group) = current_group {
                        let path = if value.is_empty() {
                            String::new()
                        } else {
                            value.to_string()
                        };
                        group.rules.push(RobotRule { path, allow: false });
                    }
                }
                "allow" => {
                    if let Some(ref mut group) = current_group {
                        group.rules.push(RobotRule {
                            path: value.to_string(),
                            allow: true,
                        });
                    }
                }
                "crawl-delay" => {
                    if let Some(ref mut group) = current_group {
                        if let Ok(delay) = value.parse::<f64>() {
                            group.crawl_delay = Some(delay);
                        }
                    }
                }
                "sitemap" => {
                    if let Some(ref mut group) = current_group {
                        group.sitemaps.push(value.to_string());
                    }
                }
                _ => {}
            }
        }

        if let Some(group) = current_group {
            groups.push(group);
        }

        if groups.is_empty() {
            groups.push(RobotGroup {
                user_agents: vec!["*".to_string()],
                rules: Vec::new(),
                crawl_delay: None,
                sitemaps: Vec::new(),
            });
        }

        RobotSpecs { groups }
    }

    /// Parses the robots.txt content for the given host and caches the result.
    ///
    /// # Arguments
    /// * `host` - The hostname to associate the parsed rules with
    /// * `content` - The raw text content of the host's robots.txt file
    pub fn load(&mut self, host: &str, content: &str) {
        let specs = self.parse(content);
        self.specs_cache.insert(host.to_ascii_lowercase(), specs);
    }

    /// Returns whether the given URL is allowed for the specified host according to
    /// the cached robots.txt rules.
    ///
    /// When more than one rule matches the path, the rule with the longest matching
    /// path takes precedence (most-specific-rule wins). If no cache entry exists for
    /// the host, `None` is returned. If no rules match, access is allowed (`Some(true)`).
    ///
    /// # Arguments
    /// * `host` - The hostname to look up
    /// * `url` - The URL whose path should be checked
    ///
    /// # Returns
    /// * `Some(true)` if the URL is allowed
    /// * `Some(false)` if the URL is disallowed
    /// * `None` if no cached rules exist for the host
    pub fn is_allowed(&self, host: &str, url: &str) -> Option<bool> {
        let host_lc = host.to_ascii_lowercase();
        let specs = self.specs_cache.get(&host_lc)?;

        let parsed = ParsedUrl::parse(url).ok()?;
        let path = &parsed.path;

        let mut best_group: Option<&RobotGroup> = None;
        let mut best_specificity: i32 = -1;

        for group in &specs.groups {
            for agent in &group.user_agents {
                let agent_match = agent == "*" || self.user_agent.eq_ignore_ascii_case(agent);
                let specificity = if agent == "*" {
                    0
                } else if self.user_agent.eq_ignore_ascii_case(agent) {
                    1
                } else {
                    -1
                };

                if agent_match && specificity > best_specificity {
                    best_group = Some(group);
                    best_specificity = specificity;
                }
            }
        }

        let group = match best_group {
            Some(g) => g,
            None => return Some(true),
        };

        let mut longest_match: Option<&RobotRule> = None;
        let mut longest_len = 0usize;

        for rule in &group.rules {
            if path_matches_rule(path, &rule.path) {
                if rule.path.len() > longest_len {
                    longest_len = rule.path.len();
                    longest_match = Some(rule);
                }
            }
        }

        match longest_match {
            Some(rule) => Some(rule.allow),
            None => Some(true),
        }
    }

    /// Returns the crawl delay for the specified host, if one is defined in the
    /// cached robots.txt content.
    ///
    /// The most specific user-agent match (exact match over wildcard) takes precedence.
    ///
    /// # Arguments
    /// * `host` - The hostname to look up
    ///
    /// # Returns
    /// The crawl delay in seconds, or `None` if not specified or not cached.
    pub fn crawl_delay(&self, host: &str) -> Option<f64> {
        let host_lc = host.to_ascii_lowercase();
        let specs = self.specs_cache.get(&host_lc)?;

        let mut best_group: Option<&RobotGroup> = None;
        let mut best_specificity: i32 = -1;

        for group in &specs.groups {
            for agent in &group.user_agents {
                let specificity = if agent == "*" {
                    0
                } else if self.user_agent.eq_ignore_ascii_case(agent) {
                    1
                } else {
                    -1
                };
                if specificity > best_specificity {
                    best_group = Some(group);
                    best_specificity = specificity;
                }
            }
        }

        best_group.and_then(|g| g.crawl_delay)
    }

    /// Returns all sitemap URLs declared in the cached robots.txt content for the
    /// specified host, without duplicates.
    ///
    /// # Arguments
    /// * `host` - The hostname to look up
    ///
    /// # Returns
    /// A vector of sitemap URL strings (empty if none are declared or not cached).
    pub fn sitemaps(&self, host: &str) -> Vec<String> {
        let host_lc = host.to_ascii_lowercase();
        let mut result = Vec::new();
        if let Some(specs) = self.specs_cache.get(&host_lc) {
            for group in &specs.groups {
                for sitemap in &group.sitemaps {
                    if !result.contains(sitemap) {
                        result.push(sitemap.clone());
                    }
                }
            }
        }
        result
    }
}
