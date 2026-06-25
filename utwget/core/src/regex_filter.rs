//! URL filtering for recursive downloads.
//!
//! This module provides various URL filters for controlling which URLs
//! are followed during recursive downloads, including pattern matching,
//! domain restrictions, and scheme filtering.

use crate::types::Scheme;
use crate::url::ParsedUrl;
use regex::Regex;
use std::collections::HashSet;

/// Trait for URL filtering.
///
/// Implementations determine whether a URL should be accepted
/// during recursive downloads.
pub trait UrlFilter: Send + Sync {
    /// Checks if a URL should be accepted.
    ///
    /// # Arguments
    ///
    /// * `url` - The full URL to check.
    /// * `filename` - The filename portion of the URL.
    ///
    /// # Returns
    ///
    /// `true` if the URL should be accepted, `false` to reject it.
    fn is_accepted(&self, url: &str, filename: &str) -> bool;
}

/// A composite filter that combines multiple filters.
///
/// A URL is accepted only if all contained filters accept it.
pub struct CompositeFilter {
    /// The filters to apply.
    filters: Vec<Box<dyn UrlFilter>>,
}

impl CompositeFilter {
    /// Creates a new empty composite filter.
    ///
    /// # Returns
    ///
    /// A new `CompositeFilter` with no filters.
    pub fn new() -> Self {
        CompositeFilter {
            filters: Vec::new(),
        }
    }

    /// Adds a filter to the composite.
    ///
    /// # Arguments
    ///
    /// * `filter` - The filter to add.
    pub fn add<F: UrlFilter + 'static>(&mut self, filter: F) {
        self.filters.push(Box::new(filter));
    }
}

impl UrlFilter for CompositeFilter {
    fn is_accepted(&self, url: &str, filename: &str) -> bool {
        self.filters.iter().all(|f| f.is_accepted(url, filename))
    }
}

impl Default for CompositeFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Accept filter using glob patterns.
///
/// URLs are accepted if their filename matches any of the patterns.
pub struct PatternAcceptFilter {
    /// Glob patterns to match.
    patterns: Vec<String>,
}

impl PatternAcceptFilter {
    /// Creates a new pattern accept filter.
    ///
    /// # Arguments
    ///
    /// * `patterns` - Glob patterns to accept (e.g., "*.html").
    pub fn new(patterns: Vec<String>) -> Self {
        PatternAcceptFilter { patterns }
    }
}

impl UrlFilter for PatternAcceptFilter {
    fn is_accepted(&self, _url: &str, filename: &str) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        self.patterns.iter().any(|p| match_glob(filename, p))
    }
}

/// Reject filter using glob patterns.
///
/// URLs are rejected if their filename matches any of the patterns.
pub struct PatternRejectFilter {
    /// Glob patterns to reject.
    patterns: Vec<String>,
}

impl PatternRejectFilter {
    /// Creates a new pattern reject filter.
    ///
    /// # Arguments
    ///
    /// * `patterns` - Glob patterns to reject (e.g., "*.jpg").
    pub fn new(patterns: Vec<String>) -> Self {
        PatternRejectFilter { patterns }
    }
}

impl UrlFilter for PatternRejectFilter {
    fn is_accepted(&self, _url: &str, filename: &str) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        !self.patterns.iter().any(|p| match_glob(filename, p))
    }
}

/// Accept filter using regular expressions.
///
/// URLs are accepted if their filename matches the regex pattern.
pub struct RegexAcceptFilter {
    /// The compiled regex pattern.
    regex: Option<Regex>,
}

impl RegexAcceptFilter {
    /// Creates a new regex accept filter.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The regex pattern to match.
    ///
    /// # Returns
    ///
    /// `Ok(RegexAcceptFilter)` if the pattern compiles, or a regex error.
    ///
    /// # Errors
    ///
    /// Returns an error if the regex pattern is invalid.
    pub fn new(pattern: &str) -> std::result::Result<Self, regex::Error> {
        Ok(RegexAcceptFilter {
            regex: Some(Regex::new(pattern)?),
        })
    }
}

impl UrlFilter for RegexAcceptFilter {
    fn is_accepted(&self, _url: &str, filename: &str) -> bool {
        match &self.regex {
            Some(re) => re.is_match(filename),
            None => true,
        }
    }
}

/// Reject filter using regular expressions.
///
/// URLs are rejected if their filename matches the regex pattern.
pub struct RegexRejectFilter {
    /// The compiled regex pattern.
    regex: Option<Regex>,
}

impl RegexRejectFilter {
    /// Creates a new regex reject filter.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The regex pattern to match.
    ///
    /// # Returns
    ///
    /// `Ok(RegexRejectFilter)` if the pattern compiles, or a regex error.
    ///
    /// # Errors
    ///
    /// Returns an error if the regex pattern is invalid.
    pub fn new(pattern: &str) -> std::result::Result<Self, regex::Error> {
        Ok(RegexRejectFilter {
            regex: Some(Regex::new(pattern)?),
        })
    }
}

impl UrlFilter for RegexRejectFilter {
    fn is_accepted(&self, _url: &str, filename: &str) -> bool {
        match &self.regex {
            Some(re) => !re.is_match(filename),
            None => true,
        }
    }
}

/// Domain restriction filter.
///
/// URLs are accepted only if their host is in the allowed domains list
/// and not in the excluded domains list.
pub struct DomainFilter {
    /// Allowed domains.
    domains: Vec<String>,
    /// Excluded domains.
    exclude: Vec<String>,
}

impl DomainFilter {
    /// Creates a new domain filter.
    ///
    /// # Arguments
    ///
    /// * `domains` - Domains to allow (empty means all allowed).
    /// * `exclude` - Domains to exclude.
    pub fn new(domains: Vec<String>, exclude: Vec<String>) -> Self {
        DomainFilter { domains, exclude }
    }
}

impl UrlFilter for DomainFilter {
    fn is_accepted(&self, url: &str, _filename: &str) -> bool {
        let host = match url_to_host(url) {
            Some(h) => h,
            None => return true,
        };
        if self.domains.is_empty() {
            return true;
        }
        let host_lc = host.to_ascii_lowercase();
        let accepted = self.domains.iter().any(|d| {
            let d_lc = d.to_ascii_lowercase();
            host_lc == d_lc
                || host_lc.ends_with(&format!(".{}", d_lc))
                || d_lc.starts_with('.') && host_lc.ends_with(&d_lc)
        });
        if !accepted {
            return false;
        }
        !self.exclude.iter().any(|d| {
            let d_lc = d.to_ascii_lowercase();
            host_lc == d_lc
                || host_lc.ends_with(&format!(".{}", d_lc))
                || d_lc.starts_with('.') && host_lc.ends_with(&d_lc)
        })
    }
}

/// Parent directory filter.
///
/// When `no_parent` is enabled, URLs are rejected if they would
/// ascend above the starting URL's directory.
pub struct ParentFilter {
    /// Whether to reject parent directories.
    no_parent: bool,
    /// The starting URL for comparison.
    start_url: Option<ParsedUrl>,
}

impl ParentFilter {
    /// Creates a new parent filter.
    ///
    /// # Arguments
    ///
    /// * `no_parent` - Whether to reject parent directories.
    /// * `start_url` - The starting URL for comparison.
    pub fn new(no_parent: bool, start_url: &str) -> Self {
        ParentFilter {
            no_parent,
            start_url: ParsedUrl::parse(start_url).ok(),
        }
    }
}

impl UrlFilter for ParentFilter {
    fn is_accepted(&self, url: &str, _filename: &str) -> bool {
        if !self.no_parent {
            return true;
        }
        let start = match &self.start_url {
            Some(u) => u,
            None => return true,
        };
        let target = match ParsedUrl::parse(url) {
            Ok(u) => u,
            Err(_) => return true,
        };
        if target.host.to_ascii_lowercase() != start.host.to_ascii_lowercase() {
            return true;
        }
        let target_dir = target.dir.trim_end_matches('/');
        let start_dir = start.dir.trim_end_matches('/');
        if start_dir.is_empty() {
            return true;
        }
        target_dir.starts_with(start_dir)
    }
}

/// Robots.txt filter placeholder.
///
/// This filter is a placeholder; actual robots.txt checking
/// is handled by the robots module.
pub struct RobotsFilter {
    /// Whether to respect robots.txt.
    use_robots: bool,
}

impl RobotsFilter {
    /// Creates a new robots filter.
    ///
    /// # Arguments
    ///
    /// * `use_robots` - Whether to respect robots.txt.
    pub fn new(use_robots: bool) -> Self {
        RobotsFilter { use_robots }
    }
}

impl UrlFilter for RobotsFilter {
    fn is_accepted(&self, _url: &str, _filename: &str) -> bool {
        !self.use_robots
    }
}

/// Span hosts filter.
///
/// When `span` is disabled, URLs are rejected if they point to
/// a different host than the starting host.
pub struct SpanHostFilter {
    /// Whether to allow spanning to other hosts.
    span: bool,
    /// The starting host.
    start_host: String,
}
