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
