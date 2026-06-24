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
