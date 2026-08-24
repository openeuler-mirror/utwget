//! URL queue for recursive downloads.
//!
//! This module provides a breadth-first queue for URLs to be downloaded
//! during recursive retrieval. It tracks visited URLs to prevent duplicates
//! and enforces maximum depth limits.

use std::collections::{HashSet, VecDeque};

/// Entry in the URL queue representing a URL to be downloaded.
#[derive(Debug, Clone)]
pub struct QueueEntry {
    /// The URL to download.
    pub url: String,
    /// The referer URL where this link was found.
    pub referer: Option<String>,
    /// Recursion depth (0 for starting URL).
    pub depth: u32,
    /// Whether the URL is expected to be HTML content.
    pub expect_html: bool,
    /// Whether the URL is expected to be CSS content.
    pub expect_css: bool,
}
