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

/// Queue of URLs to be downloaded with deduplication and depth limiting.
///
/// The `UrlQueue` maintains a FIFO queue of URLs to download and a set
/// of already-visited URLs to prevent duplicate downloads. URLs are
/// normalized by removing fragment identifiers before comparison.
///
/// # Example
///
/// ```
/// use ut_retriever::url_queue::{UrlQueue, QueueEntry};
///
/// let mut queue = UrlQueue::new(Some(3));
/// queue.push(QueueEntry {
///     url: "http://example.com/".to_string(),
///     referer: None,
///     depth: 0,
///     expect_html: true,
///     expect_css: false,
/// });
///
/// while let Some(entry) = queue.pop() {
///     // Process entry
/// }
/// ```
#[derive(Debug)]
pub struct UrlQueue {
    /// FIFO queue of URLs waiting to be processed.
    queue: VecDeque<QueueEntry>,
    /// Set of normalized URLs that have been queued or processed.
    blacklist: HashSet<String>,
    /// Maximum recursion depth, if configured.
    max_depth: Option<u32>,
}
