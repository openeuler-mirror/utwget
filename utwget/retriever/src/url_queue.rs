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

impl UrlQueue {
    /// Create a new URL queue with optional maximum depth.
    ///
    /// # Arguments
    ///
    /// * `max_depth` - Maximum recursion depth, or `None` for unlimited.
    ///
    /// # Returns
    ///
    /// A new `UrlQueue` instance.
    pub fn new(max_depth: Option<u32>) -> Self {
        UrlQueue {
            queue: VecDeque::new(),
            blacklist: HashSet::new(),
            max_depth,
        }
    }

    /// Add a URL entry to the queue.
    ///
    /// The URL is not added if:
    /// - It exceeds the maximum depth limit.
    /// - It has already been queued or processed (checked by normalized URL).
    ///
    /// # Arguments
    ///
    /// * `entry` - The queue entry to add.
    pub fn push(&mut self, entry: QueueEntry) {
        if self.max_depth.map_or(false, |md| entry.depth > md) {
            return;
        }
        let normalized = normalize(&entry.url);
        if self.blacklist.contains(&normalized) {
            return;
        }
        self.blacklist.insert(normalized);
        self.queue.push_back(entry);
    }

    /// Remove and return the next URL entry from the queue.
    ///
    /// # Returns
    ///
    /// `Some(QueueEntry)` if the queue is non-empty, `None` otherwise.
    pub fn pop(&mut self) -> Option<QueueEntry> {
        self.queue.pop_front()
    }

    /// Check if a URL has been visited.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to check.
    ///
    /// # Returns
    ///
    /// `true` if the URL has been queued or processed, `false` otherwise.
    pub fn is_visited(&self, url: &str) -> bool {
        self.blacklist.contains(&normalize(url))
    }

    /// Mark a URL as visited without adding it to the queue.
    ///
    /// This is useful for URLs that should be excluded from processing
    /// but still counted as visited.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to mark as visited.
    pub fn mark_visited(&mut self, url: &str) {
        self.blacklist.insert(normalize(url));
    }

    /// Get the number of URLs waiting in the queue.
    ///
    /// # Returns
    ///
    /// The number of pending queue entries.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if the queue is empty.
    ///
    /// # Returns
    ///
    /// `true` if no URLs are waiting, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Clear the queue and visited set.
    ///
    /// Removes all pending entries and forgets all visited URLs.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.blacklist.clear();
    }

    /// Get the total number of URLs that have been visited.
    ///
    /// This includes both queued and processed URLs.
    ///
    /// # Returns
    ///
    /// The size of the visited set.
    pub fn visited_count(&self) -> usize {
        self.blacklist.len()
    }
}
