//! URL queue for recursive downloads.
//!
//! This module provides a breadth-first queue for URLs to be downloaded
//! during recursive retrieval. It tracks visited URLs to prevent duplicates
//! and enforces maximum depth limits.

use std::collections::{HashSet, VecDeque};

/// Maximum number of URLs in the queue to prevent memory exhaustion from malicious pages.
const MAX_QUEUE_SIZE: usize = 10_000;

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
    /// Number of redirects followed to reach this URL. Bounded by
    /// `--max-redirect`: without it a server returning an unbounded chain
    /// of distinct (non-repeating) redirect URLs makes the recursive crawl
    /// never terminate (arch 6.3-4). Defaults to 0 for seed entries.
    pub redirect_count: u32,
    /// Whether this entry is an inline page requisite (`-p`): images,
    /// stylesheets, scripts. GNU wget fetches requisites of leaf pages
    /// even beyond the depth limit (recur.c dash_p_leaf_HTML), so the
    /// queue allows these entries to overstep `max_depth` by exactly one
    /// level. Defaults to false.
    pub inline_requisite: bool,
}

impl QueueEntry {
    /// Create a seed/child entry with zero redirects followed.
    pub fn new(url: String, referer: Option<String>, depth: u32) -> Self {
        QueueEntry {
            url,
            referer,
            depth,
            expect_html: false,
            expect_css: false,
            redirect_count: 0,
            inline_requisite: false,
        }
    }
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
    /// - It exceeds the maximum depth limit — except inline page
    ///   requisites (`-p`) exactly one level beyond, mirroring wget's
    ///   leaf-page requisite overstep (recur.c dash_p_leaf_HTML).
    /// - It has already been queued or processed (checked by normalized URL).
    ///
    /// # Arguments
    ///
    /// * `entry` - The queue entry to add.
    pub fn push(&mut self, entry: QueueEntry) {
        if let Some(md) = self.max_depth {
            let requisite_overstep = entry.inline_requisite && entry.depth == md.saturating_add(1);
            if entry.depth > md && !requisite_overstep {
                return;
            }
        }
        if self.queue.len() >= MAX_QUEUE_SIZE {
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

/// Normalize a URL for deduplication.
///
/// Removes leading/trailing whitespace and the fragment identifier
/// (everything from `#` onwards). URLs that differ only in their
/// fragment are considered equivalent for download purposes.
///
/// # Arguments
///
/// * `url` - The URL to normalize.
///
/// # Returns
///
/// The normalized URL string.
fn normalize(url: &str) -> String {
    let url = url.trim();
    if let Some(idx) = url.find('#') {
        url[..idx].to_string()
    } else {
        url.to_string()
    }
}
