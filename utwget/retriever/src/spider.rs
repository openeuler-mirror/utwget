//! Spider mode implementation for link checking.
//!
//! This module provides the `Spider` struct for checking URLs without downloading
//! them. Spider mode is useful for:
//! - Finding broken links on a website
//! - Verifying URL accessibility
//! - Checking redirect chains

use std::sync::Arc;

use log::{debug, info, warn};
use ut_core::Config;
use ut_progress::ProgressDisplay;

use crate::recursive::{ExitStatus, RecursiveRetriever};

/// Result of a spider operation.
///
/// Contains statistics about checked URLs and any broken links found.
#[derive(Debug, Clone)]
pub struct SpiderResult {
    /// List of broken links as (URL, referer, error_message) tuples.
    pub broken_links: Vec<(String, String, String)>,
    /// Total number of URLs checked.
    pub total_checked: usize,
    /// Number of successful URL checks.
    pub successful: usize,
    /// Number of redirected URLs.
    pub redirected: usize,
}

/// Spider for checking URLs without downloading content.
///
/// The `Spider` uses the recursive retriever infrastructure but operates
/// in spider mode, which performs HEAD requests or range requests to
/// check URL validity without downloading the full content.
///
/// # Example
///
/// ```no_run
/// use ut_retriever::Spider;
/// use ut_core::Config;
/// use std::sync::Arc;
///
/// let config = Arc::new(Config::default());
/// let mut spider = Spider::new(config, progress);
/// let result = spider.spider_and_report("http://example.com/");
/// ```
pub struct Spider {
    /// Inner recursive retriever configured for spider mode.
    inner: RecursiveRetriever,
    /// List of broken links found during spidering.
    broken_links: Vec<(String, String, String)>,
    /// Total number of URLs checked.
    total_checked: usize,
    /// Number of successful checks.
    successful: usize,
    /// Number of redirects encountered.
    redirected: usize,
}
