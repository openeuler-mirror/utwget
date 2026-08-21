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

impl Spider {
    /// Create a new spider with the given configuration.
    ///
    /// The configuration is automatically modified to enable spider mode
    /// and recursive operation.
    ///
    /// # Arguments
    ///
    /// * `config` - Shared configuration reference.
    /// * `progress` - Progress display for reporting status.
    ///
    /// # Returns
    ///
    /// A new `Spider` instance configured for link checking.
    pub fn new(config: Arc<Config>, progress: Box<dyn ProgressDisplay>) -> Self {
        let mut spider_config = (*config).clone();
        spider_config.recursive.spider = true;
        spider_config.recursive.enabled = true;
        let inner = RecursiveRetriever::new(Arc::new(spider_config), progress);
        Spider {
            inner,
            broken_links: Vec::new(),
            total_checked: 0,
            successful: 0,
            redirected: 0,
        }
    }

    /// Spider a URL and return the results.
    ///
    /// Performs spider mode retrieval starting from the given URL,
    /// checking all linked URLs without downloading content.
    ///
    /// # Arguments
    ///
    /// * `url` - The starting URL to spider.
    ///
    /// # Returns
    ///
    /// - `Ok(SpiderResult)` containing statistics and broken links.
    /// - `Err(RetrieveError)` if a critical error occurred.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if the spider operation fails critically.
    pub fn spider(&mut self, url: &str) -> Result<SpiderResult, crate::RetrieveError> {
        info!("spidering: {}", url);

        match self.inner.retrieve_tree(url) {
            Ok(ExitStatus::Success) | Ok(ExitStatus::NoUrlsFound) | Ok(ExitStatus::Error) => {}
            Err(e) => return Err(e),
        }

        let _registry = self.inner.retriever().download_registry();
        let _queue = self.inner.retriever().download_registry();

        let result = SpiderResult {
            broken_links: self.broken_links.clone(),
            total_checked: self.total_checked,
            successful: self.successful,
            redirected: self.redirected,
        };

        Ok(result)
    }

    /// Spider a URL and print a report of broken links.
    ///
    /// This is a convenience method that calls `spider()` and then
    /// prints the broken links report to the log.
    ///
    /// # Arguments
    ///
    /// * `url` - The starting URL to spider.
    ///
    /// # Returns
    ///
    /// - `Ok(SpiderResult)` containing statistics and broken links.
    /// - `Err(RetrieveError)` if a critical error occurred.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if the spider operation fails critically.
    pub fn spider_and_report(&mut self, url: &str) -> Result<SpiderResult, crate::RetrieveError> {
        let result = self.spider(url)?;
        self.print_broken_links();
        Ok(result)
    }

    /// Record a successful URL check.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL that was checked successfully.
    /// * `referer` - Optional referer URL where this link was found.
    pub fn record_success(&mut self, url: &str, referer: Option<&str>) {
        self.total_checked += 1;
        self.successful += 1;
        debug!("spider OK: {} (referer: {:?})", url, referer);
    }

    /// Record a URL redirect.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL that redirected.
    /// * `target` - The redirect target URL.
    pub fn record_redirect(&mut self, url: &str, target: &str) {
        self.total_checked += 1;
        self.redirected += 1;
        debug!("spider redirect: {} -> {}", url, target);
    }

    /// Record a broken link.
    ///
    /// # Arguments
    ///
    /// * `url` - The broken URL.
    /// * `referer` - The page containing the broken link.
    /// * `error` - The error message describing the failure.
    pub fn record_broken(&mut self, url: &str, referer: &str, error: &str) {
        self.total_checked += 1;
        self.broken_links.push((url.to_string(), referer.to_string(), error.to_string()));
        warn!("broken link: {} (from {}, error: {})", url, referer, error);
    }

    /// Print a summary of broken links to the log.
    ///
    /// Outputs the total number of links checked and lists any broken
    /// links found during the spider operation.
    pub fn print_broken_links(&self) {
        if self.broken_links.is_empty() {
            info!("spider finished: {} links checked, no broken links found", self.total_checked);
            return;
        }

        info!("spider finished: {} links checked, {} broken", self.total_checked, self.broken_links.len());
        info!("broken links:");
        for (url, referer, error) in &self.broken_links {
            info!("  {} (from {}) - {}", url, referer, error);
        }
    }

    /// Get a reference to the inner recursive retriever.
    ///
    /// # Returns
    ///
    /// A reference to the `RecursiveRetriever` used for spidering.
    pub fn inner(&self) -> &RecursiveRetriever {
        &self.inner
    }

    /// Get a mutable reference to the inner recursive retriever.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `RecursiveRetriever` used for spidering.
    pub fn inner_mut(&mut self) -> &mut RecursiveRetriever {
        &mut self.inner
    }
}
