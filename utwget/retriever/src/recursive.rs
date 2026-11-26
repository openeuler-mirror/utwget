//! Recursive download implementation.
//!
//! This module provides the `RecursiveRetriever` struct for downloading entire
//! website trees by following links in HTML and CSS files. It handles:
//! - Depth-limited recursion
//! - Host spanning control
//! - robots.txt compliance
//! - URL filtering (accept/reject patterns)
//! - Page requisites (images, stylesheets, etc.)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::io::Write;

use log::{debug, warn};
use ut_core::url::ParsedUrl;
use ut_core::{Config, RobotParser, Scheme, UrlFilter};
use ut_html::css_extractor::CssExtractor;
use ut_html::html_extractor::HtmlExtractor;
use ut_html::types::ContentExtractor;
use ut_html::url_position::{ExtractOptions, LinkType, UrlPosition};
use ut_progress::ProgressDisplay;

use crate::retriever::Retriever;
use crate::types::{content_type_is_css, content_type_is_html, RetrieveError, RetrieveOutcome};
use crate::download_registry::DownloadRegistry;
use crate::url_queue::{QueueEntry, UrlQueue};

/// Exit status for a recursive retrieval operation.
///
/// Distinct from `utwget_cli::app::RecursiveExitStatus` (the process-wide exit
/// code enum) to avoid the name collision flagged in the architecture
/// review (arch 6.3-6).
///
/// Indicates the overall result of a recursive download session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecursiveExitStatus {
    /// All downloads completed successfully.
    Success,
    /// One or more downloads encountered errors.
    Error,
    /// No URLs were found to download.
    NoUrlsFound,
}

/// RAII guard for the parallel-recursive `active_count` atomic: increments
/// on construction and decrements on drop, so EVERY exit path of the worker
/// loop body (quota break, visited/robots continue, retrieve error, normal
/// completion) reliably decrements the counter. A leak would keep
/// active_count > 0 forever, and all workers would then spin in the
/// queue-empty wait loop instead of exiting (process hang).
struct ActiveGuard<'a>(&'a AtomicUsize);

impl<'a> ActiveGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> ActiveGuard<'a> {
        counter.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(counter)
    }
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Test-only accessor exercising the private [`ActiveGuard`] from the
/// integration test suite (`tests/unit_tests/recursive_parallel.rs`).
/// Increments `counter` and returns a guard that decrements on drop.
#[doc(hidden)]
pub fn test_guard(counter: &AtomicUsize) -> impl Drop + '_ {
    ActiveGuard::new(counter)
}

/// Recursive downloader for retrieving entire website trees.
///
/// The `RecursiveRetriever` coordinates the download of a URL and all linked
/// resources, following links in HTML and CSS files up to a configurable depth.
/// It integrates with the URL queue, robots.txt parser, and URL filters.
///
/// # Features
///
/// - Depth-limited recursion (`-l` / `--level`)
/// - Host spanning control (`-H` / `--span-hosts`)
/// - robots.txt compliance (`--use-robots`)
/// - URL filtering (`-A` / `-R` accept/reject patterns)
/// - Page requisites (`-p` / `--page-requisites`)
/// - Spider mode (`--spider`)
///
/// # Example
///
/// ```no_run
/// use ut_retriever::RecursiveRetriever;
/// use ut_core::Config;
/// use std::sync::Arc;
///
/// let config = Arc::new(Config::default());
/// let progress = ut_progress::create_progress_display(ut_core::ProgressStyle::Silent, true);
/// let mut retriever = RecursiveRetriever::new(config, progress);
/// let result = retriever.retrieve_tree("http://example.com/");
/// ```
pub struct RecursiveRetriever {
    /// Core retriever for individual downloads.
    retriever: Retriever,
    /// HTML link extractor.
    html_extractor: HtmlExtractor,
    /// CSS URL extractor.
    css_extractor: CssExtractor,
    /// Cache of robots.txt allow/deny status per host.
    robots_cache: HashMap<String, bool>,
    /// The parsed start URL, used as the --no-parent reference point.
    /// `None` before `retrieve_tree` is first called.
    start_url: Option<ParsedUrl>,
}

impl RecursiveRetriever {
    /// Create a new recursive retriever with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Shared configuration reference containing recursive options.
    /// * `progress` - Progress display for reporting download status.
    ///
    /// # Returns
    ///
    /// A new `RecursiveRetriever` instance.
    pub fn new(config: Arc<Config>, progress: Box<dyn ProgressDisplay>) -> Self {
        let retriever = Retriever::new(config.clone(), progress);
        RecursiveRetriever {
            retriever,
            html_extractor: HtmlExtractor,
            css_extractor: CssExtractor,
            robots_cache: HashMap::new(),
            start_url: None,
        }
    }

    /// Log a rejected URL to the reject log file if configured.
    ///
    /// When `--reject-log` is set, URLs that are filtered out or disallowed
    /// by robots.txt are written to the specified file for debugging.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL that was rejected.
    /// * `reason` - The reason for rejection.
    fn log_rejected_url(&self, url: &str, reason: &str) {
        if let Some(ref reject_log_path) = self.retriever.config().reject_log {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(reject_log_path)
            {
                let _ = writeln!(file, "{}: {}", url, reason);
            }
        }
    }

    /// Retrieve an entire URL tree starting from the given URL.
    ///
    /// This is the main entry point for recursive downloads. It downloads
    /// the starting URL, extracts links from HTML/CSS content, and continues
    /// downloading linked resources up to the configured depth.
    ///
    /// The method handles:
    /// - Quota checking (`--quota`)
    /// - robots.txt compliance (`--use-robots`)
    /// - URL filtering (`-A`/`-R`)
    /// - Redirect following
    /// - Page requisites (`--page-requisites`)
    /// - Wait intervals (`--wait`)
    ///
    /// # Arguments
    ///
    /// * `start_url` - The starting URL for the recursive download.
    ///
    /// # Returns
    ///
    /// - `Ok(RecursiveExitStatus::Success)` if downloads completed successfully.
    /// - `Ok(RecursiveExitStatus::Error)` if some downloads failed.
    /// - `Ok(RecursiveExitStatus::NoUrlsFound)` if no URLs were downloaded.
    /// - `Err(RetrieveError)` if a critical error occurred.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if the starting URL cannot be parsed or
    /// a critical error prevents the download from proceeding.
    pub fn retrieve_tree(&mut self, start_url: &str) -> Result<RecursiveExitStatus, RetrieveError> {
        let parsed = ParsedUrl::parse(start_url)
            .map_err(RetrieveError::Protocol)?;

        let max_depth = self.retriever.config().recursive.max_level;
        let max_redirect = self.retriever.config().max_redirect;
        let mut queue = UrlQueue::new(max_depth);

        if self.retriever.config().recursive.spider {
            queue.push(QueueEntry {
                url: start_url.to_string(),
                referer: None,
                depth: 0,
                expect_html: true,
                expect_css: false,
                redirect_count: 0,
            });
        } else {
            queue.push(QueueEntry {
                url: start_url.to_string(),
                referer: None,
                depth: 0,
                expect_html: true,
                expect_css: false,
                redirect_count: 0,
            });
        }

        let start_host = parsed.host.clone();
        self.start_url = Some(parsed.clone());
        let mut robot_parser = RobotParser::new(
            self.retriever.config().http.user_agent.as_deref().unwrap_or("wget-rs")
        );
        let mut exit_status = RecursiveExitStatus::Success;
        let mut any_downloaded = false;

        while let Some(entry) = queue.pop() {
            if let Some(quota) = self.retriever.config().quota {
                if self.retriever.total_downloaded() >= quota {
                    warn!("quota exceeded, stopping");
                    break;
                }
            }

            let url_str = entry.url.clone();

            if self.retriever.download_registry().is_visited(&url_str) {
                continue;
            }

            if !self.is_url_allowed(&url_str, &start_host, &mut robot_parser) {
                debug!("URL not allowed by filter/robots: {}", url_str);
                self.log_rejected_url(&url_str, "not allowed by filter/robots");
                continue;
            }

            if !UrlFilter::is_accepted(self.retriever.url_filter(), &url_str, &url_str) {
                debug!("URL filtered out: {}", url_str);
                self.log_rejected_url(&url_str, "filtered by accept/reject patterns");
                continue;
            }

            let spider_mode = self.retriever.config().recursive.spider;
            let page_requisites = self.retriever.config().page_requisites;

            if spider_mode {
                match self.retriever.retrieve(&url_str) {
                    Ok(RetrieveOutcome::Success(_)) |
                    Ok(RetrieveOutcome::NotModified) => {
                        any_downloaded = true;
                    }
                    Ok(RetrieveOutcome::Redirected(target)) => {
                        // Arch 6.3-4: enforce --max-redirect on the re-queued
                        // redirect target (parallel path does the same).
                        let next_hops = entry.redirect_count + 1;
                        if next_hops <= max_redirect {
                            if !queue.is_visited(&target) {
                                queue.push(QueueEntry {
                                    url: target,
                                    referer: Some(url_str.clone()),
                                    depth: entry.depth,
                                    expect_html: entry.expect_html,
                                    expect_css: entry.expect_css,
                                    redirect_count: next_hops,
                                });
                            }
                        } else {
                            warn!(
                                "max redirects ({}) exceeded following {} -- not re-queuing {}",
                                max_redirect, url_str, target
                            );
                            exit_status = RecursiveExitStatus::Error;
                        }
                    }
                    Ok(RetrieveOutcome::SpiderOnly) => {}
                    Err(e) => {
                        warn!("error retrieving {}: {}", url_str, e);
                        exit_status = RecursiveExitStatus::Error;
                    }
                }
            } else {
                match self.retriever.retrieve(&url_str) {
                    Ok(RetrieveOutcome::Success(body_result)) => {
                        any_downloaded = true;
                        let local = body_result.local_file.as_ref().map(|p| p.as_path());

                        // Determine whether to descend into children.
                        // GNU wget (recur.c:390-408) allows -p to exceed the
                        // maximum depth by up to 2 pseudo-levels for inline
                        // links (dash_p_leaf_HTML).
                        let depth_limit = max_depth.unwrap_or(u32::MAX);
                        let at_or_beyond_limit = entry.depth >= depth_limit;
                        let dash_p_leaf = page_requisites && at_or_beyond_limit
                            && (entry.depth == depth_limit || entry.depth == depth_limit.saturating_add(1));

                        // Descend if we haven't hit the depth limit, or if -p
                        // allows inline links at the leaf level.
                        let descend = entry.depth < depth_limit || dash_p_leaf;

                        if descend {
                            if let Some(lpath) = local {
                                let links_opt = self.extract_links(lpath, &url_str, &entry);
                                if let Some(links) = links_opt {
                                    // <base href> overrides the merge base for
                                    // relative links on this page (first one
                                    // wins, like browsers and wget).
                                    let doc_base =
                                        effective_base_url(&links, &url_str);
                                    for link in &links {
                                        if link.meta_disallow_follow {
                                            continue;
                                        }
                                        // At dash_p_leaf level, only follow
                                        // inline links (GNU wget recur.c:470).
                                        if dash_p_leaf && !link.inline {
                                            continue;
                                        }
                                        self.enqueue_child(
                                            link, &url_str, entry.depth, &mut queue,
                                            doc_base.as_deref(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Ok(RetrieveOutcome::NotModified) => {
                        // Same descend logic as Success branch above.
                        let depth_limit = max_depth.unwrap_or(u32::MAX);
                        let at_or_beyond_limit = entry.depth >= depth_limit;
                        let dash_p_leaf = page_requisites && at_or_beyond_limit
                            && (entry.depth == depth_limit || entry.depth == depth_limit.saturating_add(1));
                        let descend = entry.depth < depth_limit || dash_p_leaf;

                        if descend {
                            let local_path = self.retriever.download_registry().get_local(&url_str).cloned();
                            if let Some(lpath) = local_path {
                                if let Some(links) = self.extract_links(&lpath, &url_str, &entry) {
                                    // <base href> override, same as the Success branch.
                                    let doc_base = effective_base_url(&links, &url_str);
                                    for link in &links {
                                        if link.meta_disallow_follow {
                                            continue;
                                        }
                                        if dash_p_leaf && !link.inline {
                                            continue;
                                        }
                                        self.enqueue_child(
                                            link, &url_str, entry.depth, &mut queue,
                                            doc_base.as_deref(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Ok(RetrieveOutcome::Redirected(target)) => {
                        // Arch 6.3-4: enforce --max-redirect on the re-queued
                        // redirect target (parallel path does the same).
                        let next_hops = entry.redirect_count + 1;
                        if next_hops <= max_redirect {
                            if !queue.is_visited(&target) {
                                queue.push(QueueEntry {
                                    url: target,
                                    referer: Some(url_str.clone()),
                                    depth: entry.depth,
                                    expect_html: entry.expect_html,
                                    expect_css: entry.expect_css,
                                    redirect_count: next_hops,
                                });
                            }
                        } else {
                            warn!(
                                "max redirects ({}) exceeded following {} -- not re-queuing {}",
                                max_redirect, url_str, target
                            );
                            exit_status = RecursiveExitStatus::Error;
                        }
                    }
                    Ok(RetrieveOutcome::SpiderOnly) => {}
                    Err(e) => {
                        warn!("error retrieving {}: {}", url_str, e);
                        exit_status = RecursiveExitStatus::Error;
                    }
                }
            }

            if let Some(wait) = self.retriever.config().wait {
                debug!("waiting {:?}", wait);
                std::thread::sleep(wait);
            }
        }

        if !any_downloaded {
            Ok(RecursiveExitStatus::NoUrlsFound)
        } else {
            Ok(exit_status)
        }
    }

    /// Parallel recursive download using N worker threads.
    ///
    /// Each worker has its own `Retriever` instance (sharing the TLS connection
    /// pool via `Arc`), but the `UrlQueue` is shared via `Arc<Mutex<UrlQueue>>`.
    /// URL deduplication happens at the queue level (blacklist in push()).
    ///
    /// Link extraction is performed in the worker that downloaded the file,
    /// then new URLs are pushed back into the shared queue.
    ///
    /// This method is used when `-j N` (N > 1) is specified with recursive mode.
    ///
    /// # Arguments
    ///
    /// * `start_url` - The starting URL for the recursive download.
    /// * `num_workers` - Number of parallel download workers.
    ///
    /// # Returns
    ///
    /// - `Ok(RecursiveExitStatus::Success)` if downloads completed successfully.
    /// - `Ok(RecursiveExitStatus::Error)` if some downloads failed.
    /// - `Ok(RecursiveExitStatus::NoUrlsFound)` if no URLs were downloaded.
    pub fn retrieve_tree_parallel(
        &mut self,
        start_url: &str,
        num_workers: usize,
    ) -> Result<RecursiveExitStatus, RetrieveError> {
        let parsed = ParsedUrl::parse(start_url)
            .map_err(RetrieveError::Protocol)?;

        let max_depth = self.retriever.config().recursive.max_level;
        let queue = Arc::new(Mutex::new(UrlQueue::new(max_depth)));
        let error_flag = Arc::new(AtomicBool::new(false));
        let any_downloaded = Arc::new(AtomicBool::new(false));
        let start_host = parsed.host.clone();

        let max_redirect = self.retriever.config().max_redirect;
        // Seed the queue with the start URL
        {
            let mut q = queue.lock().unwrap();
            q.push(QueueEntry {
                url: start_url.to_string(),
                referer: None,
                depth: 0,
                expect_html: true,
                expect_css: false,
                redirect_count: 0,
            });
        }

        self.start_url = Some(parsed.clone());

        // Get config and TLS pool for cloning to each worker
        let config = self.retriever.config_arc_clone();
        let tls_pool = self.retriever.connection_pool_clone();
        // H-6: clone the main retriever's registry Arc so every worker
        // shares one registry (cross-worker dedupe + conversion). Cloning
        // the Arc (not borrowing) keeps the closure Send.
        let shared_registry: Arc<std::sync::Mutex<DownloadRegistry>> =
            self.retriever.registry_arc_clone();

        // Build start_url for each worker to use as --no-parent reference
        let start_url_parsed = Arc::new(parsed);

        // Use std::thread::scope for scoped threads (no 'static needed)
        // active_count tracks workers currently processing a URL. A worker
        // only exits when the queue is empty AND active_count == 0, preventing
        // the race where a worker exits while another is about to push new URLs.
        let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_handles: Vec<_> = (0..num_workers)
            .map(|worker_id| {
                let queue = queue.clone();
                let error_flag = error_flag.clone();
                let any_downloaded = any_downloaded.clone();
                let config = config.clone();
                let tls_pool = tls_pool.clone();
                let start_url_parsed = start_url_parsed.clone();
                let start_host = start_host.clone();
                let active_count = active_count.clone();
                let shared_registry = shared_registry.clone();

                std::thread::Builder::new()
                    .name(format!("recursive-worker-{}", worker_id))
                    .spawn(move || {
                        // Each worker has its own Retriever + extractors.
                        // The TLS pool is shared via Arc (TlsConnectionPool::Clone).
                        let progress = ut_progress::create_progress_display(
                            ut_core::ProgressStyle::Silent, true,
                        );
                        let mut retriever = Retriever::with_connection_pool(
                            config.clone(), progress, tls_pool,
                        );
                        // H-6: share ONE download registry across all workers.
                        // With per-worker registries, `is_visited` only knew
                        // about downloads made by the SAME worker, so the same
                        // resource could be fetched repeatedly by different
                        // workers (the queue's string blacklist only blocks
                        // exact duplicate URLs). Sharing the registry makes
                        // the visited check cross-worker, and also funnels
                        // every worker's downloads into the single registry
                        // used later for link conversion.
                        retriever.set_shared_registry(shared_registry.clone());
                        let html_extractor = HtmlExtractor;
                        let css_extractor = CssExtractor;
                        let mut robots_cache: HashMap<String, bool> = HashMap::new();

                        loop {
                            // Pop next URL from shared queue
                            let entry = {
                                let mut q = queue.lock().unwrap();
                                q.pop()
                            };

                            let Some(entry) = entry else {
                                // Queue empty. Only exit if no other worker is
                                // currently processing (they might push more URLs).
                                // Use a short sleep to avoid busy-waiting, but
                                // check active_count to prevent premature exit.
                                if active_count.load(Ordering::Relaxed) == 0 {
                                    // No workers are processing; queue is truly done.
                                    break;
                                }
                                // Some worker is still processing; wait briefly.
                                std::thread::sleep(std::time::Duration::from_millis(10));
                                continue;
                            };

                            // Mark this worker as active before processing.
                            // RAII guard: decremented on EVERY exit path of the
                            // loop body (quota break, visited/robots continue,
                            // retrieve error, normal completion). The previous
                            // manual fetch_sub at the end of the loop was
                            // skipped by three early-exit paths, permanently
                            // inflating active_count and hanging all workers
                            // in the queue-empty wait loop above.
                            let _active = ActiveGuard::new(&active_count);

                            let url_str = entry.url.clone();

                            // Check quota
                            if let Some(quota) = config.quota {
                                if retriever.total_downloaded() >= quota {
                                    warn!("quota exceeded, stopping");
                                    break;
                                }
                            }

                            // Check if visited (download registry)
                            if retriever.download_registry().is_visited(&url_str) {
                                continue;
                            }

                            // Check robots
                            if !is_url_allowed_static(
                                &url_str, &start_host, &config, &mut robots_cache,
                            ) {
                                debug!("URL not allowed by filter/robots: {}", url_str);
                                continue;
                            }

                            // Check accept/reject filters (-A/-R/--accept-regex/
                            // --reject-regex/-D/-I/-X). P0 fix: the parallel
                            // path previously skipped the CompositeFilter
                            // entirely, so workers downloaded URLs the user
                            // explicitly excluded. The sequential path applies
                            // the same check (recursive.rs `is_accepted` call);
                            // both now mirror wget's download_child filtering
                            // (recur.c:695-720).
                            if !UrlFilter::is_accepted(
                                retriever.url_filter(),
                                &url_str,
                                &url_str,
                            ) {
                                debug!("URL filtered out: {}", url_str);
                                log_rejected_url_static(
                                    &config,
                                    &url_str,
                                    "filtered by accept/reject patterns",
                                );
                                continue;
                            }

                            // Download
                            match retriever.retrieve(&url_str) {
                                Ok(RetrieveOutcome::Success(body_result)) => {
                                    any_downloaded.store(true, Ordering::Relaxed);
                                    let local = body_result.local_file.as_ref().map(|p| p.as_path());

                                    // Descend?
                                    let depth_limit = max_depth.unwrap_or(u32::MAX);
                                    let descend = entry.depth < depth_limit;

                                    if descend {
                                        if let Some(lpath) = local {
                                            if let Some(links) = extract_links_static(
                                                lpath, &url_str, &entry,
                                                &html_extractor, &css_extractor, &config,
                                            ) {
                                                // <base href> override for this
                                                // page (first one wins).
                                                let doc_base =
                                                    effective_base_url(&links, &url_str);
                                                let mut q = queue.lock().unwrap();
                                                for link in &links {
                                                    if link.meta_disallow_follow { continue; }
                                                    enqueue_child_static(
                                                        link, &url_str, entry.depth, &mut q,
                                                        &start_url_parsed, &config,
                                                        doc_base.as_deref(),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(RetrieveOutcome::NotModified) => {
                                    any_downloaded.store(true, Ordering::Relaxed);
                                }
                                Ok(RetrieveOutcome::Redirected(target)) => {
                                    let mut q = queue.lock().unwrap();
                                    // Arch 6.3-4: count redirect hops and
                                    // enforce --max-redirect. Previously the
                                    // re-queued entry kept redirect_count
                                    // implicit/0 and no limit was checked —
                                    // a server returning an unbounded chain of
                                    // distinct redirect URLs made the parallel
                                    // crawl never terminate.
                                    let next_hops = entry.redirect_count + 1;
                                    if next_hops <= max_redirect {
                                        if !q.is_visited(&target) {
                                            q.push(QueueEntry {
                                                url: target,
                                                referer: Some(url_str.clone()),
                                                depth: entry.depth,
                                                expect_html: entry.expect_html,
                                                expect_css: entry.expect_css,
                                                redirect_count: next_hops,
                                            });
                                        }
                                    } else {
                                        warn!(
                                            "max redirects ({}) exceeded following {} -- not re-queuing {}",
                                            max_redirect, url_str, target
                                        );
                                        error_flag.store(true, Ordering::Relaxed);
                                    }
                                }
                                Ok(RetrieveOutcome::SpiderOnly) => {}
                                Err(e) => {
                                    warn!("error retrieving {}: {}", url_str, e);
                                    error_flag.store(true, Ordering::Relaxed);
                                }
                            }

                            if let Some(wait) = config.wait {
                                debug!("waiting {:?}", wait);
                                std::thread::sleep(wait);
                            }

                            // _active guard drops here: active_count is
                            // decremented AFTER all queue pushes so other
                            // workers don't exit early.
                        }
                    })
                    .expect("failed to spawn worker thread")
            })
            .collect();

        // Wait for all workers to finish
        for handle in worker_handles {
            let _ = handle.join();
        }

        let had_errors = error_flag.load(Ordering::Relaxed);
        let downloaded = any_downloaded.load(Ordering::Relaxed);

        if !downloaded {
            Ok(RecursiveExitStatus::NoUrlsFound)
        } else if had_errors {
            Ok(RecursiveExitStatus::Error)
        } else {
            Ok(RecursiveExitStatus::Success)
        }
    }

    /// Extract links from a downloaded file.
    ///
    /// Reads the local file and extracts URLs based on its content type:
    /// - HTML files: extracts links from `<a>`, `<img>`, `<link>`, etc.
    /// - CSS files: extracts `url()` references.
    ///
    /// # Arguments
    ///
    /// * `local_path` - Path to the downloaded file.
    /// * `base_url` - The URL from which the file was downloaded (for resolving relative URLs).
    /// * `entry` - Queue entry containing context about the expected content type.
    ///
    /// # Returns
    ///
    /// `Some(Vec<UrlPosition>)` containing extracted URLs with metadata,
    /// or `None` if the file cannot be read or parsed.
    fn extract_links(
        &mut self,
        local_path: &std::path::Path,
        base_url: &str,
        entry: &QueueEntry,
    ) -> Option<Vec<UrlPosition>> {
        if !local_path.exists() {
            return None;
        }

        let mut file = std::fs::File::open(local_path).ok()?;
        let parsed_url = ParsedUrl::parse(base_url).ok()?;

        let base = parsed_url.display();
        let mut opts = ExtractOptions::default();
        opts.follow_tags = self.retriever.config().recursive.follow_tags.clone();
        opts.ignore_tags = self.retriever.config().recursive.ignore_tags.clone();
        opts.strict_comments = self.retriever.config().recursive.strict_comments;

        let content_type = detect_content_type(local_path);
        let results = if content_type_is_html(Some(&content_type)) || entry.expect_html {
            self.html_extractor.extract_urls(&mut file, &base, &opts).ok()?
        } else if content_type_is_css(Some(&content_type)) || entry.expect_css {
            self.css_extractor.extract_urls(&mut file, &base, &opts).ok()?
        } else {
            return None;
        };

        Some(results)
    }

    /// Enqueue a child URL for recursive download.
    ///
    /// Applies various filters and checks before adding the URL to the queue:
    /// - Host spanning: rejects cross-host URLs unless `--span-hosts` is set.
    /// - Relative-only: rejects absolute URLs if `--relative` is set.
    /// - No-parent: rejects URLs above the parent directory if `--no-parent` is set.
    /// - HTTPS-only: rejects HTTP URLs if `--https-only` is set.
    /// - FTP following: rejects FTP URLs unless `--follow-ftp` is set.
    ///
    /// # Arguments
    ///
    /// * `link` - The extracted URL with metadata.
    /// * `parent_url` - The URL of the page containing the link.
    /// * `parent_depth` - The recursion depth of the parent page.
    /// * `queue` - The URL queue to add the child to.
    fn enqueue_child(
        &self,
        link: &UrlPosition,
        parent_url: &str,
        parent_depth: u32,
        queue: &mut UrlQueue,
        base_url: Option<&str>,
    ) {
        let parent_parsed = match ParsedUrl::parse(parent_url) {
            Ok(p) => p,
            Err(_) => return,
        };

        let absolute_url = match link.link_type {
            LinkType::BaseHref => {
                // <base href> is document metadata, not a resource to
                // download (GNU wget html-url.c tag_handle_base). The
                // caller resolves subsequent relative links against it.
                return;
            }
            LinkType::Relative | LinkType::CssImport | LinkType::RefreshRedirect => {
                // Resolve against <base href> when the document declares
                // one, else against the document URL itself (wget resolves
                // every extracted URL against the document base).
                let merged = if let Some(base) = base_url {
                    ParsedUrl::parse(base).ok().and_then(|b| b.merge(&link.url).ok())
                } else {
                    parent_parsed.merge(&link.url).ok()
                };
                match merged {
                    Some(u) => u.display(),
                    None => return,
                }
            }
            _ => link.url.clone(),
        };

        if queue.is_visited(&absolute_url) {
            return;
        }

        let child_parsed = match ParsedUrl::parse(&absolute_url) {
            Ok(p) => p,
            Err(_) => {
                return;
            }
        };

        if !self.retriever.config().recursive.span_hosts {
            if child_parsed.host.to_ascii_lowercase() != parent_parsed.host.to_ascii_lowercase() {
                return;
            }
        }

        if self.retriever.config().recursive.relative_only {
            if link.link_type != LinkType::Relative && link.link_type != LinkType::CssImport {
                return;
            }
        }

        if self.retriever.config().recursive.no_parent {
            // --no-parent: reject links that ascend above the *start* URL's
            // directory (GNU wget compares against start_url_parsed->dir, not
            // the immediate parent). The check only applies when the child is
            // on the same logical site as the start URL: schemes are "similar"
            // (equal, or an http/https pair), the host matches, and -- when the
            // schemes are identical -- the port matches too. Page requisites
            // (inline resources) are exempt in -p mode. A child is allowed iff
            // its directory lies within the start directory's subtree.
            if let Some(ref start) = self.start_url {
                let schemes_similar = schemes_are_similar(child_parsed.scheme, start.scheme);
                let host_match = child_parsed.host.eq_ignore_ascii_case(&start.host);
                // GNU wget skips the port test when the schemes differ (e.g.
                // http vs https), because their default ports legitimately differ.
                let port_ok = child_parsed.scheme != start.scheme
                    || child_parsed.port == start.port;
                let page_reqs_inline = self.retriever.config().page_requisites && link.inline;
                if schemes_similar && host_match && port_ok && !page_reqs_inline {
                    if !is_subdir(&start.dir, &child_parsed.dir, self.retriever.config().ignore_case) {
                        debug!("--no-parent: {} escapes start dir {}", child_parsed.display(), start.dir);
                        return;
                    }
                }
            }
        }

        if self.retriever.config().http.https_only && !child_parsed.scheme.is_secure() {
            return;
        }

        if child_parsed.scheme == Scheme::Ftp && !self.retriever.config().ftp.follow_ftp {
            return;
        }

        queue.push(QueueEntry {
            url: absolute_url,
            referer: Some(parent_url.to_string()),
            depth: parent_depth + 1,
            expect_html: link.expect_html,
            expect_css: link.expect_css,
            redirect_count: 0
        });
    }

    /// Check if a URL is allowed by robots.txt.
    ///
    /// When `--use-robots` is enabled, this method checks the robots.txt
    /// rules for the URL's host. Results are cached per host to avoid
    /// repeated fetches.
    ///
    /// For FTP URLs, robots.txt checking is always skipped.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to check.
    /// * `_start_host` - The starting host (currently unused).
    /// * `robot_parser` - The robots.txt parser instance.
    ///
    /// # Returns
    ///
    /// `true` if the URL is allowed or robots.txt checking is disabled,
    /// `false` if the URL is disallowed by robots.txt.
    fn is_url_allowed(
        &mut self,
        url: &str,
        _start_host: &str,
        robot_parser: &mut RobotParser,
    ) -> bool {
        let parsed = match ParsedUrl::parse(url) {
            Ok(p) => p,
            Err(_) => return true,
        };

        if parsed.scheme == Scheme::Ftp {
            return true;
        }

        if !self.retriever.config().recursive.use_robots {
            return true;
        }

        let host_lc = parsed.host.to_ascii_lowercase();

        // Fetch robots.txt from the network if not already cached
        if !self.robots_cache.contains_key(&host_lc) {
            let allowed = match self.fetch_robots(&host_lc, &parsed.scheme, robot_parser) {
                Some(content) => {
                    robot_parser.load(&host_lc, &content);
                    robot_parser.is_allowed(&host_lc, url).unwrap_or(true)
                }
                None => true,
            };
            self.robots_cache.insert(host_lc.clone(), allowed);
        }

        // Check path-specific rules
        let allowed = robot_parser.is_allowed(&host_lc, url).unwrap_or(true);
        allowed
    }

    /// Fetch robots.txt for a host from the network.
    ///
    /// Downloads `{scheme}://{host}/robots.txt` via the retriever and returns
    /// the content. The scheme matches the URL being checked (HTTP or HTTPS),
    /// matching GNU wget's behavior (recur.c:retrieve_robots), which fetches
    /// robots.txt using the same scheme as the page being crawled. We do
    /// NOT write to a predictable `/tmp` path because that would expose us to
    /// symlink attacks (an attacker could pre-create a symlink at the cache
    /// path pointing at a sensitive file, which we would then overwrite).
    ///
    /// # Arguments
    ///
    /// * `host` - The host to fetch robots.txt for (lowercase).
    /// * `scheme` - The URL scheme to use ("http" or "https").
    /// * `robot_parser` - The robots.txt parser instance (unused here, kept for API consistency).
    ///
    /// # Returns
    ///
    /// `Some(content)` if robots.txt was successfully fetched, `None` otherwise.
    fn fetch_robots(&mut self, host: &str, scheme: &ut_core::types::Scheme, _robot_parser: &mut RobotParser) -> Option<String> {
        // Use the same scheme as the page being crawled (GNU wget semantics).
        // Previously this was hardcoded to HTTPS, which caused HTTP-only sites
        // to fail robots.txt retrieval (404 or TLS error) and could abort
        // recursive downloads.
        let robots_url = format!("{}://{}/robots.txt", scheme.as_str(), host);

        match self.retriever.retrieve(&robots_url) {
            Ok(RetrieveOutcome::Success(body)) => {
                if let Some(ref path) = body.local_file {
                    std::fs::read_to_string(path).ok()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Get a reference to the underlying retriever.
    ///
    /// # Returns
    ///
    /// A reference to the `Retriever` used for individual downloads.
    pub fn retriever(&self) -> &Retriever {
        &self.retriever
    }

    /// Get a mutable reference to the underlying retriever.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `Retriever` used for individual downloads.
    pub fn retriever_mut(&mut self) -> &mut Retriever {
        &mut self.retriever
    }
}

/// Detect content type from file extension.
///
/// Maps common file extensions to their MIME types. This is used when
/// the Content-Type header is not available (e.g., for local files
/// during recursive downloads).
///
/// # Arguments
///
/// * `path` - The file path to examine.
///
/// # Returns
///
/// A MIME type string based on the file extension, or
/// `application/octet-stream` for unknown extensions.
fn detect_content_type(path: &std::path::Path) -> String {
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());

    match ext.as_deref() {
        Some("html") | Some("htm") | Some("xhtml") => "text/html".to_string(),
        Some("css") => "text/css".to_string(),
        Some("js") | Some("mjs") => "application/javascript".to_string(),
        Some("json") => "application/json".to_string(),
        Some("xml") => "text/xml".to_string(),
        Some("txt") => "text/plain".to_string(),
        Some("pdf") => "application/pdf".to_string(),
        Some("png") => "image/png".to_string(),
        Some("jpg") | Some("jpeg") => "image/jpeg".to_string(),
        Some("gif") => "image/gif".to_string(),
        Some("svg") => "image/svg+xml".to_string(),
        Some("ico") => "image/x-icon".to_string(),
        Some("webp") => "image/webp".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}


/// Whether two URL schemes are "similar" per GNU wget's
/// `schemes_are_similar_p` (src/url.c): equal, or an http/https pair. Used by
/// `--no-parent` to decide whether a link is on the same logical site.
fn schemes_are_similar(a: Scheme, b: Scheme) -> bool {
    if a == b {
        return true;
    }
    matches!((a, b), (Scheme::Http, Scheme::Https) | (Scheme::Https, Scheme::Http))
}

/// Check if `child_dir` is within the subtree of `start_dir`, matching GNU
/// wget's `subdir_p()` (src/utils.c). GNU wget stores directory paths *without*
/// a trailing slash, but Rust's `ParsedUrl::dir` keeps one, so trailing slashes
/// are trimmed before the byte-wise prefix comparison.
///
/// Returns `true` when `child_dir` equals `start_dir` or begins with
/// `start_dir` immediately followed by `/`. An empty `start_dir` (the site
/// root) matches every directory.
fn is_subdir(start_dir: &str, child_dir: &str, ignore_case: bool) -> bool {
    let d1 = start_dir.trim_end_matches('/');
    let d2 = child_dir.trim_end_matches('/');
    if d1.is_empty() {
        return true;
    }
    let b1 = d1.as_bytes();
    let b2 = d2.as_bytes();
    let mut i = 0;
    if !ignore_case {
        while i < b1.len() && i < b2.len() && b1[i] == b2[i] {
            i += 1;
        }
    } else {
        while i < b1.len() && i < b2.len()
            && b1[i].to_ascii_lowercase() == b2[i].to_ascii_lowercase()
        {
            i += 1;
        }
    }
    i == b1.len() && (i == b2.len() || b2[i] == b'/')
}

#[cfg(test)]
mod no_parent_tests {
    use super::is_subdir;

    #[test]
    fn same_directory_is_allowed() {
        assert!(is_subdir("/a/b/", "/a/b/", false));
        assert!(is_subdir("/a/b", "/a/b", false));
    }

    #[test]
    fn child_subdirectory_is_allowed() {
        assert!(is_subdir("/a/b/", "/a/b/c/", false));
        assert!(is_subdir("/a/b/", "/a/b/c/d/", false));
    }

    #[test]
    fn parent_directory_is_rejected() {
        assert!(!is_subdir("/a/b/", "/a/", false));
        assert!(!is_subdir("/a/b/", "/", false));
    }

    #[test]
    fn sibling_directory_is_rejected() {
        assert!(!is_subdir("/a/b/", "/a/c/", false));
        assert!(!is_subdir("/a/b/", "/a/bc/", false));
    }

    #[test]
    fn root_start_matches_everything() {
        assert!(is_subdir("", "/anything/here/", false));
        assert!(is_subdir("/", "/a/b/c/", false));
    }

    #[test]
    fn ignore_case_comparison() {
        assert!(is_subdir("/A/B/", "/a/b/c/", true));
        assert!(!is_subdir("/A/B/", "/a/c/", true));
    }
}

// ============ Static helper functions for parallel recursive download ============

/// Append a rejected URL to `--reject-log` (parallel worker version of
/// `log_rejected_url`).
///
/// Workers cannot reach the `RecursiveRetriever` method, so the log write is
/// duplicated here. Line-sized O_APPEND writes are atomic on POSIX, so
/// concurrent workers cannot interleave mid-line.
fn log_rejected_url_static(config: &Config, url: &str, reason: &str) {
    if let Some(ref reject_log_path) = config.reject_log {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(reject_log_path)
        {
            let _ = writeln!(file, "{}: {}", url, reason);
        }
    }
}

/// Check if a URL is allowed (parallel worker version, simplified robots check).
///
/// In parallel mode, robots.txt fetching is simplified: we only check the
/// already-fetched robots_cache. Network fetch of robots.txt is not done in
/// parallel workers to avoid race conditions. The first encounter of a new
/// host will allow the URL; a subsequent sequential robots.txt fetch may
/// block it later (matching wget's "fail open" behavior).
fn is_url_allowed_static(
    url: &str,
    _start_host: &str,
    config: &Config,
    robots_cache: &mut HashMap<String, bool>,
) -> bool {
    let parsed = match ParsedUrl::parse(url) {
        Ok(p) => p,
        Err(_) => return true,
    };

    if parsed.scheme == Scheme::Ftp {
        return true;
    }

    if !config.recursive.use_robots {
        return true;
    }

    let host_lc = parsed.host.to_ascii_lowercase();
    // In parallel mode, if robots.txt hasn't been fetched yet, allow the URL
    // (fail-open, matching wget's behavior). The cache is checked but not
    // populated by network fetch in workers.
    if let Some(&allowed) = robots_cache.get(&host_lc) {
        return allowed;
    }

    true
}

/// Extract links from a downloaded file (parallel worker version).
fn extract_links_static(
    local_path: &std::path::Path,
    base_url: &str,
    entry: &QueueEntry,
    html_extractor: &HtmlExtractor,
    css_extractor: &CssExtractor,
    config: &Config,
) -> Option<Vec<UrlPosition>> {
    if !local_path.exists() {
        return None;
    }

    let mut file = std::fs::File::open(local_path).ok()?;
    let parsed_url = ParsedUrl::parse(base_url).ok()?;

    let base = parsed_url.display();
    let mut opts = ExtractOptions::default();
    opts.follow_tags = config.recursive.follow_tags.clone();
    opts.ignore_tags = config.recursive.ignore_tags.clone();
    opts.strict_comments = config.recursive.strict_comments;

    let content_type = detect_content_type(local_path);
    let results = if content_type_is_html(Some(&content_type)) || entry.expect_html {
        html_extractor.extract_urls(&mut file, &base, &opts).ok()?
    } else if content_type_is_css(Some(&content_type)) || entry.expect_css {
        css_extractor.extract_urls(&mut file, &base, &opts).ok()?
    } else {
        return None;
    };

    Some(results)
}

/// Compute the effective document base URL from extracted links.
///
/// When the page declares `<base href="...">`, relative links (including
/// relative meta-refresh targets) must resolve against it instead of the
/// document URL (GNU wget html-url.c `tag_handle_base`). The first `<base>`
/// wins, matching browser behavior. Returns `None` when the page has no
/// usable base or the base cannot be merged into an absolute URL.
fn effective_base_url(links: &[UrlPosition], document_url: &str) -> Option<String> {
    let base_link = links.iter().find(|l| l.link_type == LinkType::BaseHref)?;
    let doc = ParsedUrl::parse(document_url).ok()?;
    doc.merge(&base_link.url).ok().map(|u| u.display())
}

/// Enqueue a child URL into the shared queue (parallel worker version).
fn enqueue_child_static(
    link: &UrlPosition,
    parent_url: &str,
    parent_depth: u32,
    queue: &mut UrlQueue,
    start_url: &ParsedUrl,
    config: &Config,
    base_url: Option<&str>,
) {
    let parent_parsed = match ParsedUrl::parse(parent_url) {
        Ok(p) => p,
        Err(_) => return,
    };

    let absolute_url = match link.link_type {
        LinkType::BaseHref => {
            // Document metadata, not a downloadable resource (see
            // enqueue_child — GNU wget html-url.c tag_handle_base).
            return;
        }
        LinkType::Relative | LinkType::CssImport | LinkType::RefreshRedirect => {
            // Resolve against <base href> when the document declares one,
            // else against the document URL itself.
            let merged = if let Some(base) = base_url {
                ParsedUrl::parse(base).ok().and_then(|b| b.merge(&link.url).ok())
            } else {
                parent_parsed.merge(&link.url).ok()
            };
            match merged {
                Some(u) => u.display(),
                None => return,
            }
        }
        _ => link.url.clone(),
    };

    let child_parsed = match ParsedUrl::parse(&absolute_url) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Span hosts check
    if !config.recursive.span_hosts
        && child_parsed.host.to_ascii_lowercase() != parent_parsed.host.to_ascii_lowercase()
    {
        return;
    }

    // Relative only check
    if config.recursive.relative_only
        && link.link_type != LinkType::Relative
        && link.link_type != LinkType::CssImport
    {
        return;
    }

    // No-parent check
    if config.recursive.no_parent {
        if !is_subdir(
            &start_url.dir,
            &child_parsed.dir,
            config.ignore_case,
        ) {
            return;
        }
    }

    // HTTPS-only check
    if config.http.https_only && !child_parsed.scheme.is_secure() {
        return;
    }

    // FTP following check
    if child_parsed.scheme == Scheme::Ftp && !config.ftp.follow_ftp {
        return;
    }

    queue.push(QueueEntry {
        url: absolute_url,
        referer: Some(parent_url.to_string()),
        depth: parent_depth + 1,
        expect_html: link.expect_html,
        expect_css: link.expect_css,
                                redirect_count: 0
    });
}
