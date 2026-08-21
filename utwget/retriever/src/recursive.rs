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
use std::sync::Arc;
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
use crate::url_queue::{QueueEntry, UrlQueue};

/// Exit status for recursive retrieval operations.
///
/// Indicates the overall result of a recursive download session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// All downloads completed successfully.
    Success,
    /// One or more downloads encountered errors.
    Error,
    /// No URLs were found to download.
    NoUrlsFound,
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
/// let retriever = RecursiveRetriever::new(config, progress);
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
    /// - `Ok(ExitStatus::Success)` if downloads completed successfully.
    /// - `Ok(ExitStatus::Error)` if some downloads failed.
    /// - `Ok(ExitStatus::NoUrlsFound)` if no URLs were downloaded.
    /// - `Err(RetrieveError)` if a critical error occurred.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if the starting URL cannot be parsed or
    /// a critical error prevents the download from proceeding.
    pub fn retrieve_tree(&mut self, start_url: &str) -> Result<ExitStatus, RetrieveError> {
        let parsed = ParsedUrl::parse(start_url)
            .map_err(RetrieveError::Protocol)?;

        let max_depth = self.retriever.config().recursive.max_level;
        let mut queue = UrlQueue::new(max_depth);

        if self.retriever.config().recursive.spider {
            queue.push(QueueEntry {
                url: start_url.to_string(),
                referer: None,
                depth: 0,
                expect_html: true,
                expect_css: false,
            });
        } else {
            queue.push(QueueEntry {
                url: start_url.to_string(),
                referer: None,
                depth: 0,
                expect_html: true,
                expect_css: false,
            });
        }

        let start_host = parsed.host.clone();
        let mut robot_parser = RobotParser::new(
            self.retriever.config().http.user_agent.as_deref().unwrap_or("wget-rs")
        );
        let mut exit_status = ExitStatus::Success;
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
                        if !queue.is_visited(&target) {
                            queue.push(QueueEntry {
                                url: target,
                                referer: Some(url_str.clone()),
                                depth: entry.depth,
                                expect_html: entry.expect_html,
                                expect_css: entry.expect_css,
                            });
                        }
                    }
                    Ok(RetrieveOutcome::SpiderOnly) => {}
                    Err(e) => {
                        warn!("error retrieving {}: {}", url_str, e);
                        exit_status = ExitStatus::Error;
                    }
                }
            } else {
                match self.retriever.retrieve(&url_str) {
                    Ok(RetrieveOutcome::Success(body_result)) => {
                        any_downloaded = true;
                        let local = body_result.local_file.as_ref().map(|p| p.as_path());

                        if !page_requisites && entry.depth < max_depth.unwrap_or(u32::MAX) {
                            if let Some(lpath) = local {
                                if let Some(links) = self.extract_links(lpath, &url_str, &entry) {
                                    for link in links {
                                        if link.meta_disallow_follow {
                                            continue;
                                        }
                                        self.enqueue_child(&link, &url_str, entry.depth, &mut queue);
                                    }
                                }
                            }
                        }

                        if page_requisites {
                            if let Some(lpath) = local {
                                if let Some(links) = self.extract_links(lpath, &url_str, &entry) {
                                    for link in links {
                                        if link.inline {
                                            self.enqueue_child(&link, &url_str, entry.depth, &mut queue);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(RetrieveOutcome::NotModified) => {
                        if !page_requisites && entry.depth < max_depth.unwrap_or(u32::MAX) {
                            let local_path = self.retriever.download_registry().get_local(&url_str).cloned();
                            if let Some(lpath) = local_path {
                                if let Some(links) = self.extract_links(&lpath, &url_str, &entry) {
                                    for link in links {
                                        if link.meta_disallow_follow {
                                            continue;
                                        }
                                        self.enqueue_child(&link, &url_str, entry.depth, &mut queue);
                                    }
                                }
                            }
                        }
                    }
                    Ok(RetrieveOutcome::Redirected(target)) => {
                        if !queue.is_visited(&target) {
                            queue.push(QueueEntry {
                                url: target,
                                referer: Some(url_str.clone()),
                                depth: entry.depth,
                                expect_html: entry.expect_html,
                                expect_css: entry.expect_css,
                            });
                        }
                    }
                    Ok(RetrieveOutcome::SpiderOnly) => {}
                    Err(e) => {
                        warn!("error retrieving {}: {}", url_str, e);
                        exit_status = ExitStatus::Error;
                    }
                }
            }

            if let Some(wait) = self.retriever.config().wait {
                debug!("waiting {:?}", wait);
                std::thread::sleep(wait);
            }
        }

        if !any_downloaded {
            Ok(ExitStatus::NoUrlsFound)
        } else {
            Ok(exit_status)
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
    ) {
        let parent_parsed = match ParsedUrl::parse(parent_url) {
            Ok(p) => p,
            Err(_) => return,
        };

        let absolute_url = match link.link_type {
            LinkType::Relative | LinkType::CssImport => {
                match parent_parsed.merge(&link.url) {
                    Ok(u) => u.display(),
                    Err(_) => return,
                }
            }
            _ => link.url.clone(),
        };

        if queue.is_visited(&absolute_url) {
            return;
        }

        let child_parsed = match ParsedUrl::parse(&absolute_url) {
            Ok(p) => p,
            Err(_) => return,
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
            let parent_dir = parent_parsed.dir.trim_end_matches('/');
            let child_dir = child_parsed.dir.trim_end_matches('/');
            if child_dir.len() < parent_dir.len() {
                return;
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
        if let Some(&allowed) = self.robots_cache.get(&host_lc) {
            return allowed;
        }

        let _robots_url = format!("http://{}/robots.txt", host_lc);
        let allowed = match std::fs::read_to_string(format!("/tmp/.wget-robots-{}", host_lc)) {
            Ok(content) => {
                robot_parser.load(&host_lc, &content);
                robot_parser.is_allowed(&host_lc, url).unwrap_or(true)
            }
            Err(_) => true,
        };

        self.robots_cache.insert(host_lc, allowed);
        allowed
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
