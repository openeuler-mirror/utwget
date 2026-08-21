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
