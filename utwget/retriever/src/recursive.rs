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
