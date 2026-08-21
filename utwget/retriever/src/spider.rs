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
