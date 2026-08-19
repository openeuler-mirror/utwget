//! CSS URL extractor for finding embedded resources in stylesheets.
//!
//! This module provides functionality to parse CSS files and extract
//! URLs from `url()` functions and `@import` rules.

use std::io::Read;

use cssparser::{ParseError, Parser, ParserInput, Token};

use crate::converter::ConvertError;
use crate::types::{ContentExtractor, ContentKind};
use crate::url_position::{ExtractOptions, LinkType, UrlPosition};

/// CSS content extractor for URL extraction.
///
/// Parses CSS stylesheets and extracts URLs from:
/// - `url()` function values (background, content, etc.)
/// - `@import` rules
///
/// # Example
///
/// ```ignore
/// use html::css_extractor::CssExtractor;
/// use html::types::ContentExtractor;
///
/// let extractor = CssExtractor;
/// let css = r#"
///     body { background: url(bg.png); }
///     @import url("reset.css");
/// "#;
/// let urls = extractor.extract_urls(&mut css.as_bytes(), "http://example.com/", &ExtractOptions::default())?;
/// ```
pub struct CssExtractor;

/// Checks if a URL should be skipped during extraction.
///
/// Skips URLs that are:
/// - Empty strings
/// - Data URLs (`data:`)
/// - Fragment identifiers (`#`)
/// - Blob URLs (`blob:`)
///
/// # Arguments
///
/// * `url` - The URL to check.
///
/// # Returns
///
/// `true` if the URL should be skipped, `false` otherwise.
fn is_skippable_url(url: &str) -> bool {
    url.is_empty()
        || url.starts_with("data:")
        || url.starts_with('#')
        || url.starts_with("blob:")
}
