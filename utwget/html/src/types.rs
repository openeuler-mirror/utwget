//! Content extractor types and traits for URL extraction.
//!
//! This module defines the common interface for content extractors that can
//! parse different content types (HTML, CSS, etc.) and extract embedded URLs.

use std::io::Read;

use crate::url_position::{ExtractOptions, UrlPosition};
use crate::converter::ConvertError;

/// Represents the kind of content being processed.
///
/// Different content types require different parsing strategies for URL extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    /// HTML document content.
    Html,
    /// CSS stylesheet content.
    Css,
    /// XML document content.
    Xml,
    /// Plain text content.
    Plaintext,
    /// FTP directory listing.
    FtpListing,
}

/// Trait for extracting URLs from different content types.
///
/// Implementations of this trait parse specific content formats (HTML, CSS, etc.)
/// and extract embedded URLs for recursive downloading.
///
/// # Thread Safety
///
/// All implementations must be `Send` to support concurrent processing.
pub trait ContentExtractor: Send {
    /// Extracts URLs from the given content.
    ///
    /// # Arguments
    ///
    /// * `reader` - A reader providing the content to parse.
    /// * `base_url` - The base URL for resolving relative URLs.
    /// * `opts` - Options controlling which URLs to extract.
    ///
    /// # Returns
    ///
    /// A vector of `UrlPosition` objects representing the extracted URLs,
    /// or a `ConvertError` if parsing fails.
    fn extract_urls(
        &self,
        reader: &mut dyn Read,
        base_url: &str,
        opts: &ExtractOptions,
    ) -> Result<Vec<UrlPosition>, ConvertError>;

    /// Returns the kind of content this extractor handles.
    ///
    /// # Returns
    ///
    /// The `ContentKind` this extractor is designed to process.
    fn content_kind(&self) -> ContentKind;

    /// Indicates whether the extractor requires the full content to be loaded.
    ///
    /// Some extractors (like CSS) need the entire content in memory,
    /// while others (like HTML) can process content incrementally.
    ///
    /// # Returns
    ///
    /// `true` if the full content must be loaded before extraction,
    /// `false` if incremental processing is supported.
    fn requires_full_load(&self) -> bool;
}
