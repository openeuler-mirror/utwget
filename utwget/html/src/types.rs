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
