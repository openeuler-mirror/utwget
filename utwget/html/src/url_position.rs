//! URL position tracking for link extraction.
//!
//! This module defines types for tracking URLs found in content and their
//! characteristics, such as link type and whether they are inline resources.

/// Represents the type of link found in content.
///
/// Different link types require different handling during recursive downloading
/// and link conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Relative URL that needs to be resolved against a base URL.
    Relative,
    /// Absolute URL with a complete scheme and host.
    Absolute,
    /// CSS @import directive URL.
    CssImport,
    /// Meta refresh redirect URL.
    RefreshRedirect,
    /// Base element href attribute value.
    BaseHref,
}

/// Represents a URL found in content with its associated metadata.
///
/// This structure captures all relevant information about a URL discovered
/// during content parsing, including its type, location, and expected content.
#[derive(Debug, Clone)]
pub struct UrlPosition {
    /// The URL string as found in the content.
    pub url: String,
    /// The type of link (relative, absolute, CSS import, etc.).
    pub link_type: LinkType,
    /// Whether this is an inline resource (images, scripts, stylesheets).
    pub inline: bool,
    /// The HTML attribute name containing the URL, if applicable.
    pub attr_name: Option<String>,
    /// Whether the linked content is expected to be HTML.
    pub expect_html: bool,
    /// Whether the linked content is expected to be CSS.
    pub expect_css: bool,
    /// Whether a meta robots nofollow directive disallows following this link.
    pub meta_disallow_follow: bool,
}
