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

/// Returns the default list of tags to follow for URL extraction.
///
/// Includes all standard HTML elements that can contain URLs.
fn default_follow_tags() -> Vec<String> {
    vec![
        "a".into(),
        "area".into(),
        "link".into(),
        "img".into(),
        "script".into(),
        "iframe".into(),
        "frame".into(),
        "embed".into(),
        "object".into(),
        "source".into(),
        "track".into(),
        "video".into(),
        "body".into(),
        "applet".into(),
        "meta".into(),
        "base".into(),
    ]
}

/// Options controlling URL extraction behavior.
///
/// These options determine which elements are processed during URL extraction
/// from HTML documents.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Whether to follow URLs in `<base>` elements.
    pub follow_base: bool,
    /// Tags to ignore during extraction.
    ///
    /// URLs in these elements will not be extracted.
    pub ignore_tags: Vec<String>,
    /// Tags to follow during extraction.
    ///
    /// Only URLs in these elements will be extracted.
    /// If empty, all tags with URL attributes are processed.
    pub follow_tags: Vec<String>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            follow_base: true,
            ignore_tags: Vec::new(),
            follow_tags: default_follow_tags(),
        }
    }
}
