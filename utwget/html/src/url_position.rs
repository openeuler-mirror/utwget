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
