//! URL parsing and manipulation module.
//!
//! This module provides URL parsing, manipulation, and conversion utilities
//! for HTTP, HTTPS, FTP, and FTPS URLs. It supports IRI (Internationalized
//! Resource Identifiers) for handling non-ASCII characters in URLs.

use crate::error::{Result, WgetError};
use crate::types::Scheme;
use crate::utils::safe_filename;
use crate::config::FilenameRestrictions;
use std::fmt;
use std::path::PathBuf;

/// A parsed URL with all its components.
///
/// This struct represents a fully parsed URL with separate fields for each
/// component: scheme, host, port, path, query string, fragment, etc.
///
/// # Example
///
/// ```
/// use ut_core::url::ParsedUrl;
///
/// let url = ParsedUrl::parse("https://example.com:8080/path?query=1#frag")?;
/// assert_eq!(url.scheme, Scheme::Https);
/// assert_eq!(url.host, "example.com");
/// assert_eq!(url.port, 8080);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParsedUrl {
    /// The original URL string as provided.
    pub original: String,
    /// The URL scheme (http, https, ftp, ftps).
    pub scheme: Scheme,
    /// The hostname or IP address.
    pub host: String,
    /// The port number.
    pub port: u16,
    /// The path component (e.g., "/path/to/resource").
    pub path: String,
    /// Optional path parameters (semicolon syntax).
    pub params: Option<String>,
    /// Optional query string (without the leading '?').
    pub query: Option<String>,
    /// Optional fragment identifier (without the leading '#').
    pub fragment: Option<String>,
    /// The directory portion of the path.
    pub dir: String,
    /// The filename portion of the path.
    pub file: String,
    /// Optional username for authentication.
    pub user: Option<String>,
    /// Optional password for authentication.
    pub password: Option<String>,
}
