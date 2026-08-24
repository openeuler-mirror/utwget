//! Extended attributes (xattr) support for downloaded files.
//!
//! This module provides functionality to store metadata in file extended attributes,
//! compatible with GNU wget's `--xattr` option. On Linux, this uses the `user`
//! namespace for xattr keys.
//!
//! # Stored Attributes
//!
//! - `user.xdg.origin.url`: The original download URL
//! - `user.xdg.content.type`: The Content-Type from the server
//! - `user.wget.last_modified`: The Last-Modified timestamp
//! - `user.wget.etag`: The ETag from the server
//!
//! # Example
//!
//! ```no_run
//! use ut_retriever::xattr::{FileMetadata, set_xattr};
//! use std::path::Path;
//!
//! let metadata = FileMetadata {
//!     url: "http://example.com/file.txt".to_string(),
//!     content_type: Some("text/plain".to_string()),
//!     last_modified: None,
//!     etag: None,
//! };
//! set_xattr(Path::new("file.txt"), &metadata).ok();
//! ```

use std::path::Path;
use std::io;

/// Metadata to store in extended attributes.
///
/// This struct holds the metadata that will be written to a file's
/// extended attributes when `--xattr` is enabled.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Original URL from which the file was downloaded.
    pub url: String,
    /// Content-Type header value from the server response.
    pub content_type: Option<String>,
    /// Last-Modified timestamp from the server, formatted as RFC 2822.
    pub last_modified: Option<String>,
    /// ETag header value from the server response.
    pub etag: Option<String>,
}
