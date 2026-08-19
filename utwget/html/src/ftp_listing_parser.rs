//! FTP directory listing parser and HTML converter.
//!
//! This module provides functionality to convert FTP directory listings
//! to HTML format for recursive downloading support.

/// Represents a single entry in an FTP directory listing.
///
/// Contains metadata about a file or directory retrieved from an FTP server.
#[derive(Debug, Clone)]
pub struct FtpEntry {
    /// The name of the file or directory.
    pub name: String,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// The size of the file in bytes (0 for directories).
    pub size: u64,
    /// The modification date string as returned by the server.
    pub date: String,
    /// The permission string (e.g., "rw-r--r--").
    pub permissions: String,
    /// The owner name.
    pub owner: String,
    /// The group name.
    pub group: String,
}
