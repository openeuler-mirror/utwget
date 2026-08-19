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

/// Converts FTP directory entries to an HTML listing.
///
/// Generates a simple HTML page with links for each FTP entry.
/// Directories are shown with a trailing slash.
///
/// # Arguments
///
/// * `entries` - Slice of FTP entries to convert.
///
/// # Returns
///
/// An HTML string containing links to each entry.
///
/// # Example
///
/// ```
/// use ut_html::ftp_listing_parser::{FtpEntry, ftp_listing_to_html};
///
/// let entries = vec![
///     FtpEntry {
///         name: "docs".to_string(),
///         is_dir: true,
///         size: 0,
///         date: "2024-01-01".to_string(),
///         permissions: "rwxr-xr-x".to_string(),
///         owner: "user".to_string(),
///         group: "group".to_string(),
///     },
/// ];
///
/// let html = ftp_listing_to_html(&entries);
/// assert!(html.contains("<a href=\"docs/\">docs/</a>"));
/// ```
pub fn ftp_listing_to_html(entries: &[FtpEntry]) -> String {
    let mut html = String::from("<html><head><title>FTP Directory Listing</title></head><body>\n");

    html.push_str("<pre>\n");

    for entry in entries {
        if entry.is_dir {
            html.push_str(&format!(
                "<a href=\"{}/\">{}/</a>\n",
                escape_html(&entry.name),
                escape_html(&entry.name)
            ));
        } else {
            html.push_str(&format!(
                "<a href=\"{}\">{}</a>\n",
                escape_html(&entry.name),
                escape_html(&entry.name)
            ));
        }
    }

    html.push_str("</pre>\n");
    html.push_str("</body></html>");

    html
}
