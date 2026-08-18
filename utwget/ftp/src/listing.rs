use chrono::{DateTime, Datelike, TimeZone, Utc};

/// Represents a single entry parsed from an FTP directory listing.
///
/// Each entry corresponds to one file or directory returned by the FTP `LIST` or `MLSD` command.
#[derive(Debug, Clone)]
pub struct FtpEntry {
    /// The name of the file or directory.
    pub name: String,
    /// Whether this entry is a directory rather than a regular file.
    pub is_dir: bool,
    /// The size of the file in bytes, if available from the listing.
    pub size: Option<u64>,
    /// The modification date and time of the entry, if available.
    pub date: Option<DateTime<Utc>>,
    /// The permission string (e.g., `-rw-r--r--` for Unix listings), if available.
    pub perms: Option<String>,
    /// The owner of the entry, if available from the listing.
    pub owner: Option<String>,
    /// The group of the entry, if available from the listing.
    pub group: Option<String>,
}

/// Identifies the format style of an FTP directory listing.
///
/// FTP servers return listings in various formats depending on the server platform.
/// This enum is used to select the appropriate parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingFormat {
    /// Unix-style listing (e.g., `-rw-r--r--  1 user group 1024 Jan 15 10:30 file.txt`).
    Unix,
    /// Windows-style listing (e.g., `01-15-2025  10:30AM       <DIR>          docs`).
    Windows,
    /// VMS-style listing (e.g., `FILE.TXT;1 1024 15-JAN-2025 10:30`).
    Vms,
    /// The listing format could not be determined from the available content.
    Unknown,
}
