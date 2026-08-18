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
