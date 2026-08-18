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

/// Parse an FTP directory listing string and return a vector of [`FtpEntry`] items.
///
/// The listing format (Unix, Windows, or VMS) is automatically detected
/// from the content by sampling the first lines. If detection is ambiguous,
/// all parser strategies are attempted on each line.
///
/// # Arguments
/// * `raw` - The raw text of the FTP directory listing.
///
/// # Returns
/// A vector of parsed [`FtpEntry`] values for all recognized lines.
pub fn parse_listing(raw: &str) -> Vec<FtpEntry> {
    let lines: Vec<&str> = raw.lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .collect();

    if lines.is_empty() {
        return Vec::new();
    }

    let format = detect_format(&lines);

    match format {
        ListingFormat::Unix => lines.iter().filter_map(|l| parse_unix_entry(l)).collect(),
        ListingFormat::Windows => lines.iter().filter_map(|l| parse_windows_entry(l)).collect(),
        ListingFormat::Vms => lines.iter().filter_map(|l| parse_vms_entry(l)).collect(),
        ListingFormat::Unknown => lines.iter().filter_map(|l| {
            parse_unix_entry(l)
                .or_else(|| parse_windows_entry(l))
                .or_else(|| parse_vms_entry(l))
        }).collect(),
    }
}

/// Detect the listing format by examining a sample of the first lines.
///
/// Each line is scored against heuristics for Unix, Windows, and VMS formats.
/// The format with the highest score (most matching lines) is returned.
///
/// # Arguments
/// * `lines` - Slice of non-empty lines from the listing.
///
/// # Returns
/// The most likely [`ListingFormat`].
fn detect_format(lines: &[&str]) -> ListingFormat {
    let sample_size = lines.len().min(10);
    let mut unix = 0usize;
    let mut windows = 0usize;
    let mut vms = 0usize;

    for line in &lines[..sample_size] {
        if looks_like_unix(*line) { unix += 1; }
        if looks_like_windows(*line) { windows += 1; }
        if looks_like_vms(*line) { vms += 1; }
    }

    let max = unix.max(windows).max(vms);
    if max == 0 {
        return ListingFormat::Unknown;
    }
    if unix == max { ListingFormat::Unix }
    else if windows == max { ListingFormat::Windows }
    else { ListingFormat::Vms }
}

/// Check whether a line appears to be from a Unix-style FTP listing.
///
/// Heuristic: the first whitespace-separated token is at least 10 characters
/// long and starts with a character typical of Unix permission strings
/// (`-`, `d`, `l`, `c`, `b`, `p`, `s`).
///
/// # Arguments
/// * `line` - A single line from the listing.
///
/// # Returns
/// `true` if the line looks like a Unix-style entry.
fn looks_like_unix(line: &str) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return false;
    }
    let perms = parts[0];
    if perms.len() < 10 {
        return false;
    }
    matches!(perms.as_bytes()[0], b'-' | b'd' | b'l' | b'c' | b'b' | b'p' | b's')
}
