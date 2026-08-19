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

/// Check whether a line appears to be from a Windows-style FTP listing.
///
/// Heuristic: the line starts with a date in `MM-DD-YYYY` format (hyphens at
/// positions 2 and 5) followed by a space before the time portion.
///
/// # Arguments
/// * `line` - A single line from the listing.
///
/// # Returns
/// `true` if the line looks like a Windows-style entry.
fn looks_like_windows(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.len() < 18 {
        return false;
    }
    let bytes = trimmed.as_bytes();
    (bytes[2] == b'-' || bytes[5] == b'-')
        && (bytes[10] == b' ' || bytes[11] == b' ')
}

/// Check whether a line appears to be from a VMS-style FTP listing.
///
/// Heuristic: the line contains a `;` (version separator) together with
/// brackets (`[` or `]`) or the word "Directory".
///
/// # Arguments
/// * `line` - A single line from the listing.
///
/// # Returns
/// `true` if the line looks like a VMS-style entry.
fn looks_like_vms(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.contains(';') && (trimmed.contains('[') || trimmed.contains(']'))
        || trimmed.contains("Directory")
}

/// Parse a Unix-style FTP directory listing and return a vector of [`FtpEntry`] items.
///
/// This is a convenience wrapper around [`parse_unix_entry`] that processes all non-empty lines.
///
/// # Arguments
/// * `raw` - The raw text of a Unix-style FTP listing.
///
/// # Returns
/// A vector of parsed [`FtpEntry`] values.
pub fn parse_unix_listing(raw: &str) -> Vec<FtpEntry> {
    raw.lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .filter_map(parse_unix_entry)
        .collect()
}

/// Parse a single line of a Unix-style FTP listing into an [`FtpEntry`].
///
/// Expects the standard `ls -l` format with at least 8 whitespace-separated tokens:
/// `permissions links owner group size month day [year|time] filename`.
///
/// # Arguments
/// * `line` - A single Unix listing line.
///
/// # Returns
/// `Some(FtpEntry)` if the line could be parsed, or `None` if it is malformed.
fn parse_unix_entry(line: &str) -> Option<FtpEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 8 {
        return None;
    }

    let perms = parts[0].to_string();
    let is_dir = perms.as_bytes()[0] == b'd';
    let owner = parts[2].to_string();
    let group = parts[3].to_string();
    let size: u64 = parts[4].parse().ok()?;

    let date_str = format!("{} {} {}", parts[5], parts[6], parts[7]);
    let date = parse_unix_date(&date_str);

    let name: String = if parts.len() > 9 && parts[8] == "->" {
        parts[9..].join(" ")
    } else {
        parts[8..].join(" ")
    };

    Some(FtpEntry {
        name,
        is_dir,
        size: Some(size),
        date,
        perms: Some(perms),
        owner: Some(owner),
        group: Some(group),
    })
}

/// Parse a Unix date/time string (e.g., `"Jan 15 10:30"` or `"Jan 15 2025"`) into a UTC [`DateTime`].
///
/// If the token after the day is a four-digit year, it is used directly.
/// Otherwise it is treated as `HH:MM` and the current year is assumed, with a
/// one-year rollback if the resulting date is in the future.
///
/// # Arguments
/// * `s` - A three-part date string (`Mon DD YYYY` or `Mon DD HH:MM`).
///
/// # Returns
/// `Some(DateTime<Utc>)` on success, `None` if the string is malformed.
fn parse_unix_date(s: &str) -> Option<DateTime<Utc>> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 3 {
        return None;
    }

    let month = month_to_num(parts[0])?;
    let day: u32 = parts[1].parse().ok()?;

    if let Ok(year) = parts[2].parse::<i32>() {
        return Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single();
    }

    let time_parts: Vec<&str> = parts[2].split(':').collect();
    if time_parts.len() != 2 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;

    let now = Utc::now();
    let mut year = now.year();
    let file_date = Utc.with_ymd_and_hms(year, month, day, hour, minute, 0).single()?;

    if file_date > now {
        year -= 1;
        Utc.with_ymd_and_hms(year, month, day, hour, minute, 0).single()
    } else {
        Some(file_date)
    }
}

/// Convert a three-letter English month abbreviation to its numeric value (1-12).
///
/// # Arguments
/// * `s` - The month abbreviation (case-insensitive), e.g. `"Jan"`, `"FEB"`, `"mar"`.
///
/// # Returns
/// `Some(u32)` between 1 and 12, or `None` if the abbreviation is not recognised.
fn month_to_num(s: &str) -> Option<u32> {
    match s.to_ascii_lowercase().as_str() {
        "jan" => Some(1), "feb" => Some(2), "mar" => Some(3),
        "apr" => Some(4), "may" => Some(5), "jun" => Some(6),
        "jul" => Some(7), "aug" => Some(8), "sep" => Some(9),
        "oct" => Some(10), "nov" => Some(11), "dec" => Some(12),
        _ => None,
    }
}

/// Parse a Windows-style FTP directory listing and return a vector of [`FtpEntry`] items.
///
/// This is a convenience wrapper around [`parse_windows_entry`] that processes all non-empty lines.
///
/// # Arguments
/// * `raw` - The raw text of a Windows-style FTP listing.
///
/// # Returns
/// A vector of parsed [`FtpEntry`] values.
pub fn parse_windows_listing(raw: &str) -> Vec<FtpEntry> {
    raw.lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .filter_map(parse_windows_entry)
        .collect()
}

/// Parse a single line of a Windows-style FTP listing into an [`FtpEntry`].
///
/// Expects the format: `MM-DD-YYYY  HH:MM[AP]M  [<DIR> | <size>]  name`.
///
/// # Arguments
/// * `line` - A single Windows listing line.
///
/// # Returns
/// `Some(FtpEntry)` if the line could be parsed, or `None` if it is malformed.
fn parse_windows_entry(line: &str) -> Option<FtpEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Windows format: MM-DD-YYYY  HH:MM[AP]M  [size or <DIR>]  name
    // Example: 01-15-2025  10:30AM       <DIR>          docs
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let date_str = parts.get(0)?;
    let time_str = parts.get(1)?;

    // Check if it's a directory
    let is_dir = parts.get(2).map(|s| *s == "<DIR>").unwrap_or(false);

    let (name, size) = if is_dir {
        let name = parts.get(3..).map(|s| s.join(" ")).unwrap_or_default();
        (name, None)
    } else {
        // File: size is in position 2, name starts from position 3
        let size: Option<u64> = parts.get(2).and_then(|s| s.parse().ok());
        let name = parts.get(3..).map(|s| s.join(" ")).unwrap_or_default();
        (name, size)
    };

    if name.is_empty() {
        return None;
    }

    let date = parse_windows_datetime(date_str, time_str);

    Some(FtpEntry {
        name,
        is_dir,
        size,
        date,
        perms: None,
        owner: None,
        group: None,
    })
}

/// Parse a Windows date and time string into a UTC [`DateTime`].
///
/// Date format: `MM-DD-YYYY`. Time format: `HH:MM[AP]M` (12-hour clock with AM/PM).
///
/// # Arguments
/// * `date_str` - The date portion, e.g. `"01-15-2025"`.
/// * `time_str` - The time portion, e.g. `"10:30AM"`.
///
/// # Returns
/// `Some(DateTime<Utc>)` if both strings are valid, `None` otherwise.
fn parse_windows_datetime(date_str: &str, time_str: &str) -> Option<DateTime<Utc>> {
    // Date format: MM-DD-YYYY
    let date_parts: Vec<&str> = date_str.split('-').collect();
    if date_parts.len() != 3 {
        return None;
    }

    let month: u32 = date_parts[0].parse().ok()?;
    let day: u32 = date_parts[1].parse().ok()?;
    let year: i32 = date_parts[2].parse().ok()?;

    // Time format: HH:MM[AP]M or HH:MM:SS[AP]M
    let time_upper = time_str.to_ascii_uppercase();
    let is_pm = time_upper.ends_with("PM");
    let is_am = time_upper.ends_with("AM");

    let time_clean = time_upper.trim_end_matches("AM").trim_end_matches("PM");
    let time_parts: Vec<&str> = time_clean.split(':').collect();

    if time_parts.is_empty() {
        return None;
    }

    let hour_raw: u32 = time_parts.get(0)?.parse().ok()?;
    let minute: u32 = time_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let hour = if is_pm && hour_raw != 12 {
        hour_raw + 12
    } else if is_am && hour_raw == 12 {
        0
    } else {
        hour_raw
    };

    Utc.with_ymd_and_hms(year, month, day, hour, minute, 0).single()
}

/// Parse a VMS-style FTP directory listing and return a vector of [`FtpEntry`] items.
///
/// This is a convenience wrapper around [`parse_vms_entry`] that processes all non-empty lines.
///
/// # Arguments
/// * `raw` - The raw text of a VMS-style FTP listing.
///
/// # Returns
/// A vector of parsed [`FtpEntry`] values.
pub fn parse_vms_listing(raw: &str) -> Vec<FtpEntry> {
    raw.lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .filter_map(parse_vms_entry)
        .collect()
}

/// Parse a single line of a VMS-style FTP listing into an [`FtpEntry`].
///
/// VMS entries typically look like `FILE.TXT;1 1024 15-JAN-2025 10:30`.
/// Lines starting with "Directory" or "Total" are skipped as headers/summaries.
/// Files ending in `.DIR` are treated as directories.
///
/// # Arguments
/// * `line` - A single VMS listing line.
///
/// # Returns
/// `Some(FtpEntry)` if the line could be parsed, or `None` if it is a header/summary line.
fn parse_vms_entry(line: &str) -> Option<FtpEntry> {
    let trimmed = line.trim();

    if trimmed.starts_with("Directory") || trimmed.starts_with("Total") {
        return None;
    }

    if let Some(idx) = trimmed.find(';') {
        let name_part = &trimmed[..idx];
        let is_dir = name_part.ends_with(".DIR") || name_part.ends_with(".dir");
        let name = if is_dir {
            let dir_name = &name_part[..name_part.len() - 4];
            dir_name.to_string()
        } else {
            name_part.to_string()
        };

        let rest = &trimmed[idx..];
        let size: Option<u64> = rest.split_whitespace()
            .skip(1)
            .next()
            .and_then(|s| s.parse().ok());

        let date = parse_vms_date(rest);

        Some(FtpEntry {
            name,
            is_dir,
            size,
            date,
            perms: None,
            owner: None,
            group: None,
        })
    } else {
        let name = trimmed.to_string();
        let is_dir = name.ends_with(".DIR") || name.ends_with(".dir");
        Some(FtpEntry {
            name,
            is_dir,
            size: None,
            date: None,
            perms: None,
            owner: None,
            group: None,
        })
    }
}

/// Parse a VMS date-time string from the remainder of a listing line.
///
/// Scans whitespace-separated tokens for a date in `DD-Mon-YYYY` format and,
/// if available, the following token for a time in `HH:MM` format.
///
/// # Arguments
/// * `s` - The portion of the VMS listing line after the file name and version.
///
/// # Returns
/// `Some(DateTime<Utc>)` if a valid date token is found, `None` otherwise.
fn parse_vms_date(s: &str) -> Option<DateTime<Utc>> {
    let tokens: Vec<&str> = s.split_whitespace().collect();

    for (i, token) in tokens.iter().enumerate() {
        let date_opt = parse_vms_date_token(token);
        if date_opt.is_some() {
            let time_opt = if i + 1 < tokens.len() {
                parse_vms_time_token(tokens[i + 1])
            } else {
                None
            };
            let (year, month, day) = date_opt.unwrap();
            let (hour, minute) = time_opt.unwrap_or((0, 0));
            return Utc.with_ymd_and_hms(year, month, day, hour, minute, 0).single();
        }
    }

    None
}

/// Parse a VMS date token in `DD-Mon-YYYY` format.
///
/// # Arguments
/// * `s` - A token such as `"15-JAN-2025"`.
///
/// # Returns
/// `Some((year, month, day))` on success, or `None` if the token is malformed.
fn parse_vms_date_token(s: &str) -> Option<(i32, u32, u32)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }

    let day: u32 = parts[0].parse().ok()?;
    let month = month_abbrev_to_num(parts[1])?;
    let year: i32 = parts[2].parse().ok()?;
    Some((year, month, day))
}
