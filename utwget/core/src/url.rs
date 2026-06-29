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

impl ParsedUrl {
    /// Parse a URL string into its components.
    ///
    /// This function handles IRI (Internationalized Resource Identifiers) by
    /// automatically encoding non-ASCII characters to percent-encoded form.
    ///
    /// # Arguments
    ///
    /// * `input` - The URL string to parse.
    ///
    /// # Returns
    ///
    /// A `ParsedUrl` struct containing all URL components, or an error if
    /// parsing fails.
    ///
    /// # Errors
    ///
    /// Returns `WgetError::UrlParse` if the URL is malformed.
    /// Returns `WgetError::UnsupportedScheme` if the scheme is not recognized.
    ///
    /// # Example
    ///
    /// ```
    /// let url = ParsedUrl::parse("https://example.com/path")?;
    /// ```
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();

        // Encode IRI (non-ASCII characters) to percent-encoded form
        let input = encode_iri(input);

        let (scheme_str, rest) = input
            .split_once("://")
            .ok_or_else(|| WgetError::UrlParse(format!("missing scheme in URL: {}", input)))?;

        let scheme = Scheme::from_str(scheme_str)
            .ok_or_else(|| WgetError::UnsupportedScheme(scheme_str.to_string()))?;

        let slash_idx = find_unescaped_slash(rest);
        let (authority, after_slash) = if slash_idx == usize::MAX {
            (rest, "")
        } else {
            (&rest[..slash_idx], &rest[slash_idx..])
        };

        let (user, password, host_port) = parse_authority(authority)?;
        let (host, port) = parse_host_port(&host_port, scheme)?;

        let (path, query, fragment) = parse_path_query_fragment(after_slash);
        let (path_only, params) = split_params(&path);
        let path_only = if path_only.is_empty() { "/".to_string() } else { path_only };
        let dir = extract_dir(&path_only);
        let file = extract_file(&path_only);

        Ok(ParsedUrl {
            original: input.to_string(),
            scheme,
            host,
            port,
            path: path_only,
            params,
            query,
            fragment,
            dir,
            file,
            user,
            password,
        })
    }

    /// Merge a relative URL with this URL.
    ///
    /// This implements RFC 3986 URL resolution. The relative URL can be:
    /// - An absolute URL (returned as-is)
    /// - A scheme-relative URL (//host/path)
    /// - An absolute path (/path)
    /// - A query string (?query)
    /// - A fragment (#fragment)
    /// - A relative path (path)
    ///
    /// # Arguments
    ///
    /// * `relative` - The relative URL to merge.
    ///
    /// # Returns
    ///
    /// A new `ParsedUrl` representing the merged URL.
    ///
    /// # Example
    ///
    /// ```
    /// let base = ParsedUrl::parse("https://example.com/page")?;
    /// let merged = base.merge("/other")?;
    /// assert_eq!(merged.path, "/other");
    /// ```
    pub fn merge(&self, relative: &str) -> Result<Self> {
        let relative = relative.trim();

        if relative.contains("://") {
            return ParsedUrl::parse(relative);
        }

        if relative.starts_with("//") {
            let full = format!("{}:{}", self.scheme, relative);
            return ParsedUrl::parse(&full);
        }

        if relative.starts_with('/') {
            let full = format!("{}://{}:{}{}", self.scheme, self.host, self.port, relative);
            return ParsedUrl::parse(&full);
        }

        if let Some(query) = relative.strip_prefix('?') {
            let mut merged = self.clone();
            merged.query = Some(query.to_string());
            merged.params = None;
            merged.fragment = None;
            merged.original = merged.to_string();
            return Ok(merged);
        }

        if let Some(fragment) = relative.strip_prefix('#') {
            let mut merged = self.clone();
            merged.fragment = Some(fragment.to_string());
            merged.original = merged.to_string();
            return Ok(merged);
        }

        let base_dir = if self.path.ends_with('/') {
            &self.path
        } else {
            &self.dir
        };
        let separator = if base_dir.ends_with('/') || relative.starts_with('/') {
            ""
        } else {
            "/"
        };
        let new_path = format!("{}{}{}", base_dir, separator, relative);
        let full = format!("{}://{}:{}{}", self.scheme, self.host, self.port, new_path);
        ParsedUrl::parse(&full)
    }

    /// Get the full path including params and query string.
    ///
    /// Returns the path component with optional params (semicolon syntax)
    /// and query string (question mark syntax). Fragment is not included
    /// as it's client-side only.
    ///
    /// # Returns
    ///
    /// A string like "/path;params?query".
    pub fn full_path(&self) -> String {
        let mut result = self.path.clone();
        if let Some(ref p) = self.params {
            result.push(';');
            result.push_str(p);
        }
        if let Some(ref q) = self.query {
            result.push('?');
            result.push_str(q);
        }
        // Note: fragment (#) is NOT included as it's client-side only
        // and should not be sent to the server
        result
    }

    /// Convert URL to a local filename.
    ///
    /// Uses the file component of the URL path, or "index.html" if empty.
    /// The filename is sanitized to remove unsafe characters.
    ///
    /// # Arguments
    ///
    /// * `no_host_directories` - If true, don't include host in path.
    ///
    /// # Returns
    ///
    /// A `PathBuf` suitable for saving the downloaded file.
    pub fn to_filename(&self, _no_host_directories: bool) -> PathBuf {
        // Default wget behavior: download directly to current directory with just the filename
        // Only create directory structure when -x (no_host_directories=false) is NOT the default
        // Actually, wget default is to just use the filename, not create directories
        // The directory structure is created only with -x or -r options
        let name = if self.file.is_empty() { "index.html" } else { &self.file };
        PathBuf::from(safe_filename(name))
    }

    /// Convert URL to filename with OS-specific restrictions applied.
    ///
    /// Similar to `to_filename` but applies additional restrictions for
    /// cross-platform compatibility (e.g., removing characters invalid on Windows).
    ///
    /// # Arguments
    ///
    /// * `no_host_directories` - If true, don't include host in path.
    /// * `restrictions` - Filename restriction settings.
    ///
    /// # Returns
    ///
    /// A `PathBuf` with restrictions applied.
    pub fn to_filename_with_restrictions(&self, _no_host_directories: bool, restrictions: &FilenameRestrictions) -> PathBuf {
        let name = if self.file.is_empty() { "index.html" } else { &self.file };
        let safe_name = crate::utils::safe_filename_with_restrictions(
            name,
            restrictions.restrict_os,
            restrictions.restrict_ctrl_chars,
            restrictions.restrict_nonascii,
            restrictions.case_restriction,
        );
        PathBuf::from(safe_name)
    }

    /// Get a displayable string representation of the URL.
    ///
    /// # Returns
    ///
    /// A string representation suitable for display.
    pub fn display(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for ParsedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.scheme)?;
        if let Some(ref user) = self.user {
            write!(f, "{}", user)?;
            if let Some(ref pass) = self.password {
                write!(f, ":{}", pass)?;
            }
            write!(f, "@")?;
        }
        write!(f, "{}", self.host)?;
        let default_port = self.scheme.default_port();
        if self.port != default_port {
            write!(f, ":{}", self.port)?;
        }
        write!(f, "{}", self.path)?;
        if let Some(ref p) = self.params {
            write!(f, ";{}", p)?;
        }
        if let Some(ref q) = self.query {
            write!(f, "?{}", q)?;
        }
        if let Some(ref fr) = self.fragment {
            write!(f, "#{}", fr)?;
        }
        Ok(())
    }
}

/// Encode non-ASCII characters in URL for IRI support.
///
/// Converts Unicode characters to their percent-encoded UTF-8 representation.
/// This allows URLs with international characters to be properly transmitted.
///
/// # Arguments
///
/// * `url` - The URL string possibly containing non-ASCII characters.
///
/// # Returns
///
/// A new string with all non-ASCII characters percent-encoded.
///
/// # Example
///
/// ```
/// let encoded = encode_iri("https://example.com/文档");
/// assert!(encoded.contains("%"));
/// ```
pub fn encode_iri(url: &str) -> String {
    let mut result = String::with_capacity(url.len());
    for ch in url.chars() {
        if ch.is_ascii() {
            result.push(ch);
        } else {
            // Percent-encode non-ASCII characters as UTF-8 bytes
            let mut buf = [0u8; 4];
            for byte in ch.encode_utf8(&mut buf).as_bytes() {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Decode percent-encoded characters in URL for IRI support.
///
/// Converts percent-encoded sequences back to their original characters.
/// This is useful for displaying URLs with international characters.
///
/// # Arguments
///
/// * `url` - The URL string with percent-encoded sequences.
///
/// # Returns
///
/// A new string with percent-encoded sequences decoded.
///
/// # Example
///
/// ```
/// let decoded = decode_iri("https://example.com/%E6%96%87%E6%A1%A3");
/// ```
pub fn decode_iri(url: &str) -> String {
    let mut result = String::with_capacity(url.len());
    let mut chars = url.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else {
            result.push(ch);
        }
    }

    // Try to decode as UTF-8
    String::from_utf8_lossy(result.as_bytes()).to_string()
}

fn find_unescaped_slash(s: &str) -> usize {
    let mut bracket_depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => bracket_depth -= 1,
            '/' if bracket_depth == 0 => return i,
            _ => {}
        }
    }
    usize::MAX
}

fn parse_authority(authority: &str) -> Result<(Option<String>, Option<String>, String)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Ok((None, None, String::new()));
    }

    let at_idx = match authority.rfind('@') {
        Some(idx) => idx,
        None => return Ok((None, None, authority.to_string())),
    };

    let ui = &authority[..at_idx];
    let hp = &authority[at_idx + 1..];
    let (user, pass) = match ui.find(':') {
        Some(ci) => (Some(ui[..ci].to_string()), Some(ui[ci + 1..].to_string())),
        None => (Some(ui.to_string()), None),
    };
    Ok((user, pass, hp.to_string()))
}

fn parse_host_port(host_port: &str, scheme: Scheme) -> Result<(String, u16)> {
    if host_port.is_empty() {
        return Err(WgetError::UrlParse("empty host".to_string()));
    }

    let (host_str, port_str) = if host_port.starts_with('[') {
        let end_bracket = host_port
            .find(']')
            .ok_or_else(|| WgetError::UrlParse("unclosed IPv6 bracket".to_string()))?;
        let host = &host_port[1..end_bracket];
        let rest = &host_port[end_bracket + 1..];
        let port = if rest.starts_with(':') { Some(&rest[1..]) } else { None };
        (host, port)
    } else {
        match host_port.rfind(':') {
            Some(ci) => {
                let h = &host_port[..ci];
                if h.is_empty() {
                    return Err(WgetError::UrlParse("empty host".to_string()));
                }
                (h, Some(&host_port[ci + 1..]))
            }
            None => (host_port, None),
        }
    };

    let port = match port_str {
        Some(p) => p
            .parse::<u16>()
            .map_err(|_| WgetError::UrlParse(format!("invalid port: {}", p)))?,
        None => scheme.default_port(),
    };

    let host = host_str.to_string();
    if host.is_empty() {
        return Err(WgetError::UrlParse("empty host".to_string()));
    }

    Ok((host, port))
}

fn parse_path_query_fragment(input: &str) -> (String, Option<String>, Option<String>) {
    let question_idx = input.find('?').unwrap_or(usize::MAX);
    let hash_idx = input.find('#').unwrap_or(usize::MAX);
    let split_idx = question_idx.min(hash_idx);

    let (path_part, rest) = if split_idx == usize::MAX {
        (input, "")
    } else {
        (&input[..split_idx], &input[split_idx + 1..])
    };

    let path = if path_part.is_empty() {
        "/".to_string()
    } else {
        path_part.to_string()
    };

    let (query, fragment) = if question_idx < hash_idx && split_idx == question_idx {
        let after_q = rest;
        let frag_in_q = after_q.find('#').unwrap_or(usize::MAX);
        if frag_in_q < after_q.len() {
            (Some(after_q[..frag_in_q].to_string()), Some(after_q[frag_in_q + 1..].to_string()))
        } else {
            (Some(after_q.to_string()), None)
        }
    } else if split_idx == hash_idx {
        let after_h = rest;
        let q_in_h = after_h.find('?').unwrap_or(usize::MAX);
        if q_in_h < after_h.len() {
            (Some(after_h[..q_in_h].to_string()), Some(after_h[q_in_h + 1..].to_string()))
        } else {
            (None, Some(after_h.to_string()))
        }
    } else {
        (None, None)
    };

    (path, query, fragment)
}

fn split_params(path: &str) -> (String, Option<String>) {
    match path.find(';') {
        Some(si) => (path[..si].to_string(), Some(path[si + 1..].to_string())),
        None => (path.to_string(), None),
    }
}

fn extract_dir(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => {
            let mut dir = trimmed[..idx + 1].to_string();
            if !dir.ends_with('/') {
                dir.push('/');
            }
            dir
        }
        None => "/".to_string(),
    }
}

fn extract_file(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(idx) => trimmed[idx + 1..].to_string(),
        None => trimmed.to_string(),
    }
}
