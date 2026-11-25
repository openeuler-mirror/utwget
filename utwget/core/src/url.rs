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
/// use ut_core::types::Scheme;
///
/// let url = ParsedUrl::parse("https://example.com:8080/path?query=1#frag").unwrap();
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
    /// use ut_core::url::ParsedUrl;
    ///
    /// let url = ParsedUrl::parse("https://example.com/path").unwrap();
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

        // IDN/Punycode: convert international domain names to ASCII form
        // (e.g. "münchen.de" → "xn--mnchen-3ya.de") so DNS resolution works.
        // GNU wget calls idn_encode() at url.c:957-966. We skip the
        // conversion for IP addresses (which aren't domain names).
        let host = encode_idn_host(&host);

        let (path, query, fragment) = parse_path_query_fragment(after_slash);
        let (path_only, params) = split_params(&path);
        let path_only = if path_only.is_empty() { "/".to_string() } else { path_only };
        // Normalize "." and ".." segments per RFC 3986 §5.2.4.
        // GNU wget calls path_simplify() during url_parse(); failing to do so
        // here would leave literal ".." in the path, enabling path traversal
        // when the path is mapped to a local filesystem path.
        let path_only = normalize_dot_segments(&path_only);
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
    /// use ut_core::url::ParsedUrl;
    ///
/// let base = ParsedUrl::parse("https://example.com/page").unwrap();
/// let merged = base.merge("/other").unwrap();
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
            let default_port = self.scheme.default_port();
            let port_part = if self.port != default_port {
                format!(":{}", self.port)
            } else {
                String::new()
            };
            let full = format!("{}://{}{}{}", self.scheme, self.host, port_part, relative);
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
        let normalized = normalize_dot_segments(&new_path);
        let full = format!("{}://{}:{}{}", self.scheme, self.host, self.port, normalized);
        ParsedUrl::parse(&full)
    }

    /// Normalize `.` and `..` path segments per RFC 3986 section 5.2.4.
    ///
    /// Removes `.` segments and resolves `..` segments against the preceding
    /// component. A trailing slash is preserved. This prevents `..` from
    /// appearing literally in the path, which would break output-path
    /// computation and the `--no-parent` filter.
    pub fn normalize_dot_segments(path: &str) -> String {
        normalize_dot_segments(path)
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
        // and should not be sent to the server.
        //
        // Percent-encode characters that must not appear raw in an HTTP
        // request target (spaces, control chars, DEL, raw non-ASCII bytes)
        // so they cannot break out of the request line or smuggle extra
        // requests. Existing percent-encodings (e.g. "%20") are preserved
        // because '%' is not in the encoded set, so this never double-encodes.
        encode_request_target(&result)
    }

    /// Build the `Host` header value (and CONNECT target) for this URL.
    ///
    /// - IPv6 address literals are re-wrapped in `[...]` (the parser stores
    ///   them without brackets so they can be fed directly to the resolver).
    /// - The port is appended when it differs from the scheme default.
    /// - CR/LF and other ASCII control characters are stripped as
    ///   defense-in-depth against request-line / header splitting.
    pub fn host_header(&self) -> String {
        let clean: String = self.host.chars()
            .filter(|&c| c != '\r' && c != '\n' && !c.is_ascii_control())
            .collect();
        let is_ipv6 = clean.contains(':');
        let default_port = self.scheme.default_port();
        if self.port == default_port {
            if is_ipv6 { format!("[{}]", clean) } else { clean }
        } else if is_ipv6 {
            format!("[{}]:{}", clean, self.port)
        } else {
            format!("{}:{}", clean, self.port)
        }
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
    /// Credentials are masked to prevent leaking in logs/stderr.
    /// Use `display_with_credentials()` if you need the full URL with
    /// credentials (e.g. for internal HTTP request construction).
    pub fn display(&self) -> String {
        self.display_safe()
    }

    /// Get the full URL with credentials included (no masking).
    ///
    /// This should only be used where the raw URL with credentials is
    /// genuinely needed (e.g. HTTP request-target, proxy connections).
    /// For all user-visible output (logs, stderr, progress), use
    /// `display()` or `display_safe()` instead.
    pub fn display_with_credentials(&self) -> String {
        let mut result = format!("{}://", self.scheme);
        if let Some(ref user) = self.user {
            result.push_str(user);
            if let Some(ref pass) = self.password {
                result.push(':');
                result.push_str(pass);
            }
            result.push('@');
        }
        result.push_str(&self.host);
        let default_port = self.scheme.default_port();
        if self.port != default_port {
            result.push_str(&format!(":{}", self.port));
        }
        result.push_str(&self.path);
        if let Some(ref p) = self.params {
            result.push_str(&format!(";{}", p));
        }
        if let Some(ref q) = self.query {
            result.push_str(&format!("?{}", q));
        }
        if let Some(ref fr) = self.fragment {
            result.push_str(&format!("#{}", fr));
        }
        result
    }

    /// Get a log-safe string representation with credentials masked.
    ///
    /// Credentials (user:password) are replaced with `***:***` to prevent
    /// leaking sensitive information in debug/log output.
    pub fn display_safe(&self) -> String {
        let mut result = format!("{}://", self.scheme);
        if self.user.is_some() {
            result.push_str("***:***@");
        }
        result.push_str(&self.host);
        let default_port = self.scheme.default_port();
        if self.port != default_port {
            result.push_str(&format!(":{}", self.port));
        }
        result.push_str(&self.path);
        if let Some(ref q) = self.query {
            result.push_str(&format!("?{}", q));
        }
        if let Some(ref fr) = self.fragment {
            result.push_str(&format!("#{}", fr));
        }
        result
    }
}

impl fmt::Display for ParsedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display masks credentials to prevent leaking in logs/stderr.
        // Use display_with_credentials() for internal HTTP request construction.
        write!(f, "{}://", self.scheme)?;
        if self.user.is_some() {
            write!(f, "***:***@")?;
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
/// use ut_core::url::encode_iri;
///
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

/// Convert an internationalized domain name (IDN) to Punycode (ASCII) form.
///
/// Mirrors GNU wget's `idn_encode()` (url.c:957-966). If the host contains
/// non-ASCII characters, the `idna` crate converts each label to its
/// `xn--` Punycode representation. IP addresses and pure-ASCII hosts are
/// returned unchanged.
///
/// Falls back to the original host if the `idna` feature is disabled or
/// the conversion fails (to avoid breaking existing ASCII URLs).
/// Convert an IDN hostname to ASCII punycode (RFC 3492).
///
/// Public helper so TLS layers (SNI / rustls `ServerName`) can accept
/// Unicode hostnames: rustls' `ServerName::try_from` rejects non-ASCII,
/// while wget+GnuTLS converts via idna before the handshake (M19).
/// IP addresses and already-ASCII names pass through unchanged;
/// conversion failure falls back to the input.
#[cfg(feature = "idn")]
pub fn to_punycode(host: &str) -> String {
    encode_idn_host(host)
}

#[cfg(feature = "idn")]
fn encode_idn_host(host: &str) -> String {
    // Skip IP addresses (they're not domain names).
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    // Skip if already ASCII (no IDN conversion needed).
    if host.is_ascii() {
        return host.to_string();
    }
    match idna::domain_to_ascii(host) {
        Ok(punycode) => {
            log::debug!("IDN: {} → {}", host, punycode);
            punycode
        }
        Err(e) => {
            log::warn!("IDN: failed to convert '{}': {:?}; using as-is", host, e);
            host.to_string()
        }
    }
}

#[cfg(not(feature = "idn"))]
fn encode_idn_host(host: &str) -> String {
    host.to_string()
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
/// use ut_core::url::decode_iri;
///
/// let decoded = decode_iri("https://example.com/%E6%96%87%E6%A1%A3");
/// ```
pub fn decode_iri(url: &str) -> String {
    let mut result: Vec<u8> = Vec::with_capacity(url.len());
    let mut chars = url.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            let mut hex = String::with_capacity(2);
            // Collect up to 2 hex digits; stop early if non-hex or end of string
            while hex.len() < 2 {
                match chars.peek() {
                    Some(c) if c.is_ascii_hexdigit() => {
                        hex.push(*c);
                        chars.next();
                    }
                    _ => break,
                }
            }
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte);
                } else {
                    result.push(b'%');
                    result.extend_from_slice(hex.as_bytes());
                }
            } else {
                // Not enough hex digits after %, output literally
                result.push(b'%');
                result.extend_from_slice(hex.as_bytes());
            }
        } else {
            result.extend_from_slice(ch.encode_utf8(&mut [0u8; 4]).as_bytes());
        }
    }

    String::from_utf8_lossy(&result).to_string()
}

fn find_unescaped_slash(s: &str) -> usize {
    let mut bracket_depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => {
                bracket_depth -= 1;
                // Prevent negative depth (malformed URL like "]foo[")
                if bracket_depth < 0 {
                    bracket_depth = 0;
                }
            }
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
    if ui.is_empty() {
        return Ok((None, None, hp.to_string()));
    }
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
    } else if hash_idx != usize::MAX && split_idx == hash_idx {
        // RFC 3986: everything after # is fragment, ? inside fragment is literal.
        // Note: the `hash_idx != usize::MAX` guard matters — without it, a URL
        // with neither '?' nor '#' takes this branch and yields
        // `fragment: Some("")`, which serializes back with a spurious
        // trailing '#' (seen in WARC-Target-URI / CDX output).
        (None, Some(rest.to_string()))
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
    // A trailing slash means the path refers to a directory; the entire path
    // (minus the trailing slash) is the directory. Otherwise, the directory
    // is everything up to and including the last '/'.
    if path.ends_with('/') {
        // Directory path: e.g. "/a/b/" -> dir "/a/b/", "/foo/" -> dir "/foo/"
        let trimmed = path.trim_end_matches('/');
        match trimmed.rfind('/') {
            Some(idx) => {
                // idx is the position of the last '/' in the trimmed path.
                // For "/foo" -> idx=0, dir becomes "/foo/".
                // For "/a/b" -> idx=2, dir becomes "/a/b/".
                let mut dir = trimmed[..idx + 1].to_string();
                let last = &trimmed[idx + 1..];
                if !last.is_empty() {
                    dir.push_str(last);
                    dir.push('/');
                }
                dir
            }
            None => "/".to_string(),
        }
    } else {
        // File path: e.g. "/a/b/file.html" -> dir "/a/b/"
        match path.rfind('/') {
            Some(0) => "/".to_string(),
            Some(idx) => path[..idx + 1].to_string(),
            None => "/".to_string(),
        }
    }
}

fn extract_file(path: &str) -> String {
    // A trailing slash means the path refers to a directory with no filename
    // component. The caller will substitute "index.html" as needed.
    if path.ends_with('/') {
        return String::new();
    }
    match path.rfind('/') {
        Some(idx) => path[idx + 1..].to_string(),
        None => path.to_string(),
    }
}


/// Normalize `.` and `..` segments in a URL path (RFC 3986 §5.2.4).
///
/// - `.` segments are removed
/// - `..` segments remove the preceding component
/// - A trailing slash is preserved
/// - Leading `..` that would escape above root are dropped
fn normalize_dot_segments(path: &str) -> String {
    let leading_slash = path.starts_with('/');
    let trailing_slash = path.ends_with('/') && path != "/";

    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut out: Vec<&str> = Vec::new();
    for seg in &segments {
        match *seg {
            "." => continue,
            ".." => {
                if let Some(last) = out.last() {
                    if *last != ".." {
                        out.pop();
                    }
                } else if leading_slash {
                    // ".." above root for rooted paths: drop it
                    continue;
                } else {
                    // Relative path: keep ".." as-is
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }

    let joined = out.join("/");
    let mut result = String::new();
    if leading_slash {
        result.push('/');
    }
    result.push_str(&joined);
    if trailing_slash && !result.ends_with('/') {
        result.push('/');
    }
    if result.is_empty() {
        result.push('/');
    }
    result
}

/// Percent-encode characters that must not appear raw in an HTTP request
/// target (RFC 9110): ASCII spaces, C0 control characters (0x00-0x1F), DEL
/// (0x7F), and raw non-ASCII bytes (0x80-0xFF). Already-percent-encoded
/// sequences such as `%20` are preserved because `%` is ASCII and outside the
/// encoded set, so this never double-encodes.
pub fn encode_request_target(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b' ' => out.push_str("%20"),
            0x00..=0x1f | 0x7f | 0x80..=0xff => out.push_str(&format!("%{:02X}", b)),
            _ => out.push(b as char),
        }
    }
    out
}

#[cfg(test)]
mod request_target_tests {
    use super::encode_request_target;

    #[test]
    fn normal_path_is_unchanged() {
        assert_eq!(encode_request_target("/path/to/file"), "/path/to/file");
        assert_eq!(encode_request_target("/path;params?q=1&a=b"), "/path;params?q=1&a=b");
    }

    #[test]
    fn existing_percent_encoding_is_preserved() {
        assert_eq!(encode_request_target("/a%20b"), "/a%20b");
        assert_eq!(encode_request_target("/%0d%0a"), "/%0d%0a");
    }

    #[test]
    fn raw_space_is_encoded() {
        assert_eq!(encode_request_target("/a b"), "/a%20b");
    }

    #[test]
    fn raw_crlf_is_encoded() {
        assert_eq!(encode_request_target("/a\r\nb"), "/a%0D%0Ab");
    }

    #[test]
    fn control_chars_are_encoded() {
        assert_eq!(encode_request_target("/a\tb\x00c"), "/a%09b%00c");
    }
}

#[cfg(test)]
mod host_header_tests {
    use super::ParsedUrl;

    #[test]
    fn plain_host_default_port() {
        let url = ParsedUrl::parse("http://example.com/path").unwrap();
        assert_eq!(url.host_header(), "example.com");
    }

    #[test]
    fn plain_host_nondefault_port() {
        let url = ParsedUrl::parse("http://example.com:8080/path").unwrap();
        assert_eq!(url.host_header(), "example.com:8080");
    }

    #[test]
    fn ipv6_default_port_is_bracketed() {
        let url = ParsedUrl::parse("http://[::1]/path").unwrap();
        assert_eq!(url.host_header(), "[::1]");
    }

    #[test]
    fn ipv6_nondefault_port_is_bracketed() {
        let url = ParsedUrl::parse("http://[::1]:8080/path").unwrap();
        assert_eq!(url.host_header(), "[::1]:8080");
    }

    #[test]
    fn ipv6_https_default_port() {
        let url = ParsedUrl::parse("https://[2001:db8::1]/path").unwrap();
        assert_eq!(url.host_header(), "[2001:db8::1]");
    }
}
