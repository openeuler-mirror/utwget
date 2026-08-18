//! Utility functions for file retrieval.
//!
//! This module contains helper functions for file operations, proxy handling,
//! retry logic, and content disposition parsing.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use log::{debug, warn};
use ut_core::url::ParsedUrl;
use ut_core::{Config, Scheme, WgetError};
use ut_http::HeaderMap;
use ut_http::request::HttpRequest;

use crate::types::RetrieveError;

/// Headers whose values may carry credentials or session tokens. When logging
/// raw HTTP requests for `--debug`, these values are replaced with a placeholder
/// so that sharing debug logs does not leak credentials (Basic/Digest/NTLM auth,
/// cookies, proxy auth).
const SENSITIVE_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// Redact sensitive header values in a serialized HTTP request/response string
/// for safe `--debug` logging.
///
/// Each sensitive header line has its value replaced with `<redacted>`. Header
/// names and structure (CRLF, leading/trailing lines) are preserved so the log
/// remains useful for debugging request shape.
pub(crate) fn redact_sensitive_headers(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        // A header line looks like "Name: value\r\n". Split on the first ':'.
        // Be tolerant of leading whitespace (obs-fold), but only redact when the
        // trimmed name matches a known sensitive header.
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_ascii_lowercase();
            if SENSITIVE_HEADER_NAMES.contains(&name.as_str()) {
                // Preserve line ending if present.
                let ending = if line.ends_with("\r\n") {
                    "\r\n"
                } else if line.ends_with('\n') {
                    "\n"
                } else {
                    ""
                };
                out.push_str(&line[..=colon]);
                out.push(' ');
                out.push_str("<redacted>");
                out.push_str(ending);
                continue;
            }
        }
        out.push_str(line);
    }
    out
}

/// Information about a proxy server.
pub(crate) struct ProxyInfo {
    /// Proxy hostname.
    pub host: String,
    /// Proxy TCP port.
    pub port: u16,
}

/// Resolve the proxy configuration for a given URL.
///
/// Parse a proxy URL string into host and port.
///
/// Supports formats:
/// - `http://host:port`
/// - `host:port`
/// - `host`
fn parse_proxy_url(proxy: &str) -> (String, u16) {
    // Remove scheme prefix if present
    let addr = proxy
        .strip_prefix("http://")
        .or_else(|| proxy.strip_prefix("https://"))
        .or_else(|| proxy.strip_prefix("socks5://"))
        .unwrap_or(proxy);
    
    // Parse host:port
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = port_str.parse::<u16>().unwrap_or(8080);
        (host.to_string(), port)
    } else {
        (addr.to_string(), 8080)
    }
}

/// Returns the proxy host and port based on the URL scheme and the
/// corresponding proxy setting (`--http-proxy`, `--https-proxy`, `--ftp-proxy`).
pub(crate) fn resolve_proxy(url: &ParsedUrl, config: &Config) -> ProxyInfo {
    match url.scheme {
        Scheme::Http => {
            let proxy_str = config.proxy.http_proxy.as_deref().unwrap_or("");
            let (host, port) = parse_proxy_url(proxy_str);
            ProxyInfo { host, port }
        }
        Scheme::Https => {
            let proxy_str = config.proxy.https_proxy.as_deref().unwrap_or("");
            let (host, port) = parse_proxy_url(proxy_str);
            ProxyInfo { host, port }
        }
        Scheme::Ftp | Scheme::Ftps => {
            let proxy_str = config.proxy.ftp_proxy.as_deref().unwrap_or("");
            let (host, port) = parse_proxy_url(proxy_str);
            ProxyInfo { host, port }
        }
    }
}

/// Check if a URL should use a proxy based on the configuration.
pub(crate) fn is_url_proxied(url: &ParsedUrl, config: &Config) -> bool {
    if !config.proxy.use_proxy {
        return false;
    }

    // Check if a proxy is actually configured for this scheme
    let proxy_configured = match url.scheme {
        Scheme::Http => config.proxy.http_proxy.is_some(),
        Scheme::Https => config.proxy.https_proxy.is_some(),
        Scheme::Ftp | Scheme::Ftps => config.proxy.ftp_proxy.is_some(),
    };
    if !proxy_configured {
        return false;
    }

    // Check --no-proxy domains
    let host = url.host.as_str();
    for domain in &config.proxy.no_proxy {
        let domain = domain.trim();
        if domain == host || (domain.starts_with('.') && host.ends_with(domain)) {
            return false;
        }
    }

    true
}

/// Check if an error is retryable based on configuration.
pub(crate) fn is_retryable(err: &RetrieveError, config: &Config) -> bool {
    match err {
        RetrieveError::Protocol(e) => {
            if e.is_retryable() {
                return true;
            }
            match e {
                WgetError::ConnectionRefused => config.retry_connrefused,
                WgetError::HostNotFound(_) => config.retry_on_host_error,
                _ => false,
            }
        }
        RetrieveError::Response(e) => {
            if let WgetError::Http { status, .. } = e {
                return config.retry_on_http_error.iter().any(|&s| s == *status);
            }
            false
        }
        _ => false,
    }
}

/// Rotate backup files before writing.
///
/// For example, with n_backups=3:
///   file.2 -> file.3 (delete if exists)
///   file.1 -> file.2
///   file   -> file.1
pub(crate) fn rotate_backups(path: &Path, n_backups: u32) {
    if !path.exists() {
        return;
    }
    if let Ok(metadata) = fs::metadata(path) {
        if !metadata.is_file() {
            return;
        }
    }

    for i in (2..=n_backups).rev() {
        let from = format!("{}.{}", path.display(), i - 1);
        let to = format!("{}.{}", path.display(), i);
        let from_path = PathBuf::from(&from);
        let to_path = PathBuf::from(&to);

        if i == n_backups && to_path.exists() {
            let _ = fs::remove_file(&to_path);
        }

        if from_path.exists() {
            if let Err(e) = fs::rename(&from_path, &to_path) {
                if e.kind() != io::ErrorKind::NotFound {
                    warn!("Failed to rename {} to {}: {}", from, to, e);
                }
            }
        }
    }

    let backup1 = format!("{}.1", path.display());
    let backup1_path = PathBuf::from(&backup1);
    if let Err(e) = fs::rename(path, &backup1_path) {
        if e.kind() != io::ErrorKind::NotFound {
            warn!("Failed to rename {} to {}: {}", path.display(), backup1, e);
        }
    }
}

/// Adjust file extension based on Content-Type.
///
/// If `--adjust-extension` is set and the Content-Type indicates HTML or CSS,
/// the file is renamed to have the appropriate extension (.html or .css).
/// Compute the desired extension (`.html` or `.css`) for a Content-Type, or
/// `None` if the type is not HTML/CSS. Pure function, no filesystem access.
fn desired_extension_for(content_type: Option<&str>) -> Option<&'static str> {
    let ct = content_type?;
    let ct_lower = ct.to_lowercase();
    if ct_lower.contains("text/html") || ct_lower.contains("application/xhtml+xml") {
        Some(".html")
    } else if ct_lower.contains("text/css") {
        Some(".css")
    } else {
        None
    }
}

/// Compute the target path after adjusting the extension, without touching the
/// filesystem. Returns `None` when no adjustment is needed (the extension is
/// already correct or the content type is not HTML/CSS).
fn compute_adjusted_path(path: &Path, desired_ext: &str) -> Option<PathBuf> {
    let file_stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let last_dot = file_stem.rfind('.');
    let already_has = match last_dot {
        Some(idx) => {
            let existing = &file_stem[idx..]; // includes the leading '.'
            let existing_lower = existing.to_ascii_lowercase();
            existing_lower == desired_ext
                || (desired_ext == ".html" && existing_lower == ".htm")
        }
        None => false,
    };
    if already_has {
        return None;
    }
    // Append the desired extension to the full file name (GNU wget appends,
    // e.g. `file.txt` -> `file.txt.html`, `index` -> `index.html`).
    let mut new_path = path.as_os_str().to_owned();
    new_path.push(desired_ext);
    Some(PathBuf::from(new_path))
}

pub(crate) fn adjust_file_extension(path: &Path, content_type: Option<&str>) -> PathBuf {
    let desired_ext = match desired_extension_for(content_type) {
        Some(ext) => ext,
        None => return path.to_path_buf(),
    };

    let new_path = match compute_adjusted_path(path, desired_ext) {
        Some(p) => p,
        None => return path.to_path_buf(),
    };

    if path.exists() {
        if let Err(e) = fs::rename(path, &new_path) {
            warn!("Failed to adjust extension for {}: {}", path.display(), e);
            return path.to_path_buf();
        }
    }

    new_path
}

#[cfg(test)]
mod adjust_ext_tests {
    use super::*;

    #[test]
    fn append_html_to_extensionless() {
        assert_eq!(
            compute_adjusted_path(std::path::Path::new("index"), ".html"),
            Some(std::path::PathBuf::from("index.html"))
        );
    }

    #[test]
    fn append_html_to_existing_ext() {
        // file.txt -> file.txt.html (append, NOT replace/merge)
        assert_eq!(
            compute_adjusted_path(std::path::Path::new("file.txt"), ".html"),
            Some(std::path::PathBuf::from("file.txt.html"))
        );
    }

    #[test]
    fn already_html_no_change() {
        assert_eq!(
            compute_adjusted_path(std::path::Path::new("page.html"), ".html"),
            None
        );
    }

    #[test]
    fn htm_treated_as_html() {
        assert_eq!(
            compute_adjusted_path(std::path::Path::new("page.htm"), ".html"),
            None
        );
    }

    #[test]
    fn case_insensitive_html() {
        assert_eq!(
            compute_adjusted_path(std::path::Path::new("PAGE.HTML"), ".html"),
            None
        );
    }

    #[test]
    fn css_extension() {
        assert_eq!(
            compute_adjusted_path(std::path::Path::new("style"), ".css"),
            Some(std::path::PathBuf::from("style.css"))
        );
    }
}

#[cfg(test)]
mod redact_tests {
    use super::redact_sensitive_headers;

    #[test]
    fn redacts_authorization_basic() {
        let req = "GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\nHost: x\r\n\r\n";
        let out = redact_sensitive_headers(req);
        assert!(out.contains("Authorization: <redacted>"));
        assert!(!out.contains("dXNlcjpwYXNz"));
        // Non-sensitive headers preserved
        assert!(out.contains("Host: x"));
    }

    #[test]
    fn redacts_cookie_and_proxy_authorization() {
        let req = "CONNECT host:443 HTTP/1.1\r\nProxy-Authorization: Basic abc==\r\nCookie: session=secret\r\n\r\n";
        let out = redact_sensitive_headers(req);
        assert!(out.contains("Proxy-Authorization: <redacted>"));
        assert!(out.contains("Cookie: <redacted>"));
        assert!(!out.contains("abc=="));
        assert!(!out.contains("session=secret"));
    }

    #[test]
    fn case_insensitive_header_name() {
        let req = "AUTHORIZATION: Bearer xyz\r\n\r\n";
        let out = redact_sensitive_headers(req);
        assert!(out.contains("AUTHORIZATION: <redacted>"));
        assert!(!out.contains("xyz"));
    }

    #[test]
    fn preserves_line_endings_and_structure() {
        let req = "GET / HTTP/1.1\r\nAuthorization: secret\r\n\r\n";
        let out = redact_sensitive_headers(req);
        // CRLF preserved
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn leaves_non_sensitive_headers_untouched() {
        let req = "GET / HTTP/1.1\r\nUser-Agent: wget\r\nAccept: */*\r\n\r\n";
        let out = redact_sensitive_headers(req);
        assert_eq!(out, req);
    }

    #[test]
    fn handles_lf_only_line_endings() {
        let req = "GET / HTTP/1.1\nAuthorization: secret\n\n";
        let out = redact_sensitive_headers(req);
        assert!(out.contains("Authorization: <redacted>\n"));
        assert!(!out.contains("secret"));
    }

    #[test]
    fn handles_set_cookie() {
        let req = "HTTP/1.1 200 OK\r\nSet-Cookie: id=a1b2c3; Path=/\r\n\r\n";
        let out = redact_sensitive_headers(req);
        assert!(out.contains("Set-Cookie: <redacted>"));
        assert!(!out.contains("a1b2c3"));
    }
}

/// Apply file timestamp from server response.
pub(crate) fn apply_file_timestamp(path: &Path, dt: chrono::DateTime<chrono::Utc>) {
    let secs = dt.timestamp();
    let mtime = filetime::FileTime::from_unix_time(secs, dt.timestamp_subsec_nanos());
    if let Err(e) = filetime::set_file_mtime(path, mtime) {
        debug!("failed to set mtime on {}: {}", path.display(), e);
    }
}

/// Parse Content-Disposition header to extract filename.
///
/// Supports both `filename="..."` and `filename*=...` formats (RFC 6266).
pub(crate) fn parse_content_disposition(header: &str) -> Option<String> {
    let header_lower = header.to_lowercase();

    if let Some(pos) = header_lower.find("filename*") {
        let rest = &header_lower[pos + 9..];
        let rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=');
        if let Some(encoded) = parse_rfc5987_value(rest) {
            return Some(encoded);
        }
    }

    if let Some(pos) = header_lower.find("filename") {
        let rest = &header_lower[pos + 8..];
        if rest.starts_with('*') {
            return None;
        }
        let rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=');

        let filename = if rest.starts_with('"') {
            let end = rest[1..].find('"').map(|i| i + 1);
            if let Some(end) = end {
                &rest[1..end]
            } else {
                rest.trim_end_matches(';').trim()
            }
        } else {
            rest.split(';').next().unwrap_or("").trim()
        };

        if !filename.is_empty() {
            let filename = filename.replace('\\', "/");
            let filename = filename.rsplit('/').next().unwrap_or(&filename);
            let filename = url_decode(filename);
            return Some(filename.to_string());
        }
    }

    None
}

/// Parse RFC 5987 encoded value (e.g., `utf-8''%E4%B8%AD%E6%96%87.txt`).
fn parse_rfc5987_value(value: &str) -> Option<String> {
    let parts: Vec<&str> = value.splitn(3, '\'').collect();
    if parts.len() != 3 {
        return None;
    }
    let encoded = parts[2].split(';').next().unwrap_or("").trim();
    if encoded.is_empty() {
        return None;
    }
    Some(url_decode(encoded))
}

/// Sanitize a filename to prevent path traversal attacks.
///
/// Removes or replaces characters that could be used for path traversal:
/// - Path separators (/ and \)
/// - Parent directory references (..)
/// - Null bytes
/// - Control characters
///
/// Returns a safe filename that can be safely joined with a directory path.
pub(crate) fn sanitize_filename(filename: &str) -> String {
    let mut result = String::with_capacity(filename.len());

    for ch in filename.chars() {
        match ch {
            // Reject path separators
            '/' | '\\' => continue,
            // Reject null bytes and control characters
            '\0'..='\x1f' => continue,
            // Keep other characters
            _ => result.push(ch),
        }
    }

    // Remove leading dots to prevent hidden files and ".." tricks
    let trimmed = result.trim_start_matches('.');

    // If the result is empty after sanitization, return a default
    if trimmed.is_empty() {
        return "download".to_string();
    }

    // Check for Windows reserved device names (CON, NUL, AUX, PRN, COM1-9, LPT1-9)
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    let stem_upper = stem.to_ascii_uppercase();
    let is_reserved = matches!(
        stem_upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
            | "COM1" | "COM2" | "COM3" | "COM4" | "COM5"
            | "COM6" | "COM7" | "COM8" | "COM9"
            | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5"
            | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    );

    if is_reserved {
        format!("_{}", trimmed)
    } else {
        trimmed.to_string()
    }
}

/// Simple URL decoding.
///
/// Replaces percent-encoded sequences (`%XX`) with their corresponding characters.
pub(crate) fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Serialize a HeaderMap into raw HTTP header bytes.
pub(crate) fn serialize_headers(header_map: &HeaderMap) -> Vec<u8> {
    let mut result = Vec::new();
    for (key, value) in header_map.iter() {
        result.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
    }
    result
}

/// Build a proxy request by rewriting the request line to use an absolute URL.
/// Optionally adds Proxy-Authorization header if proxy credentials are provided.
pub(crate) fn build_proxy_request(
    request: &HttpRequest,
    target_host: &str,
    target_port: u16,
    proxy_user: Option<&str>,
    proxy_password: Option<&str>,
) -> HttpRequest {
    let mut proxy_req = request.clone();
    proxy_req.path = format!("http://{}:{}{}", target_host, target_port, request.path);
    
    // Add Proxy-Authorization header if credentials are provided
    if let (Some(user), Some(password)) = (proxy_user, proxy_password) {
        let credentials = format!("{}:{}", user, password);
        let encoded = base64_encode(&credentials);
        proxy_req.headers.push((
            "Proxy-Authorization".to_string(),
            format!("Basic {}", encoded),
        ));
    }
    
    proxy_req
}

/// Simple base64 encoding for proxy authentication.
pub(crate) fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);
    
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    
    result
}
