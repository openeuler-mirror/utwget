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
pub(crate) fn adjust_file_extension(path: &Path, content_type: Option<&str>) -> PathBuf {
    let desired_ext = match content_type {
        Some(ct) => {
            let ct_lower = ct.to_lowercase();
            if ct_lower.contains("text/html") || ct_lower.contains("application/xhtml+xml") {
                Some(".html")
            } else if ct_lower.contains("text/css") {
                Some(".css")
            } else {
                None
            }
        }
        None => None,
    };

    let desired_ext = match desired_ext {
        Some(ext) => ext,
        None => return path.to_path_buf(),
    };

    if let Some(existing_ext) = path.extension().and_then(|e| e.to_str()) {
        let existing_lower = existing_ext.to_lowercase();
        let desired_lower = desired_ext.trim_start_matches('.').to_lowercase();
        if existing_lower == desired_lower {
            return path.to_path_buf();
        }
        if desired_ext == ".html" && existing_lower == "htm" {
            return path.to_path_buf();
        }
    }

    let new_path = path.with_extension(format!(
        "{}{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or(""),
        desired_ext.trim_start_matches('.')
    ));

    if path.exists() {
        if let Err(e) = fs::rename(path, &new_path) {
            warn!("Failed to adjust extension for {}: {}", path.display(), e);
            return path.to_path_buf();
        }
    }

    new_path
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
        let rest = &header[pos + 9..];
        let rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=');
        if let Some(encoded) = parse_rfc5987_value(rest) {
            return Some(encoded);
        }
    }

    if let Some(pos) = header_lower.find("filename") {
        let rest = &header[pos + 8..];
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
        "download".to_string()
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
fn base64_encode(input: &str) -> String {
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
