//! Common type definitions for utwget.
//!
//! This module defines enumerations and structures used throughout
//! the application, including URL schemes, HTTP methods, and
//! configuration-related types.

use serde::{Deserialize, Serialize};
use std::fmt;

/// URL scheme (protocol) enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scheme {
    /// HTTP protocol (port 80).
    Http,
    /// HTTPS protocol (port 443).
    Https,
    /// FTP protocol (port 21).
    Ftp,
    /// FTPS protocol (port 990).
    Ftps,
}

impl Scheme {
    /// Returns the default port for this scheme.
    ///
    /// # Returns
    ///
    /// The default port number (80 for HTTP, 443 for HTTPS, etc.).
    pub fn default_port(&self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
            Scheme::Ftp => 21,
            Scheme::Ftps => 990,
        }
    }

    /// Checks if this scheme uses encryption.
    ///
    /// # Returns
    ///
    /// `true` for HTTPS and FTPS, `false` otherwise.
    pub fn is_secure(&self) -> bool {
        matches!(self, Scheme::Https | Scheme::Ftps)
    }

    /// Returns the scheme as a string.
    ///
    /// # Returns
    ///
    /// The lowercase scheme name ("http", "https", "ftp", "ftps").
    pub fn as_str(&self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Ftp => "ftp",
            Scheme::Ftps => "ftps",
        }
    }

    /// Parses a scheme from a string.
    ///
    /// # Arguments
    ///
    /// * `s` - The scheme string (case-insensitive).
    ///
    /// # Returns
    ///
    /// `Some(Scheme)` if valid, `None` otherwise.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Some(Scheme::Http),
            "https" => Some(Scheme::Https),
            "ftp" => Some(Scheme::Ftp),
            "ftps" => Some(Scheme::Ftps),
            _ => None,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// HTTP request method enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// GET method.
    Get,
    /// POST method.
    Post,
    /// PUT method.
    Put,
    /// DELETE method.
    Delete,
    /// HEAD method.
    Head,
    /// OPTIONS method.
    Options,
    /// PATCH method.
    Patch,
}

impl HttpMethod {
    /// Returns the method as an uppercase string.
    ///
    /// # Returns
    ///
    /// The HTTP method name ("GET", "POST", etc.).
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Patch => "PATCH",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for HttpMethod {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "PATCH" => Ok(HttpMethod::Patch),
            other => Err(format!("unsupported HTTP method: {}", other)),
        }
    }
}

/// Address family preference for DNS resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressFamily {
    /// Use IPv4 only.
    Ipv4,
    /// Use IPv6 only.
    Ipv6,
    /// Prefer IPv4, fallback to IPv6.
    PreferIpv4,
    /// Prefer IPv6, fallback to IPv4.
    PreferIpv6,
    /// Use system default.
    Unspecified,
}

/// Progress display style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgressStyle {
    /// Bar-style progress indicator.
    Bar,
    /// Dot-style progress indicator.
    Dot { bytes_per_dot: usize, dots_per_line: usize, spacing: usize },
    /// No progress output.
    Silent,
    /// Verbose output without progress.
    Verbose,
}
