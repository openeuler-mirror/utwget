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
