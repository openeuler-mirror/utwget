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
