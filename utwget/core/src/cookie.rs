//! Cookie handling for HTTP sessions.
//!
//! This module provides cookie parsing, storage, and matching functionality
//! for HTTP downloads, following RFC 6265 (HTTP State Management Mechanism).

use crate::types::Scheme;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};

/// Represents an HTTP cookie.
///
/// Contains all cookie attributes as defined in RFC 6265, including
/// domain, path, expiration, and security flags.
#[derive(Debug, Clone)]
pub struct Cookie {
    /// The domain for which the cookie is valid.
    pub domain: String,
    /// The path prefix for which the cookie is valid.
    pub path: String,
    /// The cookie name.
    pub name: String,
    /// The cookie value.
    pub value: String,
    /// Expiration timestamp, if set.
    pub expires: Option<DateTime<Utc>>,
    /// Whether the cookie should only be sent over HTTPS.
    pub secure: bool,
    /// Whether the cookie is inaccessible to JavaScript.
    pub httponly: bool,
    /// Whether the cookie should be persisted across sessions.
    pub persistent: bool,
}
