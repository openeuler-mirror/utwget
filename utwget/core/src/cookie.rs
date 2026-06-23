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

impl Cookie {
    /// Checks if the cookie has expired.
    ///
    /// # Returns
    ///
    /// `true` if the cookie has an expiration date that has passed,
    /// `false` otherwise (including cookies without expiration).
    ///
    /// # Example
    ///
    /// ```
    /// use ut_core::cookie::Cookie;
    /// // A cookie without expiration is not expired
    /// ```
    pub fn is_expired(&self) -> bool {
        match self.expires {
            Some(exp) => Utc::now() > exp,
            None => false,
        }
    }

    /// Checks if a host matches a cookie's domain attribute.
    ///
    /// Implements the domain matching rules from RFC 6265 Section 5.1.3.
    ///
    /// # Arguments
    ///
    /// * `host` - The request host to check.
    /// * `cookie_domain` - The cookie's domain attribute.
    ///
    /// # Returns
    ///
    /// `true` if the host matches the domain, `false` otherwise.
    fn domain_matches(host: &str, cookie_domain: &str) -> bool {
        let host_lc = host.to_ascii_lowercase();
        let domain_lc = cookie_domain.to_ascii_lowercase();

        if host_lc == domain_lc {
            return true;
        }
        if domain_lc.starts_with('.') {
            if let Some(suffix) = host_lc.strip_suffix(&domain_lc) {
                if suffix.ends_with('.') || suffix.is_empty() {
                    return true;
                }
            }
        } else {
            if host_lc.len() > domain_lc.len() {
                let idx = host_lc.len() - domain_lc.len();
                if host_lc.as_bytes().get(idx.saturating_sub(1)) == Some(&b'.') {
                    return host_lc[idx..] == domain_lc;
                }
            }
        }
        false
    }
}

/// A container for storing and managing HTTP cookies.
///
/// Provides functionality for parsing Set-Cookie headers, matching cookies
/// to requests, and persisting cookies to/from files in Netscape format.
#[derive(Debug, Clone)]
pub struct CookieJar {
    /// Internal storage keyed by (domain, path, name) tuple.
    cookies: HashMap<(String, String, String), Cookie>,
}
