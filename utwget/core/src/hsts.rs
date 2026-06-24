//! HSTS (HTTP Strict Transport Security) support.
//!
//! This module implements HSTS caching as specified in RFC 6797,
//! allowing the client to remember which hosts require HTTPS connections.

use crate::error::{Result, WgetError};
use crate::types::Scheme;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// A single HSTS cache entry.
///
/// Represents a host that has advertised HSTS policy via the
/// Strict-Transport-Security HTTP response header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsEntry {
    /// The hostname for which HSTS is active.
    pub host: String,
    /// Whether the policy applies to subdomains.
    pub include_subdomains: bool,
    /// The max-age directive value in seconds.
    pub max_age: u64,
    /// When this entry was created.
    #[serde(with = "ts_seconds")]
    pub created: DateTime<Utc>,
    /// When this entry expires.
    #[serde(with = "ts_seconds")]
    pub expires: DateTime<Utc>,
}

impl HstsEntry {
    /// Creates a new HSTS entry.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname.
    /// * `include_subdomains` - Whether to include subdomains.
    /// * `max_age` - The max-age in seconds.
    ///
    /// # Returns
    ///
    /// A new `HstsEntry` with calculated expiration time.
    pub fn new(host: String, include_subdomains: bool, max_age: u64) -> Self {
        let now = Utc::now();
        HstsEntry {
            host,
            include_subdomains,
            max_age,
            created: now,
            expires: now + chrono::Duration::seconds(max_age as i64),
        }
    }

    /// Checks if the entry has expired.
    ///
    /// # Returns
    ///
    /// `true` if the current time is past the expiration time.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires
    }
}

/// Serde helpers for timestamp serialization.
mod ts_seconds {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serializes a DateTime as a Unix timestamp.
    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(dt.timestamp())
    }

    /// Deserializes a Unix timestamp to a DateTime.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let ts = i64::deserialize(d)?;
        Utc.timestamp_opt(ts, 0)
            .single()
            .ok_or_else(|| serde::de::Error::custom("invalid timestamp"))
    }
