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
