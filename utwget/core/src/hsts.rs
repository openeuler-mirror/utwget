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
}

/// HSTS cache store.
///
/// Maintains a collection of HSTS entries and provides lookup
/// and persistence functionality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsStore {
    /// HSTS entries keyed by hostname.
    entries: HashMap<String, HstsEntry>,
}

impl HstsStore {
    /// Creates a new empty HSTS store.
    ///
    /// # Returns
    ///
    /// A new `HstsStore` with no entries.
    pub fn new() -> Self {
        HstsStore {
            entries: HashMap::new(),
        }
    }

    /// Looks up HSTS policy for a host.
    ///
    /// Checks both exact host matches and parent domain matches
    /// when the parent has `include_subdomains` set.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to look up.
    ///
    /// # Returns
    ///
    /// `Some(include_subdomains)` if HSTS is active for the host,
    /// `None` otherwise.
    pub fn lookup(&self, host: &str) -> Option<bool> {
        let host_lc = host.to_ascii_lowercase();
        if let Some(entry) = self.entries.get(&host_lc) {
            if !entry.is_expired() {
                return Some(entry.include_subdomains);
            }
        }
        for entry in self.entries.values() {
            if entry.include_subdomains && !entry.is_expired() {
                if host_lc.ends_with(&format!(".{}", entry.host))
                    || host_lc == entry.host
                {
                    return Some(true);
                }
            }
        }
        None
    }

    /// Adds or updates an HSTS entry.
    ///
    /// If `max_age` is 0, the entry is removed instead (HSTS deletion).
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname.
    /// * `include_subdomains` - Whether to include subdomains.
    /// * `max_age` - The max-age in seconds.
    pub fn add(&mut self, host: &str, include_subdomains: bool, max_age: u64) {
        let host_lc = host.to_ascii_lowercase();
        if max_age == 0 {
            self.remove(host);
            return;
        }
        let entry = HstsEntry::new(host_lc.clone(), include_subdomains, max_age);
        self.entries.insert(host_lc, entry);
    }

    /// Removes an HSTS entry.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to remove.
    pub fn remove(&mut self, host: &str) {
        let host_lc = host.to_ascii_lowercase();
        self.entries.remove(&host_lc);
    }

    /// Determines if a URL should be upgraded to HTTPS.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname.
    /// * `scheme` - The current URL scheme.
    ///
    /// # Returns
    ///
    /// `Scheme::Https` if HSTS policy requires upgrade, otherwise the original scheme.
    pub fn should_upgrade(&self, host: &str, scheme: Scheme) -> Scheme {
        if scheme == Scheme::Http {
            if self.lookup(host).is_some() {
                return Scheme::Https;
            }
        }
        scheme
    }

    /// Loads HSTS entries from a JSON file.
    ///
    /// Expired entries are automatically removed after loading.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the JSON file.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if loading fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from_file(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let data = fs::read_to_string(path).map_err(|e| WgetError::Other(e.to_string()))?;
        let loaded: HstsStore = serde_json::from_str(&data).map_err(|e| WgetError::Other(e.to_string()))?;
        self.entries = loaded.entries;
        self.entries.retain(|_, e| !e.is_expired());
        Ok(())
    }

    /// Saves HSTS entries to a JSON file.
    ///
    /// Only non-expired entries are saved. Creates parent directories
    /// if they don't exist.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the JSON file.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if saving fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let mut to_save = self.clone();
        to_save.entries.retain(|_, e| !e.is_expired());

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| WgetError::CannotCreateDir(e.to_string().into()))?;
        }
        let data = serde_json::to_string_pretty(&to_save).map_err(|e| WgetError::Other(e.to_string()))?;
        fs::write(path, data).map_err(WgetError::WriteError)?;
        Ok(())
    }

    /// Merges persisted entries from a file.
    ///
    /// Entries from the file are merged with current entries,
    /// preferring entries with later expiration times.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the JSON file.
    pub fn merge_persisted(&mut self, path: &Path) {
        if let Ok(data) = fs::read_to_string(path) {
            if let Ok(loaded) = serde_json::from_str::<HstsStore>(&data) {
                for (host, entry) in loaded.entries {
                    if entry.is_expired() {
                        continue;
                    }
                    let existing = self.entries.get(&host);
                    match existing {
                        Some(current) if current.expires < entry.expires => {
                            self.entries.insert(host, entry);
                        }
                        None => {
                            self.entries.insert(host, entry);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Returns the number of entries in the store.
    ///
    /// # Returns
    ///
    /// The total number of entries, including expired ones.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Checks if the store contains no entries.
    ///
    /// # Returns
    ///
    /// `true` if the store is empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes all expired entries from the store.
    pub fn prune_expired(&mut self) {
        self.entries.retain(|_, e| !e.is_expired());
    }
}
