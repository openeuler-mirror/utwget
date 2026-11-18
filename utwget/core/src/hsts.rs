//! HSTS (HTTP Strict Transport Security) support.
//!
//! This module implements HSTS caching as specified in RFC 6797,
//! allowing the client to remember which hosts require HTTPS connections.

use crate::error::{Result, WgetError};
use crate::types::Scheme;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// A single HSTS cache entry.
///
/// Represents a host that has advertised HSTS policy via the
/// Strict-Transport-Security HTTP response header.
#[derive(Debug, Clone)]
pub struct HstsEntry {
    /// The hostname for which HSTS is active.
    pub host: String,
    /// Whether the policy applies to subdomains.
    pub include_subdomains: bool,
    /// The max-age directive value in seconds.
    pub max_age: u64,
    /// When this entry was created.
    pub created: DateTime<Utc>,
    /// When this entry expires.
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

/// HSTS cache store.
///
/// Maintains a collection of HSTS entries and provides lookup
/// and persistence functionality. Uses the GNU wget tab-separated
/// text format for on-disk storage to maintain file compatibility.
#[derive(Debug, Clone)]
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
    /// Per RFC 6797 §8.1, HSTS is not applicable to IP-address hosts. Such
    /// add() calls are silently ignored to mirror GNU wget's
    /// `hsts_is_host_name_valid` check.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname.
    /// * `include_subdomains` - Whether to include subdomains.
    /// * `max_age` - The max-age in seconds.
    pub fn add(&mut self, host: &str, include_subdomains: bool, max_age: u64) {
        // RFC 6797 §8.1: HSTS only applies to hostnames, not IP literals.
        if host.parse::<std::net::IpAddr>().is_ok() {
            return;
        }
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

        // Security check: refuse to load HSTS data from a world-writable file
        // (matches GNU wget hsts.c:344-361 hsts_file_access_valid). A
        // world-writable file can be tampered with by any user, which could
        // inject false HSTS entries or delete legitimate ones.
        if let Ok(metadata) = fs::metadata(path) {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o002 != 0 {
                return Err(WgetError::Other(format!(
                    "HSTS file {} is world-writable; refusing to load (security)",
                    path.display()
                )));
            }
        }

        let data = fs::read_to_string(path).map_err(|e| WgetError::Other(e.to_string()))?;

        // GNU wget tab-separated format:
        //   # comment
        //   <hostname>\t<port>\t<incl. subdomains>\t<created>\t<max-age>
        self.entries = HashMap::new();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 5 {
                continue; // skip malformed lines
            }
            let host = parts[0].to_ascii_lowercase();
            // parts[1] is port (ignored: utwget doesn't track port-specific HSTS)
            let include_subdomains = parts[2].parse::<i32>().unwrap_or(0) != 0;
            let created_ts: i64 = parts[3].parse().unwrap_or(0);
            let max_age: u64 = parts[4].parse().unwrap_or(0);

            let created = chrono::TimeZone::timestamp_opt(&chrono::Utc, created_ts, 0)
                .single()
                .unwrap_or_else(chrono::Utc::now);
            let expires_ts = created_ts.saturating_add(max_age as i64);
            let expires = chrono::TimeZone::timestamp_opt(&chrono::Utc, expires_ts, 0)
                .single()
                .unwrap_or_else(chrono::Utc::now);

            let entry = HstsEntry {
                host: host.clone(),
                include_subdomains,
                max_age,
                created,
                expires,
            };
            if !entry.is_expired() {
                self.entries.insert(host, entry);
            }
        }
        self.entries.retain(|_, e| !e.is_expired());
        Ok(())
    }

    /// Parses a `Strict-Transport-Security` response header and adds or
    /// updates the HSTS entry for `host`.
    ///
    /// Recognizes the `max-age=<seconds>` directive (required) and the
    /// optional `includeSubDomains` directive per RFC 6797 §6.1.
    /// If `max-age` is missing or unparseable, the header is ignored.
    /// A `max-age` of 0 removes any existing entry for the host.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname that sent the header.
    /// * `header_value` - The raw `Strict-Transport-Security` header value.
    pub fn add_from_header(&mut self, host: &str, header_value: &str) {
        // RFC 6797 §8.1: HSTS is not applicable to IP-address hosts. The
        // caller (retriever) already gates this on scheme == HTTPS, but IP
        // addresses must be rejected here as well (defense in depth), matching
        // GNU wget's hsts_is_host_name_valid() check.
        if host.parse::<std::net::IpAddr>().is_ok() {
            return;
        }

        let mut max_age: Option<u64> = None;
        let mut include_subdomains = false;

        for directive in header_value.split(';') {
            let directive = directive.trim();
            if directive.is_empty() {
                continue;
            }
            let lower = directive.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("max-age") {
                // Expect "=<digits>"
                if let Some(val) = rest.trim_start().strip_prefix('=') {
                    if let Ok(n) = val.trim().parse::<u64>() {
                        max_age = Some(n);
                    }
                }
            } else if lower == "includesubdomains" {
                include_subdomains = true;
            }
        }

        if let Some(age) = max_age {
            self.add(host, include_subdomains, age);
        }
    }

    /// Saves HSTS entries to a file in GNU wget tab-separated format.
    ///
    /// Only non-expired entries are saved. Creates parent directories
    /// if they don't exist. The format is compatible with GNU wget 1.21.4:
    ///
    /// ```text
    /// # HSTS 1.0 Known Hosts database for GNU Wget.
    /// # Edit at your own risk.
    /// # <hostname>\t<port>\t<incl. subdomains>\t<created>\t<max-age>
    /// example.com\t0\t1\t1718123456\t31536000
    /// ```
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the HSTS file.
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
            fs::create_dir_all(parent)
                .map_err(|e| WgetError::CannotCreateDir(e.to_string().into()))?;
        }

        // GNU wget tab-separated format for compatibility.
        let mut content = String::new();
        content.push_str("# HSTS 1.0 Known Hosts database for GNU Wget.\n");
        content.push_str("# Edit at your own risk.\n");
        content.push_str("# <hostname>\t<port>\t<incl. subdomains>\t<created>\t<max-age>\n");
        for entry in to_save.entries.values() {
            // port is 0 (utwget doesn't track port-specific HSTS; GNU wget uses 0
            // for default port as well).
            let port = 0;
            let inc_sub = if entry.include_subdomains { 1 } else { 0 };
            let created_ts = entry.created.timestamp();
            content.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                entry.host, port, inc_sub, created_ts, entry.max_age
            ));
        }
        fs::write(path, content).map_err(WgetError::WriteError)?;
        Ok(())
    }

    /// Merges persisted entries from a file.
    ///
    /// Entries from the file are merged with current entries,
    /// preferring entries with later expiration times. Uses the GNU wget
    /// tab-separated format (same as [`load_from_file`]).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the HSTS file.
    pub fn merge_persisted(&mut self, path: &Path) {
        let mut other = HstsStore::new();
        if other.load_from_file(path).is_ok() {
            for (host, entry) in other.entries {
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

impl Default for HstsStore {
    fn default() -> Self {
        Self::new()
    }
}
