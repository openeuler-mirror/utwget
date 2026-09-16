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
    /// The port this policy applies to (GNU wget keys records by host+port,
    /// hsts.c MAKE_EXPLICIT_PORT). 0 = unspecified/legacy default.
    pub port: u16,
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
    pub fn new(host: String, port: u16, include_subdomains: bool, max_age: u64) -> Self {
        let now = Utc::now();
        // 将 max_age 限制在 i64::MAX 以内，避免 u64→i64 截断后变为负值。
        let safe_secs = max_age.min(i64::MAX as u64) as i64;
        // 使用 checked_add_signed 避免 DateTime 溢出时 panic；
        // 溢出时回退到最大可表示时间，等效于"永不过期"。
        let expires = now
            .checked_add_signed(chrono::Duration::seconds(safe_secs))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        HstsEntry {
            host,
            port,
            include_subdomains,
            max_age,
            created: now,
            expires,
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

/// Map key for an HSTS entry: lowercase "host:port" (wget keys records by
/// host+port, hsts.c MAKE_EXPLICIT_PORT).
fn hsts_key(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
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
    pub fn lookup(&self, host: &str, port: u16) -> Option<bool> {
        let host_lc = host.to_ascii_lowercase();
        // Direct host:port match, with a legacy fallback: pre-port-aware
        // utwget files stored port 0.
        for key in [hsts_key(&host_lc, port), hsts_key(&host_lc, 0)] {
            if let Some(entry) = self.entries.get(&key) {
                if !entry.is_expired() {
                    return Some(entry.include_subdomains);
                }
            }
        }
        // Subdomain matching: walk all entries with include_subdomains.
        // Avoid allocating a String via format!(".{}", ...) in the hot loop;
        // use a stack buffer and ends_with on byte slices instead. The
        // entry's port must match (wget matches host+port, hsts.c:374-418).
        for entry in self.entries.values() {
            if entry.include_subdomains
                && !entry.is_expired()
                && (entry.port == port || entry.port == 0)
            {
                // host must end with ".<entry.host>" or equal entry.host
                // (already covered by the direct get above, but check again
                // for safety in case the direct entry was expired).
                if host_lc == entry.host {
                    return Some(true);
                }
                // Build ".host" comparison without heap allocation
                let eh = entry.host.as_bytes();
                if host_lc.len() > eh.len() + 1 {
                    let suffix_start = host_lc.len() - eh.len() - 1;
                    // Check: host[suffix_start] == '.' and host[suffix_start+1..] == entry.host
                    if host_lc.as_bytes().get(suffix_start) == Some(&b'.')
                        && &host_lc.as_bytes()[suffix_start + 1..] == eh
                    {
                        return Some(true);
                    }
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
    /// * `port` - The port the policy was received on (wget keys by
    ///   host+port, hsts.c).
    /// * `include_subdomains` - Whether to include subdomains.
    /// * `max_age` - The max-age in seconds.
    pub fn add(&mut self, host: &str, port: u16, include_subdomains: bool, max_age: u64) {
        // RFC 6797 §8.1: HSTS only applies to hostnames, not IP literals.
        if host.parse::<std::net::IpAddr>().is_ok() {
            return;
        }
        let host_lc = host.to_ascii_lowercase();
        if max_age == 0 {
            self.remove(host, port);
            return;
        }
        let entry = HstsEntry::new(host_lc.clone(), port, include_subdomains, max_age);
        self.entries.insert(hsts_key(&host_lc, port), entry);
    }

    /// Removes an HSTS entry.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to remove.
    /// * `port` - The port of the policy.
    pub fn remove(&mut self, host: &str, port: u16) {
        let host_lc = host.to_ascii_lowercase();
        self.entries.remove(&hsts_key(&host_lc, port));
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
    pub fn should_upgrade(&self, host: &str, port: u16, scheme: Scheme) -> Scheme {
        if scheme == Scheme::Http {
            if self.lookup(host, port).is_some() {
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
        // 使用 File::open + fstat 消除 TOCTOU 窗口（代码审查 S7）。
        // 先打开文件获取 fd，再对 fd 做权限检查，最后从同一 fd 读取。
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return Ok(()), // 文件不存在或其他错误，静默返回
        };

        // Security check: refuse to load HSTS data from a world-writable file
        // (matches GNU wget hsts.c:344-361 hsts_file_access_valid). A
        // world-writable file can be tampered with by any user, which could
        // inject false HSTS entries or delete legitimate ones.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata().map_err(|e| WgetError::Other(e.to_string()))?;
            let mode = metadata.mode();
            if mode & 0o002 != 0 {
                return Err(WgetError::Other(format!(
                    "HSTS file {} is world-writable; refusing to load (security)",
                    path.display()
                )));
            }
        }

        // 从同一 fd 读取，消除 TOCTOU 窗口
        use std::io::Read;
        let mut data = String::new();
        std::io::BufReader::new(file).read_to_string(&mut data)
            .map_err(|e| WgetError::Other(e.to_string()))?;

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
            // parts[1] is the port (wget keys records by host+port;
            // previously ignored, so an entry for host:8443 applied to 443).
            let port: u16 = parts[1].parse().unwrap_or(0);
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
                port,
                include_subdomains,
                max_age,
                created,
                expires,
            };
            if !entry.is_expired() {
                self.entries.insert(hsts_key(&host, port), entry);
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
    /// * `port` - The port the response arrived on.
    /// * `header_value` - The raw `Strict-Transport-Security` header value.
    pub fn add_from_header(&mut self, host: &str, port: u16, header_value: &str) {
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
            self.add(host, port, include_subdomains, age);
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
            // The port the policy was received on (wget writes the real
            // port; legacy utwget files used 0 for every entry).
            let port = entry.port;
            let inc_sub = if entry.include_subdomains { 1 } else { 0 };
            let created_ts = entry.created.timestamp();
            content.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                entry.host, port, inc_sub, created_ts, entry.max_age
            ));
        }
        // Write HSTS file with 0600 permissions (owner-only) to protect
        // the user's browsing history, matching GNU wget behavior.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(WgetError::WriteError)?;
            use std::io::Write;
            file.write_all(content.as_bytes()).map_err(WgetError::WriteError)?;
        }
        #[cfg(not(unix))]
        {
            fs::write(path, content).map_err(WgetError::WriteError)?;
        }
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
