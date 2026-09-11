//! Cookie handling for HTTP sessions.
//!
//! This module provides cookie parsing, storage, and matching functionality
//! for HTTP downloads, following RFC 6265 (HTTP State Management Mechanism).

use crate::types::Scheme;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};

/// Check whether `cookie_domain` is acceptable as a cookie Domain attribute
/// value for a request to `request_host`, using the Mozilla Public Suffix List.
///
/// Mirrors GNU wget's `psl_is_cookie_domain_acceptable` (cookies.c:584). The
/// rule (per RFC 6265 §5.3 step 6 + PSL best practice):
/// 1. Reject if `cookie_domain` is itself a listed public suffix (e.g. "com",
///    "co.uk", "github.io") — a server cannot set a cookie for an entire
///    public suffix.
/// 2. Accept otherwise (including unknown single-label hosts, which have a
///    default-rule suffix but are not "listed" public suffixes).
///
/// Returns `true` if the domain is acceptable, `false` to reject the cookie.
fn is_cookie_domain_acceptable(request_host: &str, cookie_domain: &str) -> bool {
    // IP addresses are exempt from PSL checks (RFC 6265 §5.1.3).
    if request_host.parse::<std::net::IpAddr>().is_ok()
        || cookie_domain.parse::<std::net::IpAddr>().is_ok()
    {
        return true;
    }
    // Normalize: strip leading dot, lowercase.
    let cd = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    if cd.is_empty() {
        return false;
    }
    // Look up the public suffix of the cookie domain. If the suffix is
    // explicitly listed in the PSL (ICANN or Private type) AND it equals the
    // entire cookie domain, the domain IS a public suffix and must be
    // rejected. A `typ` of `None` means the default rule applied (unknown
    // TLD), which is not a "listed" public suffix and should be accepted.
    use psl::Psl;
    let list = psl::List;
    match list.suffix(cd.as_bytes()) {
        Some(suffix) => {
            let is_listed = matches!(suffix.typ(), Some(psl::Type::Icann) | Some(psl::Type::Private));
            let suffix_is_whole_domain = suffix.as_bytes() == cd.as_bytes();
            !(is_listed && suffix_is_whole_domain)
        }
        // No suffix found → treat as acceptable.
        None => true,
    }
}

/// Compute the default cookie path from a request path per RFC 6265 §5.1.4.
///
/// 1. If the path is empty or does not start with '/', return '/'.
/// 2. If the path contains exactly one '/' (i.e. just '/'), return '/'.
/// 3. Otherwise return the substring up to (but not including) the rightmost '/'.
fn default_cookie_path(request_path: &str) -> String {
    if request_path.is_empty() || !request_path.starts_with('/') {
        return "/".to_string();
    }
    // Find the rightmost '/'. We know position 0 is '/'.
    if let Some(idx) = request_path.rfind('/') {
        if idx == 0 {
            // Only one '/' at the start → default path is "/"
            return "/".to_string();
        }
        return request_path[..idx].to_string();
    }
    "/".to_string()
}

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
    /// Whether this is a host-only cookie (no `Domain=` attribute was set).
    /// Mirrors GNU wget's `domain_exact` flag (cookies.c:111): a host-only
    /// cookie's domain is the request host exactly (no leading dot, no
    /// subdomain matching), and is written to the cookie file with the
    /// subdomain-flag column set to FALSE.
    pub host_only: bool,
    /// SameSite attribute (RFC 6265bis). Defaults to Lax per modern
    /// browsers; wget as a CLI tool sends SameSite=None cookies on all
    /// requests (no cross-site context), so this is primarily stored for
    /// cookie file compatibility.
    pub samesite: SameSite,
}

/// SameSite cookie attribute values (RFC 6265bis §5.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    /// `SameSite=Strict` — cookie only sent on same-site requests.
    Strict,
    /// `SameSite=Lax` — cookie sent on top-level navigations (default).
    #[default]
    Lax,
    /// `SameSite=None` — cookie sent on all requests (requires Secure).
    None,
    /// Attribute not present in Set-Cookie (treated as Lax by modern
    /// browsers, but stored distinctly for cookie file compatibility).
    Unspecified,
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

        // RFC 6265: IP address domains must match exactly
        if host_lc.parse::<std::net::IpAddr>().is_ok()
            || domain_lc.parse::<std::net::IpAddr>().is_ok()
        {
            return false;
        }

        if domain_lc.starts_with('.') {
            // Domain has a leading dot (e.g. ".example.com"). The host
            // matches if it ends with the domain (the dot serves as the
            // subdomain separator). E.g. domain=".example.com" matches
            // host="www.example.com" (ends with ".example.com").
            // The previous code checked `suffix.ends_with('.')` which was
            // wrong — for "www.example.com" the suffix is "www" (no dot),
            // so it would incorrectly return false.
            if host_lc.ends_with(&domain_lc) {
                return true;
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

impl CookieJar {
    /// Creates a new empty cookie jar.
    ///
    /// # Returns
    ///
    /// A new `CookieJar` instance with no cookies.
    ///
    /// # Example
    ///
    /// ```
    /// use ut_core::cookie::CookieJar;
    ///
    /// let jar = CookieJar::new();
    /// assert!(jar.is_empty());
    /// ```
    pub fn new() -> Self {
        CookieJar {
            cookies: HashMap::new(),
        }
    }

    /// Parses a Set-Cookie header and stores the cookie.
    ///
    /// Implements the cookie parsing algorithm from RFC 6265 Section 5.2.
    ///
    /// # Arguments
    ///
    /// * `header` - The Set-Cookie header value.
    /// * `request_host` - The host that sent the response.
    /// * `_request_path` - The path of the request (unused currently).
    ///
    /// # Example
    ///
    /// ```
    /// use ut_core::cookie::CookieJar;
    ///
    /// let mut jar = CookieJar::new();
    /// jar.parse_set_cookie("session=abc123; Path=/", "example.com", "/");
    /// ```
    pub fn parse_set_cookie(&mut self, header: &str, request_host: &str, request_path: &str) {
        let header = header.trim();
        if header.is_empty() {
            return;
        }

        let (name_value, attrs) = match header.find(';') {
            Some(idx) => (&header[..idx], &header[idx + 1..]),
            None => (header, ""),
        };

        let (name, value) = match name_value.find('=') {
            Some(idx) => {
                let n = name_value[..idx].trim().to_string();
                let v = name_value[idx + 1..].trim().to_string();
                (n, v)
            }
            None => return,
        };

        let mut domain = request_host.to_ascii_lowercase();
        // Whether the cookie explicitly specified a Domain= attribute.
        // GNU wget (cookies.c:764-771) treats cookies without a Domain
        // attribute as "host-only" (domain_exact=1) and skips the PSL
        // check, accepting the cookie for the request host unconditionally.
        // Only cookies with an explicit Domain= attribute are subjected to
        // the Public Suffix List check (check_domain_match, cookies.c:774).
        let mut has_domain_attr = false;
        // RFC 6265 §5.1.4: default-path = the request URI up to (but not
        // including) the rightmost '/'. If there is no '/' or the URI
        // starts with '//', the default path is '/'.
        let mut path = default_cookie_path(request_path);
        let mut expires = None;
        let mut secure = false;
        let mut httponly = false;
        let mut persistent = false;
        let mut samesite = SameSite::Unspecified;

        for attr in attrs.split(';') {
            let attr = attr.trim();
            if attr.is_empty() {
                continue;
            }
            let (key, val) = match attr.find('=') {
                Some(idx) => (attr[..idx].trim().to_ascii_lowercase(), Some(attr[idx + 1..].trim())),
                None => (attr.to_ascii_lowercase(), None),
            };

            match key.as_str() {
                "domain" => {
                    if let Some(v) = val {
                        let d = v.trim_start_matches('.').to_ascii_lowercase();
                        if !d.is_empty() {
                            domain = d;
                            has_domain_attr = true;
                        }
                    }
                }
                "path" => {
                    if let Some(v) = val {
                        if v.starts_with('/') {
                            path = v.to_string();
                        }
                    }
                }
                "expires" => {
                    if let Some(v) = val {
                        persistent = true;
                        if let Ok(dt) = parse_cookie_expires(v) {
                            expires = Some(dt);
                        }
                    }
                }
                "max-age" => {
                    if let Some(v) = val {
                        if let Ok(secs) = v.parse::<i64>() {
                            if secs <= 0 {
                                // Max-Age=0 means immediately expire the cookie
                                expires = Some(Utc::now() - chrono::Duration::seconds(1));
                            } else {
                                persistent = true;
                                // Clamp to a sane maximum: `chrono::Duration::seconds`
                                // panics on values beyond ±i64::MAX milliseconds, so a
                                // hostile `Set-Cookie: Max-Age=9223372036854775807`
                                // header could crash the client. RFC 6265 has no
                                // upper bound; anything past the year 9999 behaves
                                // the same as "far future". The HSTS module
                                // (hsts.rs) already uses this checked pattern.
                                let far_future = Utc::now() + chrono::Duration::try_days(3650)
                                    .unwrap_or_else(|| chrono::Duration::zero());
                                let dur = chrono::Duration::try_seconds(secs)
                                    .filter(|d| {
                                        // Reject if the resulting expiry would overflow
                                        Utc::now().checked_add_signed(*d).is_some()
                                    });
                                expires = match dur {
                                    Some(d) => Some(Utc::now() + d),
                                    // Overflow (or near-overflow) → treat as far future
                                    None => Some(far_future),
                                };
                            }
                        }
                    }
                }
                "secure" => secure = true,
                "httponly" => httponly = true,
                "samesite" => {
                    if let Some(v) = val {
                        samesite = match v.trim().to_ascii_lowercase().as_str() {
                            "strict" => SameSite::Strict,
                            "lax" => SameSite::Lax,
                            "none" => SameSite::None,
                            _ => SameSite::Unspecified,
                        };
                    }
                }
                _ => {}
            }
        }

        if !Cookie::domain_matches(request_host, &domain) {
            return;
        }

        // Public Suffix List check: reject cookies whose Domain attribute is
        // itself a public suffix (e.g. "com", "co.uk"), which would let a
        // server set cookies for an entire public suffix and leak them to
        // unrelated subdomains. Mirrors GNU wget's libpsl usage (cookies.c:584).
        //
        // Only cookies with an explicit Domain= attribute are checked. A
        // host-only cookie (no Domain=) is always accepted for the request
        // host (GNU wget cookies.c:764-771 sets domain_exact and skips the
        // PSL check). Without this gate, host-only cookies on hosts that are
        // themselves listed as private suffixes in the PSL (e.g. httpbin.org)
        // would be wrongly rejected.
        if has_domain_attr && !is_cookie_domain_acceptable(request_host, &domain) {
            log::warn!(
                "cookie with Domain='{}' rejected: domain is a public suffix",
                domain
            );
            return;
        }

        let cookie = Cookie {
            domain,
            path,
            name,
            value,
            expires,
            secure,
            httponly,
            persistent,
            host_only: !has_domain_attr,
            samesite,
        };

        let key = (cookie.domain.clone(), cookie.path.clone(), cookie.name.clone());
        self.cookies.insert(key, cookie);
    }

    /// Finds all cookies matching a request.
    ///
    /// Implements the cookie retrieval algorithm from RFC 6265 Section 5.4.
    /// Cookies are sorted by path length (longest first) and then by
    /// persistence status.
    ///
    /// # Arguments
    ///
    /// * `host` - The request host.
    /// * `path` - The request path.
    /// * `scheme` - The request URL scheme (HTTP or HTTPS).
    ///
    /// # Returns
    ///
    /// A vector of references to matching cookies.
    pub fn match_request(&self, host: &str, path: &str, scheme: Scheme) -> Vec<&Cookie> {
        let host_lc = host.to_ascii_lowercase();
        let mut matching = Vec::new();

        for cookie in self.cookies.values() {
            if cookie.is_expired() {
                continue;
            }
            if cookie.secure && !scheme.is_secure() {
                continue;
            }
            if !Cookie::domain_matches(&host_lc, &cookie.domain) {
                continue;
            }
            // A host-only cookie (no Domain= attribute) must match the
            // request host exactly, never a subdomain. GNU wget tracks this
            // via domain_exact (cookies.c:111). domain_matches() above does
            // a suffix match that would let a host-only cookie on
            // "example.com" match "sub.example.com"; gate host-only cookies
            // to an exact host comparison.
            if cookie.host_only && host_lc != cookie.domain {
                continue;
            }
            if !path_matches(path, &cookie.path) {
                continue;
            }
            matching.push(cookie);
        }

        matching.sort_by(|a, b| {
            let path_cmp = b.path.len().cmp(&a.path.len());
            if path_cmp != std::cmp::Ordering::Equal {
                return path_cmp;
            }
            a.persistent.cmp(&b.persistent)
        });

        matching
    }

    /// Serializes matching cookies for a Cookie request header.
    ///
    /// # Arguments
    ///
    /// * `host` - The request host.
    /// * `path` - The request path.
    /// * `scheme` - The request URL scheme.
    ///
    /// # Returns
    ///
    /// `Some(String)` with the Cookie header value if there are matching cookies,
    /// `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use ut_core::cookie::CookieJar;
    /// use ut_core::types::Scheme;
    ///
    /// let mut jar = CookieJar::new();
    /// jar.parse_set_cookie("id=123", "example.com", "/");
    /// let header = jar.serialize_for_header("example.com", "/", Scheme::Https);
    /// ```
    pub fn serialize_for_header(&self, host: &str, path: &str, scheme: Scheme) -> Option<String> {
        let cookies = self.match_request(host, path, scheme);
        if cookies.is_empty() {
            return None;
        }
        let parts: Vec<String> = cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        Some(parts.join("; "))
    }

    /// Stores a cookie in the jar.
    ///
    /// If a cookie with the same domain, path, and name exists,
    /// it will be replaced.
    ///
    /// # Arguments
    ///
    /// * `cookie` - The cookie to store.
    pub fn store(&mut self, cookie: Cookie) {
        let key = (cookie.domain.clone(), cookie.path.clone(), cookie.name.clone());
        self.cookies.insert(key, cookie);
    }

    /// Loads cookies from a reader in Netscape cookie file format.
    ///
    /// The format is tab-separated fields: domain, subdomain, path,
    /// secure, expires, name, value, [httponly].
    ///
    /// # Arguments
    ///
    /// * `reader` - A reader providing the cookie file content.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an IO error on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the reader fails to provide data.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ut_core::cookie::CookieJar;
    /// use std::fs::File;
    ///
    /// let mut jar = CookieJar::new();
    /// let file = File::open("cookies.txt")?;
    /// jar.load_from_reader(file)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn load_from_reader<R: Read>(&mut self, reader: R) -> std::io::Result<()> {
        let buf = BufReader::new(reader);
        for line_result in buf.lines() {
            let line = line_result?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 7 {
                continue;
            }
            let domain = fields[0].trim_start_matches('.').to_string();
            // GNU wget's Netscape-format: a leading '.' on the domain means
            // a domain cookie (subdomain matching); the second field is the
            // "domain_exact" flag (FALSE for host-only, TRUE for domain).
            // A host-only cookie has no leading dot and field[1]=="FALSE".
            let host_only = !fields[0].starts_with('.');
            let path = fields[2].to_string();
            let secure = fields[3] == "TRUE";
            let expires = if fields[4] == "0" {
                None
            } else {
                fields[4].parse::<i64>().ok().and_then(|ts| {
                    DateTime::from_timestamp(ts, 0)
                })
            };
            let name = fields[5].to_string();
            let value = fields[6].to_string();
            let httponly = fields.len() > 7 && fields[7] == "TRUE";

            let cookie = Cookie {
                domain,
                path,
                name,
                value,
                expires,
                secure,
                httponly,
                persistent: expires.is_some(),
                host_only,
                samesite: SameSite::Unspecified,
            };
            self.store(cookie);
        }
        Ok(())
    }

    /// Saves cookies to a writer in Netscape cookie file format.
    ///
    /// Persistent cookies are always saved. Session (non-persistent)
    /// cookies are only saved when `keep_session_cookies` is true, matching
    /// GNU wget's `--keep-session-cookies` behavior (cookies.c:1397).
    /// Cookies are sorted by domain, path, and name for consistent output.
    ///
    /// The output format matches GNU wget (cookies.c:1385-1410): a 7-column
    /// tab-separated record `domain\tsubdomain_flag\tpath\tsecure\texpires\tname\tvalue`
    /// with the canonical header lines. The 8th `httponly` column previously
    /// written by utwget is non-standard and prevented original wget from
    /// parsing the file.
    ///
    /// # Arguments
    ///
    /// * `writer` - A writer to receive the cookie file content.
    /// * `keep_session_cookies` - Whether to keep non-persistent cookies.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an IO error on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer fails to accept data.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ut_core::cookie::CookieJar;
    /// use std::fs::File;
    ///
    /// let jar = CookieJar::new();
    /// let file = File::create("cookies.txt")?;
    /// jar.save_to_writer(file, false)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn save_to_writer<W: Write>(&self, mut writer: W, keep_session_cookies: bool) -> std::io::Result<()> {
        let mut cookies: Vec<_> = self.cookies.values().collect();
        cookies.sort_by(|a, b| {
            a.domain.cmp(&b.domain).then_with(|| a.path.cmp(&b.path).then_with(|| a.name.cmp(&b.name)))
        });

        // Header lines matching GNU wget (cookies.c:1385-1387).
        writeln!(writer, "# HTTP Cookie File")?;
        let now = chrono::Utc::now();
        writeln!(writer, "# Generated by Wget on {}.", now.format("%Y-%m-%d %H:%M:%S"))?;
        writeln!(writer, "# Edit at your own risk.\n")?;

        for c in cookies {
            // Skip expired cookies (cookies.c:1399).
            if c.is_expired() {
                continue;
            }
            // Skip session cookies unless --keep-session-cookies is set
            // (cookies.c:1397).
            if !c.persistent && !keep_session_cookies {
                continue;
            }
            // GNU wget format (cookies.c:1401-1410): host-only cookies
            // (domain_exact) write the bare host with the subdomain flag set
            // to FALSE and no leading dot; domain cookies write ".{domain}"
            // with the flag TRUE.
            let (domain_field, subdomain_flag) = if c.host_only {
                (c.domain.clone(), "FALSE")
            } else {
                let d = if c.domain.starts_with('.') {
                    c.domain.clone()
                } else {
                    format!(".{}", c.domain)
                };
                (d, "TRUE")
            };
            let expires = c
                .expires
                .map(|e| e.timestamp().to_string())
                .unwrap_or_else(|| "0".to_string());
            let secure = if c.secure { "TRUE" } else { "FALSE" };
            // 7-column Netscape format (cookies.c:1406-1410): no httponly column.
            writeln!(
                writer,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                domain_field,
                subdomain_flag,
                c.path,
                secure,
                expires,
                c.name,
                c.value,
            )?;
        }
        Ok(())
    }

    /// Removes all expired cookies from the jar.
    ///
    /// This should be called periodically to clean up stale cookies.
    pub fn remove_expired(&mut self) {
        self.cookies.retain(|_, c| !c.is_expired());
    }

    /// Returns the number of cookies in the jar.
    ///
    /// # Returns
    ///
    /// The total number of cookies, including expired ones.
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Checks if the jar contains no cookies.
    ///
    /// # Returns
    ///
    /// `true` if the jar is empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if a request path matches a cookie's path attribute.
///
/// Implements the path matching rules from RFC 6265 Section 5.1.4.
///
/// # Arguments
///
/// * `request_path` - The request path to check.
/// * `cookie_path` - The cookie's path attribute.
///
/// # Returns
///
/// `true` if the paths match, `false` otherwise.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if cookie_path.is_empty() || cookie_path == "/" {
        return true;
    }
    if request_path == cookie_path {
        return true;
    }
    if request_path.starts_with(cookie_path)
        && (cookie_path.ends_with('/')
            || request_path[cookie_path.len()..].starts_with('/'))
    {
        return true;
    }
    false
}

/// Parses a cookie expires date string.
///
/// Supports multiple date formats commonly used in Set-Cookie headers,
/// as specified in RFC 6265 and historical practice.
///
/// # Arguments
///
/// * `s` - The date string to parse.
///
/// # Returns
///
/// `Ok(DateTime)` if parsing succeeds, `Err(())` otherwise.
fn parse_cookie_expires(s: &str) -> Result<DateTime<Utc>, ()> {
    // RFC 6265 §5.1.1: cookie expires 日期始终以 GMT 表示。
    // NaiveDateTime::parse_from_str 要求整个字符串匹配格式，
    // 因此先剥离尾部 " GMT"（及其变体）再解析。
    let s = s.trim();
    let s = s
        .strip_suffix(" GMT")
        .or_else(|| s.strip_suffix("gmt"))
        .or_else(|| s.strip_suffix("Utc"))
        .or_else(|| s.strip_suffix("UTC"))
        .unwrap_or(s)
        .trim();

    let formats = [
        "%a, %d %b %Y %H:%M:%S",
        "%a, %d-%b-%Y %H:%M:%S",
        "%A, %d-%b-%y %H:%M:%S",
        "%a %b %d %H:%M:%S %Y",
        "%d %b %Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ];
    for fmt in &formats {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Ok(dt.and_utc());
        }
    }
    Err(())
}
