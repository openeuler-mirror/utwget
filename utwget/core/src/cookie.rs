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
    pub fn parse_set_cookie(&mut self, header: &str, request_host: &str, _request_path: &str) {
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
        let mut path = "/".to_string();
        let mut expires = None;
        let mut secure = false;
        let mut httponly = false;
        let mut persistent = false;

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
                        persistent = true;
                        if let Ok(secs) = v.parse::<i64>() {
                            let dur = chrono::Duration::seconds(secs);
                            expires = Some(Utc::now() + dur);
                        }
                    }
                }
                "secure" => secure = true,
                "httponly" => httponly = true,
                _ => {}
            }
        }

        if !Cookie::domain_matches(request_host, &domain) {
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
            };
            self.store(cookie);
        }
        Ok(())
    }

    /// Saves cookies to a writer in Netscape cookie file format.
    ///
    /// Only persistent cookies are saved. Cookies are sorted by domain,
    /// path, and name for consistent output.
    ///
    /// # Arguments
    ///
    /// * `writer` - A writer to receive the cookie file content.
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
    /// jar.save_to_writer(file)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn save_to_writer<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        let mut cookies: Vec<_> = self.cookies.values().collect();
        cookies.sort_by(|a, b| {
            a.domain.cmp(&b.domain).then_with(|| a.path.cmp(&b.path).then_with(|| a.name.cmp(&b.name)))
        });

        writeln!(writer, "# Netscape HTTP Cookie File")?;
        writeln!(writer, "# This file was generated by wget-rs.")?;

        for c in cookies {
            if !c.persistent && c.expires.is_none() {
                continue;
            }
            let domain_str = if c.domain.starts_with('.') {
                c.domain.clone()
            } else {
                format!(".{}", c.domain)
            };
            let domain = &domain_str;
            let expires = c
                .expires
                .map(|e| e.timestamp().to_string())
                .unwrap_or_else(|| "0".to_string());
            let secure = if c.secure { "TRUE" } else { "FALSE" };
            let httponly = if c.httponly { "TRUE" } else { "FALSE" };
            writeln!(
                writer,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                domain,
                "TRUE",
                c.path,
                secure,
                expires,
                c.name,
                httponly
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
