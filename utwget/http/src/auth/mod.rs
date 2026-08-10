//! HTTP Authentication module.
//!
//! This module provides authentication support for HTTP requests, including:
//! - Basic authentication (RFC 7617)
//! - Digest authentication (RFC 7616) - optional via `auth-digest` feature
//! - NTLM authentication - optional via `auth-ntlm` feature
//!
//! # Example
//!
//! ```ignore
//! use utwget_http::auth::{AuthDispatcher, AuthChallenge, AuthScheme};
//!
//! // Create a dispatcher with all available authenticators
//! let mut dispatcher = AuthDispatcher::new();
//!
//! // Parse WWW-Authenticate header
//! let challenges = AuthChallenge::from_www_authenticate(
//!     r#"Digest realm="test", nonce="abc123", qop="auth""#
//! );
//!
//! // Authenticate with credentials
//! let header = dispatcher.authenticate(
//!     &challenges[0],
//!     &credentials,
//!     "GET",
//!     "/path",
//!     None,
//! );
//! ```

pub mod basic;
#[cfg(feature = "auth-digest")]
pub mod digest;
#[cfg(feature = "auth-ntlm")]
pub mod ntlm;

use std::fmt;

/// Supported HTTP authentication schemes.
///
/// Each variant corresponds to a standard authentication mechanism
/// that may be requested by a server via the `WWW-Authenticate` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthScheme {
    /// HTTP Basic Authentication (RFC 7617).
    /// Credentials are sent as Base64-encoded `username:password`.
    Basic,
    /// HTTP Digest Authentication (RFC 7616).
    /// Uses hashed credentials with server-provided nonce.
    Digest,
    /// NTLM (NT LAN Manager) Authentication.
    /// Microsoft proprietary challenge-response protocol.
    Ntlm,
    /// Bearer Token Authentication (RFC 6750).
    /// Uses an opaque bearer token.
    Bearer,
}

impl fmt::Display for AuthScheme {
    /// Formats the authentication scheme as it appears in HTTP headers.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthScheme::Basic => f.write_str("Basic"),
            AuthScheme::Digest => f.write_str("Digest"),
            AuthScheme::Ntlm => f.write_str("NTLM"),
            AuthScheme::Bearer => f.write_str("Bearer"),
        }
    }
}

impl AuthScheme {
    /// Parses an authentication scheme name from a `WWW-Authenticate` header.
    ///
    /// The comparison is case-insensitive per HTTP specifications.
    ///
    /// # Arguments
    ///
    /// * `s` - The scheme name string (e.g., `"Basic"`, `"digest"`, `"NTLM"`).
    ///
    /// # Returns
    ///
    /// `Some(AuthScheme)` if the string matches a known scheme, `None` otherwise.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "basic" => Some(AuthScheme::Basic),
            "digest" => Some(AuthScheme::Digest),
            "ntlm" => Some(AuthScheme::Ntlm),
            "bearer" => Some(AuthScheme::Bearer),
            _ => None,
        }
    }
}

/// Parsed authentication challenge from a `WWW-Authenticate` header.
///
/// Contains all parameters specified by the server for a particular
/// authentication scheme. Not all fields are relevant for all schemes.
#[derive(Debug, Clone)]
pub struct AuthChallenge {
    /// The authentication scheme being requested.
    pub scheme: AuthScheme,
    /// The protection realm (namespace for credentials).
    pub realm: Option<String>,
    /// Server-generated nonce value (Digest, NTLM).
    pub nonce: Option<String>,
    /// Server-provided opaque value to be returned unchanged (Digest).
    pub opaque: Option<String>,
    /// Quality of protection options (Digest: `"auth"`, `"auth-int"`).
    pub qop: Option<String>,
    /// Hash algorithm to use (Digest: `"MD5"`, `"SHA-256"`, etc.).
    pub algorithm: Option<String>,
    /// Character set for credentials (Digest: `"UTF-8"`).
    pub charset: Option<String>,
    /// Whether to hash the username (Digest).
    pub userhash: Option<bool>,
    /// Whether the nonce is stale (Digest).
    pub stale: Option<bool>,
    /// Domain(s) to which the authentication applies (Digest).
    pub domain: Option<String>,
    /// NTLM Type 2 message (NTLM).
    pub ntlm_type2_msg: Option<String>,
}

impl AuthChallenge {
    /// Parses a `WWW-Authenticate` header value into a list of challenges.
    ///
    /// A single `WWW-Authenticate` header may contain multiple challenges
    /// for different schemes, separated by commas.
    ///
    /// # Arguments
    ///
    /// * `header` - The raw header value (e.g., `Basic realm="foo", Digest realm="bar", nonce="xyz"`).
    ///
    /// # Returns
    ///
    /// A vector of `AuthChallenge` instances, one per scheme in the header.
    ///
    /// # Example
    ///
    /// ```
    /// use ut_http::auth::{AuthChallenge, AuthScheme};
    ///
    /// let challenges = AuthChallenge::from_www_authenticate(
    ///     r#"Basic realm="WallyWorld""#
    /// );
    /// assert_eq!(challenges.len(), 1);
    /// assert_eq!(challenges[0].scheme, AuthScheme::Basic);
    /// assert_eq!(challenges[0].realm.as_deref(), Some("WallyWorld"));
    /// ```
    pub fn from_www_authenticate(header: &str) -> Vec<AuthChallenge> {
        let mut challenges = Vec::new();
        let mut remainder = header.trim();

        while !remainder.is_empty() {
            let (scheme_str, rest) = match remainder.find(|c: char| c.is_whitespace()) {
                Some(idx) => (&remainder[..idx], &remainder[idx..]),
                None => {
                    if let Some(scheme) = AuthScheme::from_str(remainder) {
                        challenges.push(AuthChallenge {
                            scheme,
                            realm: None, nonce: None, opaque: None,
                            qop: None, algorithm: None, charset: None,
                            userhash: None, stale: None, domain: None,
                            ntlm_type2_msg: None,
                        });
                    }
                    break;
                }
            };

            let scheme = match AuthScheme::from_str(scheme_str) {
                Some(s) => s,
                None => break,
            };

            let rest = rest.trim_start();

            let mut challenge = AuthChallenge {
                scheme,
                realm: None, nonce: None, opaque: None,
                qop: None, algorithm: None, charset: None,
                userhash: None, stale: None, domain: None,
                ntlm_type2_msg: None,
            };

            let (params, next) = parse_auth_params(rest);
            for (key, value) in params {
                match key.to_ascii_lowercase().as_str() {
                    "realm" => challenge.realm = Some(value),
                    "nonce" => challenge.nonce = Some(value),
                    "opaque" => challenge.opaque = Some(value),
                    "qop" => challenge.qop = Some(value),
                    "algorithm" => challenge.algorithm = Some(value),
                    "charset" => challenge.charset = Some(value),
                    "userhash" => challenge.userhash = Some(value == "true"),
                    "stale" => challenge.stale = Some(value == "true"),
                    "domain" => challenge.domain = Some(value),
                    _ => {}
                }
            }

            challenges.push(challenge);
            remainder = next.trim_start_matches(',').trim_start();
        }

        challenges
    }
}
