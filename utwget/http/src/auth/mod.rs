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
