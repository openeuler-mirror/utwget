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

/// Parses authentication parameters from a challenge string.
///
/// Handles both quoted and unquoted parameter values, and stops
/// when encountering the next scheme name or end of input.
///
/// # Arguments
///
/// * `input` - The parameter portion of a challenge string.
///
/// # Returns
///
/// A tuple of (parsed parameters, remaining unparsed input).
fn parse_auth_params(input: &str) -> (Vec<(String, String)>, &str) {
    let mut params = Vec::new();
    let mut rest = input;

    while !rest.is_empty() {
        rest = rest.trim_start();

        if rest.starts_with(',') {
            rest = rest[1..].trim_start();
            if rest.is_empty() || !rest.chars().next().map_or(false, |c| c.is_alphabetic()) {
                break;
            }
            continue;
        }

        if rest.chars().next().map_or(false, |c| c.is_alphabetic())
            && !rest.starts_with("realm")
            && !rest.starts_with("nonce")
            && !rest.starts_with("opaque")
            && !rest.starts_with("qop")
            && !rest.starts_with("algorithm")
            && !rest.starts_with("charset")
            && !rest.starts_with("userhash")
            && !rest.starts_with("stale")
            && !rest.starts_with("domain")
            && !rest.starts_with("response")
            && !rest.starts_with("cnonce")
            && !rest.starts_with("nc")
            && !rest.starts_with("uri")
            && !rest.starts_with("username")
        {
            break;
        }

        let key_end = rest.find('=').unwrap_or(rest.len());
        let key = rest[..key_end].trim().to_string();
        rest = &rest[key_end..];

        if rest.is_empty() || !rest.starts_with('=') {
            break;
        }
        rest = &rest[1..];

        let (value, next) = if rest.starts_with('"') {
            match rest[1..].find('"') {
                Some(end_idx) => {
                    let val = rest[1..1 + end_idx].to_string();
                    let after = &rest[2 + end_idx..];
                    let after = after.trim_start();
                    let after = if after.starts_with(',') { &after[1..] } else { after };
                    (val, after)
                }
                None => {
                    let val = rest[1..].to_string();
                    (val, "")
                }
            }
        } else {
            let token_end = rest
                .find(|c: char| c == ',' || c.is_whitespace())
                .unwrap_or(rest.len());
            let val = rest[..token_end].trim().to_string();
            let after = &rest[token_end..];
            let after = after.trim_start();
            let after = if after.starts_with(',') { &after[1..] } else { after };
            (val, after)
        };

        if !key.is_empty() {
            params.push((key, value));
        }
        rest = next;
    }

    (params, rest)
}

/// Errors that can occur during authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The authentication challenge is missing a required nonce value.
    MissingNonce,
    /// The authentication challenge is malformed or invalid.
    InvalidChallenge(String),
    /// The requested hash algorithm is not supported.
    AlgorithmUnsupported(String),
    /// An I/O error occurred during authentication.
    Io(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::MissingNonce => f.write_str("missing nonce in Digest challenge"),
            AuthError::InvalidChallenge(msg) => write!(f, "invalid auth challenge: {}", msg),
            AuthError::AlgorithmUnsupported(alg) => {
                write!(f, "unsupported algorithm: {}", alg)
            }
            AuthError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for AuthError {}

/// Trait for HTTP authentication implementations.
///
/// Each authentication scheme (Basic, Digest, NTLM) implements this trait
/// to provide scheme-specific authentication logic.
pub trait Authenticator: Send + Sync {
    /// Generates an `Authorization` header value for the given challenge.
    ///
    /// # Arguments
    ///
    /// * `challenge` - The parsed `WWW-Authenticate` challenge from the server.
    /// * `credentials` - The user's credentials.
    /// * `request_method` - The HTTP method of the request being authenticated.
    /// * `request_uri` - The URI path of the request.
    /// * `body` - The request body, if any (used for `auth-int` qop in Digest).
    ///
    /// # Returns
    ///
    /// `Ok(Some(header))` with the authorization header value,
    /// `Ok(None)` if no authentication is needed, or an error.
    fn authenticate(
        &mut self,
        challenge: &AuthChallenge,
        credentials: &ut_core::types::Credentials,
        request_method: &str,
        request_uri: &str,
        body: Option<&[u8]>,
    ) -> Result<Option<String>, AuthError>;

    /// Returns whether this authenticator can send credentials preemptively.
    ///
    /// Some schemes (like Basic) can send credentials before receiving a
    /// challenge, reducing round trips. Others (like Digest) require
    /// server-provided parameters first.
    fn supports_preemptive(&self) -> bool;

    /// Returns the authentication scheme this authenticator implements.
    fn scheme(&self) -> AuthScheme;
}

/// Dispatcher that routes authentication to the appropriate authenticator.
///
/// Holds a collection of authenticators and selects the correct one
/// based on the scheme requested by the server.
pub struct AuthDispatcher {
    authenticators: Vec<Box<dyn Authenticator>>,
}

impl AuthDispatcher {
    /// Creates a new dispatcher with all available authenticators.
    ///
    /// Automatically includes:
    /// - Basic authenticator (always)
    /// - Digest authenticator (if `auth-digest` feature is enabled)
    /// - NTLM authenticator (if `auth-ntlm` feature is enabled)
    ///
    /// # Returns
    ///
    /// A new `AuthDispatcher` with default authenticators registered.
    pub fn new() -> Self {
        let mut authenticators: Vec<Box<dyn Authenticator>> = Vec::new();
        authenticators.push(Box::new(basic::BasicAuthenticator));
        #[cfg(feature = "auth-digest")]
        authenticators.push(Box::new(digest::DigestAuthenticator::default()));
        #[cfg(feature = "auth-ntlm")]
        authenticators.push(Box::new(ntlm::NtlmAuthenticator::new()));
        AuthDispatcher { authenticators }
    }

    /// Creates a dispatcher with a custom set of authenticators.
    ///
    /// # Arguments
    ///
    /// * `authenticators` - A vector of boxed authenticator implementations.
    ///
    /// # Returns
    ///
    /// A new `AuthDispatcher` with the provided authenticators.
    pub fn with_authenticators(authenticators: Vec<Box<dyn Authenticator>>) -> Self {
        AuthDispatcher { authenticators }
    }

    /// Adds an authenticator to the dispatcher.
    ///
    /// # Arguments
    ///
    /// * `auth` - The authenticator to add.
    pub fn add(&mut self, auth: Box<dyn Authenticator>) {
        self.authenticators.push(auth);
    }

    /// Authenticates a request using the appropriate authenticator for the challenge.
    ///
    /// # Arguments
    ///
    /// * `challenge` - The authentication challenge from the server.
    /// * `credentials` - The user's credentials.
    /// * `request_method` - The HTTP method of the request.
    /// * `request_uri` - The URI path of the request.
    /// * `body` - The request body, if any.
    ///
    /// # Returns
    ///
    /// The authorization header value from the matching authenticator,
    /// or `Ok(None)` if no authenticator matches the challenge scheme.
    pub fn authenticate(
        &mut self,
        challenge: &AuthChallenge,
        credentials: &ut_core::types::Credentials,
        request_method: &str,
        request_uri: &str,
        body: Option<&[u8]>,
    ) -> Result<Option<String>, AuthError> {
        for auth in &mut self.authenticators {
            if auth.scheme() == challenge.scheme {
                return auth.authenticate(challenge, credentials, request_method, request_uri, body);
            }
        }
        Ok(None)
    }

    /// Attempts preemptive authentication for schemes that support it.
    ///
    /// Some authentication schemes (like Basic) can send credentials
    /// before receiving a challenge, which can reduce round trips.
    ///
    /// # Arguments
    ///
    /// * `credentials` - The user's credentials.
    /// * `request_uri` - The URI path of the request.
    ///
    /// # Returns
    ///
    /// The authorization header value from the first authenticator
    /// that supports preemptive auth, or `None` if none do.
    pub fn preemptive_auth(
        &mut self,
        credentials: &ut_core::types::Credentials,
        request_uri: &str,
    ) -> Option<String> {
        for auth in &mut self.authenticators {
            if auth.supports_preemptive() {
                let challenge = AuthChallenge {
                    scheme: auth.scheme(),
                    realm: None,
                    nonce: None,
                    opaque: None,
                    qop: None,
                    algorithm: None,
                    charset: None,
                    userhash: None,
                    stale: None,
                    domain: None,
                    ntlm_type2_msg: None,
                };
                let result = auth.authenticate(
                    &challenge,
                    credentials,
                    "GET",
                    request_uri,
                    None,
                );
                if let Ok(Some(header)) = result {
                    return Some(header);
                }
            }
        }
        None
    }
}

/// Parses multiple `WWW-Authenticate` header values into challenges.
///
/// HTTP responses may include multiple `WWW-Authenticate` headers,
/// each potentially containing multiple challenges.
///
/// # Arguments
///
/// * `headers` - Slice of raw header values.
///
/// # Returns
///
/// A vector of all parsed challenges across all headers.
pub fn parse_www_authenticate(headers: &[&str]) -> Vec<AuthChallenge> {
    let mut challenges = Vec::new();
    for header in headers {
        challenges.extend(AuthChallenge::from_www_authenticate(header));
    }
    challenges
}
