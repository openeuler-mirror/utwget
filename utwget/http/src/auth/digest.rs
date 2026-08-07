//! HTTP Digest Access Authentication implementation (RFC 7616).
//!
//! This module provides a Digest authenticator that supports MD5 and SHA-256
//! hash algorithms, including their session variants. Digest authentication
//! is more secure than Basic authentication as it does not send passwords
//! in plaintext.

use super::{AuthChallenge, AuthError, AuthScheme, Authenticator};

/// Supported digest authentication algorithms.
///
/// Maps to the `algorithm` directive in the WWW-Authenticate header.
/// Includes MD5, SHA-256, and their session-variant counterparts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    /// MD5 message digest algorithm (RFC 7616 default).
    Md5,
    /// SHA-256 hash algorithm.
    Sha256,
    /// MD5 with session key — the HA1 is re-derived per nonce/cnonce pair.
    Md5Sess,
    /// SHA-256 with session key.
    Sha256Sess,
}
