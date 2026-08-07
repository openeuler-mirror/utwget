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

impl DigestAlgorithm {
    /// Parses an algorithm string from the WWW-Authenticate header into a `DigestAlgorithm`.
    ///
    /// # Arguments
    ///
    /// * `s` - The algorithm string (e.g. `"MD5"`, `"SHA-256"`, `"MD5-SESS"`).
    ///
    /// # Returns
    ///
    /// `Some(DigestAlgorithm)` if the string matches a known algorithm, `None` otherwise.
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "MD5" => Some(DigestAlgorithm::Md5),
            "SHA-256" | "SHA256" => Some(DigestAlgorithm::Sha256),
            "MD5-SESS" | "MD5_SESS" => Some(DigestAlgorithm::Md5Sess),
            "SHA-256-SESS" | "SHA256-SESS" => Some(DigestAlgorithm::Sha256Sess),
            _ => None,
        }
    }

    /// Computes the hex-encoded hash of `data` using the algorithm this variant represents.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw byte slice to hash.
    ///
    /// # Returns
    ///
    /// A lowercase hex-encoded digest string.
    fn hash_func(&self, data: &[u8]) -> String {
        match self {
            DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess => md5_hex(data),
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => sha256_hex(data),
        }
    }
}
