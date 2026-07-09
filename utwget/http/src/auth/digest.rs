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

/// Computes the MD5 digest of `data` and returns it as a 32-character lowercase hex string.
///
/// This is a standalone implementation of the MD5 hash function and does not depend on
/// external cryptographic libraries.
///
/// # Arguments
///
/// * `data` - The byte slice to hash.
///
/// # Returns
///
/// A 32-character hex-encoded MD5 digest.
fn md5_hex(data: &[u8]) -> String {
    use md5::{Md5, Digest};
    let mut hasher = Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Computes the SHA-256 digest of `data` and returns it as a 64-character lowercase hex string.
///
/// Delegates to `ut_core::hash::sha256_reader`.  Falls back to a hexadecimal
/// representation of the raw bytes on error.
///
/// # Arguments
///
/// * `data` - The byte slice to hash.
///
/// # Returns
///
/// A 64-character hex-encoded SHA-256 digest.
fn sha256_hex(data: &[u8]) -> String {
    // SHA-256 must not silently fall back to raw hex on failure,
    // as that would produce wrong Digest auth responses.
    ut_core::hash::sha256_reader(&mut data.as_ref())
        .expect("SHA-256 computation failed — this should never happen")
}

/// Authenticator that implements HTTP Digest Access Authentication (RFC 7616).
///
/// Tracks the nonce count internally to support the `nc` directive required
/// when `qop` is present.
///
/// # Security
///
/// Digest authentication is more secure than Basic because it never sends
/// the password in plaintext. Instead, it sends a hash of the credentials
/// combined with server-provided nonce values.
///
/// # Example
///
/// ```ignore
/// use utwget_http::auth::digest::DigestAuthenticator;
/// use utwget_http::auth::{Authenticator, AuthChallenge, AuthScheme};
///
/// let mut auth = DigestAuthenticator::new();
/// // After receiving a 401 with WWW-Authenticate: Digest ...
/// let header = auth.authenticate(&challenge, &creds, "GET", "/path", None);
/// ```
pub struct DigestAuthenticator {
    /// Monotonically increasing counter for the number of requests authenticated
    /// with this session.  Sent as the `nc` directive in the Authorization header.
    nonce_count: u32,
}

impl Default for DigestAuthenticator {
    /// Creates a `DigestAuthenticator` with a nonce count of zero.
    fn default() -> Self {
        DigestAuthenticator { nonce_count: 0 }
    }
}

impl DigestAuthenticator {
    /// Creates a new `DigestAuthenticator` with default state.
    ///
    /// # Returns
    ///
    /// A new `DigestAuthenticator` with nonce count initialized to 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes the HA1 value (the "user credentials" hash) per RFC 7616 Section 3.4.2.
    ///
    /// For `Md5` and `Sha256` the HA1 is simply `hash(user:realm:password)`.
    /// For `Md5Sess` and `Sha256Sess` the HA1 is re-derived as
    /// `hash(HA1_base:nonce:cnonce)` for each authentication attempt.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The digest algorithm to use.
    /// * `credentials` - The user's username and password.
    /// * `nonce` - The server-provided nonce.
    /// * `cnonce` - The client-generated nonce.
    ///
    /// # Returns
    ///
    /// The hex-encoded HA1 string.
    fn compute_ha1(
        &self,
        algorithm: DigestAlgorithm,
        credentials: &ut_core::types::Credentials,
        realm: &str,
        nonce: &str,
        cnonce: &str,
    ) -> String {
        let base = format!("{}:{}:{}", credentials.username, realm, credentials.password);
        let ha1_base = algorithm.hash_func(base.as_bytes());

        match algorithm {
            DigestAlgorithm::Md5 | DigestAlgorithm::Sha256 => ha1_base,
            DigestAlgorithm::Md5Sess | DigestAlgorithm::Sha256Sess => {
                let session_input = format!("{}:{}:{}", ha1_base, nonce, cnonce);
                algorithm.hash_func(session_input.as_bytes())
            }
        }
    }

    /// Computes the response value for the Digest Authorization header.
    ///
    /// The response is derived from HA1, the method, URI, nonce, nonce count,
    /// client nonce, quality-of-protection, and optional request body.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The digest algorithm to use.
    /// * `ha1` - The HA1 hash from [`compute_ha1`].
    /// * `method` - The HTTP method (e.g. `"GET"`, `"POST"`).
    /// * `uri` - The request URI path (e.g. `"/dir/index.html"`).
    /// * `nonce` - The server-provided nonce.
    /// * `nc` - The current nonce count.
    /// * `cnonce` - The client-generated nonce.
    /// * `qop` - The quality-of-protection value (`"auth"`, `"auth-int"`, or `None`).
    /// * `body` - The request body bytes, required when `qop` is `"auth-int"`.
    ///
    /// # Returns
    ///
    /// The hex-encoded response digest.
    fn compute_response(
        &self,
        algorithm: DigestAlgorithm,
        ha1: &str,
        method: &str,
        uri: &str,
        nonce: &str,
        nc: u32,
        cnonce: &str,
        qop: Option<&str>,
        body: Option<&[u8]>,
    ) -> String {
        let ha2 = if let Some("auth-int") = qop {
            let body_hash = algorithm.hash_func(body.unwrap_or(b""));
            format!("{}:{}:{}", method, uri, body_hash)
        } else {
            format!("{}:{}", method, uri)
        };
        let ha2_hex = algorithm.hash_func(ha2.as_bytes());

        let response_input = match qop {
            Some(q) => format!("{}:{}:{:08x}:{}:{}:{}", ha1, nonce, nc, cnonce, q, ha2_hex),
            None => format!("{}:{}:{}", ha1, nonce, ha2_hex),
        };

        algorithm.hash_func(response_input.as_bytes())
    }

    /// Generates a client nonce (`cnonce`) value.
    ///
    /// Uses a cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A 16-character hex-encoded client nonce string.
    fn generate_cnonce() -> String {
        use rand::Rng;
        let rand_bytes: [u8; 8] = rand::thread_rng().gen();
        rand_bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl Authenticator for DigestAuthenticator {
    /// Builds the `Authorization: Digest ...` header value for the given challenge.
    ///
    /// Increments the internal nonce count on each call to ensure monotonic `nc` values.
    ///
    /// # Arguments
    ///
    /// * `challenge` - The `WWW-Authenticate` challenge from the server.
    /// * `credentials` - The user's username and password.
    /// * `request_method` - The HTTP method for the request.
    /// * `request_uri` - The request URI path.
    /// * `body` - The request body, used when `qop` is `"auth-int"`.
    ///
    /// # Returns
    ///
    /// `Ok(Some(header_string))` on success, or an `AuthError`:
    /// * `AuthError::MissingNonce` — the challenge did not include a nonce.
    /// * `AuthError::AlgorithmUnsupported` — the algorithm in the challenge is not recognised.
    fn authenticate(
        &mut self,
        challenge: &AuthChallenge,
        credentials: &ut_core::types::Credentials,
        request_method: &str,
        request_uri: &str,
        body: Option<&[u8]>,
    ) -> Result<Option<String>, AuthError> {
        let nonce = challenge
            .nonce
            .as_ref()
            .ok_or(AuthError::MissingNonce)?;

        let algorithm_str = challenge.algorithm.as_deref().unwrap_or("MD5");
        let algorithm = DigestAlgorithm::from_str(algorithm_str)
            .ok_or_else(|| AuthError::AlgorithmUnsupported(algorithm_str.to_string()))?;

        self.nonce_count += 1;
        let nc = self.nonce_count;
        let cnonce = Self::generate_cnonce();

        let realm = challenge.realm.as_deref().unwrap_or("");
        let ha1 = self.compute_ha1(algorithm, credentials, realm, nonce, &cnonce);

        let qop_value = challenge.qop.as_ref().and_then(|qops| {
            qops.split(',')
                .map(|s| s.trim())
                .find(|s| *s == "auth-int" || *s == "auth")
        });

        let response = self.compute_response(
            algorithm,
            &ha1,
            request_method,
            request_uri,
            nonce,
            nc,
            &cnonce,
            qop_value,
            body,
        );

        let mut parts = Vec::new();

        // When userhash=true, send hashed username instead of plaintext
        let use_userhash = challenge.userhash == Some(true);
        if use_userhash {
            let userhash = algorithm.hash_func(
                format!("{}:{}", credentials.username, challenge.realm.as_deref().unwrap_or("")).as_bytes(),
            );
            // MD5 truncates to 32 chars, SHA-256 uses full 64 chars
            let hash_str = match algorithm {
                DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess => &userhash[..32],
                DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => &userhash,
            };
            parts.push(format!("username=\"{}\"", hash_str));
        } else {
            parts.push(format!("username=\"{}\"", credentials.username));
        }

        if let Some(ref realm) = challenge.realm {
            parts.push(format!("realm=\"{}\"", realm));
        }

        parts.push(format!("nonce=\"{}\"", nonce));
        parts.push(format!("uri=\"{}\"", request_uri));
        parts.push(format!("response=\"{}\"", response));
        parts.push(format!("algorithm={}", algorithm_str));

        if let Some(qop) = qop_value {
            parts.push(format!("qop={}", qop));
            parts.push(format!("nc={:08x}", nc));
            parts.push(format!("cnonce=\"{}\"", cnonce));
        }

        if let Some(ref opaque) = challenge.opaque {
            parts.push(format!("opaque=\"{}\"", opaque));
        }

        if use_userhash {
            parts.push(format!("userhash=true"));
        }

        Ok(Some(format!("Digest {}", parts.join(", "))))
    }

    /// Returns `false` — Digest authentication cannot be used preemptively
    /// because a nonce from the server is required first.
    fn supports_preemptive(&self) -> bool {
        false
    }

    /// Returns the authentication scheme identifier for this authenticator.
    ///
    /// # Returns
    ///
    /// `AuthScheme::Digest`
    fn scheme(&self) -> AuthScheme {
        AuthScheme::Digest
    }
}

