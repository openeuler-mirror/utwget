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
    let a: u32 = 0x67452301;
    let b: u32 = 0xefcdab89;
    let c: u32 = 0x98badcfe;
    let d: u32 = 0x10325476;

    let mut state = [a, b, c, d];
    let mut h = [0u8; 16];

    let padded_len = ((data.len() + 8 + 63) / 64) * 64;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len()].copy_from_slice(data);
    padded[data.len()] = 0x80;

    let bit_len = (data.len() as u64) * 8;
    padded[padded_len - 8..].copy_from_slice(&bit_len.to_le_bytes());

    for block_start in (0..padded_len).step_by(64) {
        let block: [u8; 64] = padded[block_start..block_start + 64].try_into().unwrap();

        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }

        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);

        let s: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];

        let k: [u32; 64] = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
        ];

        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((d & b) | (!d & c), (i * 5 + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (i * 3 + 5) % 16)
            } else {
                (c ^ (b | !d), (i * 7) % 16)
            };
            let f = f.wrapping_add(k[i]).wrapping_add(m[g]).wrapping_add(a);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(s[i]));
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    for (i, &s) in state.iter().enumerate() {
        h[i * 4..i * 4 + 4].copy_from_slice(&s.to_le_bytes());
    }

    h.iter().map(|b| format!("{:02x}", b)).collect()
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
    ut_core::hash::sha256_reader(&mut data.as_ref()).unwrap_or_else(|_| {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    })
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
        nonce: &str,
        cnonce: &str,
    ) -> String {
        let base = format!("{}:{}", credentials.username, credentials.password);
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
    /// The cnonce is derived from the current system timestamp (nanoseconds since epoch)
    /// and the process ID, producing a 16-character hex string.
    ///
    /// # Returns
    ///
    /// A hex-encoded client nonce string.
    fn generate_cnonce() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let rand_bytes: [u8; 8] = std::array::from_fn(|_| {
            ((timestamp & 0xFF) as u8).wrapping_add(((timestamp >> 8) as u8).wrapping_add(std::process::id() as u8))
        });
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

        let ha1 = self.compute_ha1(algorithm, credentials, nonce, &cnonce);

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
        parts.push(format!("username=\"{}\"", credentials.username));

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

        if let Some(true) = challenge.userhash {
            let userhash = algorithm.hash_func(
                format!("{}:{}", credentials.username, challenge.realm.as_deref().unwrap_or("")).as_bytes(),
            );
            parts.push(format!("userhash=true"));
            parts.push(format!("username=\"{}\"", &userhash[..userhash.len().min(32)]));
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
