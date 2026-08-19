//! OPIE (One-Time Passwords in Everything) authentication support.
//!
//! This module implements OPIE/S/Key one-time password authentication
//! for FTP servers that support it. OPIE provides secure authentication
//! using one-time passwords that are computed from a secret passphrase
//! and a challenge from the server.

/// An OPIE challenge received from the server.
///
/// The challenge contains the sequence number (which determines how many
/// hash iterations to perform), the seed (used to salt the hash), and
/// the hash algorithm to use.
pub struct OpieChallenge {
    /// The sequence number (decrements with each use).
    pub sequence: u64,
    /// The seed string for salting the hash.
    pub seed: String,
    /// The hash algorithm to use.
    pub algorithm: OpieAlgorithm,
}

/// The hash algorithm used for OPIE computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpieAlgorithm {
    /// MD4 hash algorithm.
    Md4,
    /// MD5 hash algorithm.
    Md5,
    /// SHA-1 hash algorithm.
    Sha1,
}

/// An OPIE response to send to the server.
pub struct OpieResponse {
    /// The one-time password as a hexadecimal string.
    pub response_hex: String,
}

/// Parse an OPIE challenge from a server prompt.
///
/// The prompt typically looks like:
/// - `otp-md5 498 wi12345`
/// - `s/key 498 wi12345`
///
/// # Arguments
///
/// * `prompt` - The challenge string from the server.
///
/// # Returns
///
/// `Some(OpieChallenge)` if the prompt is recognized as an OPIE challenge,
/// `None` otherwise.
pub fn parse_opie_challenge(prompt: &str) -> Option<OpieChallenge> {
    let prompt = prompt.trim();

    if !prompt.contains("otp-") && !prompt.contains("s/key") {
        return None;
    }

    let ext = if let Some(start) = prompt.find("otp-") {
        let rest = &prompt[start + 4..];
        let end = rest.find(' ').or_else(|| rest.find(':'))?;
        let ext = &rest[..end];
        parse_opie_ext(ext)?
    } else if let Some(start) = prompt.find("s/key") {
        let rest = &prompt[start + 5..].trim_start();
        let ext = rest.split_whitespace().next()?;
        parse_opie_ext(ext)?
    } else {
        return None;
    };

    let parts: Vec<&str> = prompt.split_whitespace().collect();
    let seq_str = parts.iter().find(|p| p.parse::<u64>().is_ok())?;
    let sequence: u64 = seq_str.parse().ok()?;

    let seed = parts.iter()
        .find(|p| !p.parse::<u64>().is_ok() && !p.contains("otp-") && !p.contains("s/key"))
        .map(|s| s.trim_end_matches(':').to_string())
        .unwrap_or_default();

    if seed.is_empty() {
        return None;
    }

    Some(OpieChallenge {
        sequence,
        seed,
        algorithm: ext,
    })
}
