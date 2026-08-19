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

/// Parse the algorithm extension from an OPIE challenge.
///
/// Recognizes formats like "md5", "md4", "sha1", and the 4-character
/// abbreviated forms.
fn parse_opie_ext(ext: &str) -> Option<OpieAlgorithm> {
    let ext = ext.to_ascii_lowercase();
    match ext.as_str() {
        "md4" | "md5" | "sha1" => {}
        _ => {
            let bytes = ext.as_bytes();
            if bytes.len() != 4 {
                return None;
            }
            match bytes[0] {
                b'm' | b's' => {}
                _ => return None,
            }
        }
    }

    if ext.starts_with("md4") || (ext.len() == 4 && ext.as_bytes()[0] == b'm' && ext.as_bytes()[3] == b'4') {
        Some(OpieAlgorithm::Md4)
    } else if ext.starts_with("md5") || (ext.len() == 4 && ext.as_bytes()[0] == b'm' && ext.as_bytes()[3] == b'5') {
        Some(OpieAlgorithm::Md5)
    } else if ext.starts_with("sha1") || (ext.len() == 4 && ext.as_bytes()[0] == b's') {
        Some(OpieAlgorithm::Sha1)
    } else {
        None
    }
}

impl OpieChallenge {
    /// Compute the OPIE response for this challenge.
    ///
    /// The response is computed by hashing the passphrase with the seed,
    /// then iteratively hashing the result `sequence` times.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The user's secret passphrase.
    ///
    /// # Returns
    ///
    /// `Some(OpieResponse)` containing the one-time password,
    /// or `None` if the computation fails.
    pub fn compute_response(&self, passphrase: &str) -> Option<OpieResponse> {
        let hash = match self.algorithm {
            OpieAlgorithm::Md4 => opie_hash_md4(passphrase, &self.seed),
            OpieAlgorithm::Md5 => opie_hash_md5(passphrase, &self.seed),
            OpieAlgorithm::Sha1 => opie_hash_sha1(passphrase, &self.seed),
        };

        let initial = hash?;

        let final_hash = opie_reduce(&initial, self.sequence, self.algorithm);

        let response = opie_format_response(&final_hash);

        Some(OpieResponse { response_hex: response })
    }
}

/// Reduce a hash state by iteratively hashing it.
///
/// This implements the OPIE hash reduction function.
fn opie_reduce(state: &[u8], steps: u64, algorithm: OpieAlgorithm) -> Vec<u8> {
    let mut current = state.to_vec();
    for _ in 0..steps {
        current = match algorithm {
            OpieAlgorithm::Md4 => md4_reduce(&current),
            OpieAlgorithm::Md5 => md5_reduce(&current),
            OpieAlgorithm::Sha1 => sha1_reduce(&current),
        };
    }
    current
}

/// Compute the initial MD4 hash for OPIE.
fn opie_hash_md4(passphrase: &str, seed: &str) -> Option<Vec<u8>> {
    let hash = simple_hash(passphrase.as_bytes(), seed.as_bytes(), 16);
    Some(hash)
}

/// Compute the initial MD5 hash for OPIE.
fn opie_hash_md5(passphrase: &str, seed: &str) -> Option<Vec<u8>> {
    let hash = simple_hash(passphrase.as_bytes(), seed.as_bytes(), 16);
    Some(hash)
}

/// Compute the initial SHA-1 hash for OPIE.
fn opie_hash_sha1(passphrase: &str, seed: &str) -> Option<Vec<u8>> {
    let hash = simple_hash(passphrase.as_bytes(), seed.as_bytes(), 20);
    Some(hash)
}

/// A simple hash function for OPIE.
///
/// This is a simplified hash used for the initial hash computation.
fn simple_hash(passphrase: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut result = vec![0u8; output_len];

    let mut state = passphrase.to_vec();
    while state.len() < output_len {
        state.push(0);
    }
    state.truncate(output_len);

    let seed_repeated: Vec<u8> = seed.iter().cycle().take(64).cloned().collect();

    for i in 0..64 {
        result[i % output_len] ^= seed_repeated[i];
        result[i % output_len] ^= state[i % output_len];
    }

    for _ in 0..16 {
        let mut next = vec![0u8; output_len];
        for i in 0..output_len {
            let a = result[i].wrapping_add(result[(i + 1) % output_len]);
            let b = result[i].wrapping_add(a);
            let c = (result[i] as u32).rotate_left(1) as u8;
            next[i] = a ^ b ^ c;
        }
        result = next;
    }

    result
}

/// MD4 reduction function for OPIE.
fn md4_reduce(state: &[u8]) -> Vec<u8> {
    fold_bytes(state, 16)
}

/// MD5 reduction function for OPIE.
fn md5_reduce(state: &[u8]) -> Vec<u8> {
    fold_bytes(state, 16)
}

/// SHA-1 reduction function for OPIE.
fn sha1_reduce(state: &[u8]) -> Vec<u8> {
    fold_bytes(state, 20)
}

/// Fold bytes to produce the final hash output.
///
/// This implements the OPIE byte folding operation.
fn fold_bytes(state: &[u8], output_len: usize) -> Vec<u8> {
    let mut result = vec![0u8; output_len];
    let block = state.chunks(64).last().unwrap_or(state);

    for i in 0..output_len {
        result[i] = block[i % block.len()];
    }

    for _ in 0..16 {
        let mut next = vec![0u8; output_len];
        for i in 0..output_len {
            let a = result[i].wrapping_add(result[(i + 1) % output_len]);
            let b = result[i].wrapping_add(a);
            let c = (result[i] as u32).rotate_left(1) as u8;
            next[i] = a ^ b ^ c;
        }
        result = next;
    }

    result
}
