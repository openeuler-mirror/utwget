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
