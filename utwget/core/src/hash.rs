//! Cryptographic hash functions for file integrity verification.
//!
//! This module provides SHA-1, SHA-256, and MD5 hash computation
//! for verifying downloaded file integrity.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};

/// Computes SHA-1 hash of a file.
///
/// # Arguments
///
/// * `path` - Path to the file to hash.
///
/// # Returns
///
/// The SHA-1 hash as a lowercase hexadecimal string.
///
/// # Errors
///
/// Returns an IO error if the file cannot be opened or read.
///
/// # Example
///
/// ```no_run
/// use ut_core::hash::sha1_file;
/// use std::path::Path;
///
/// let hash = sha1_file(Path::new("file.txt"))?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn sha1_file(path: &std::path::Path) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    sha1_reader(&mut reader)
}

/// Computes SHA-1 hash from a reader.
///
/// # Arguments
///
/// * `reader` - A reader providing the data to hash.
///
/// # Returns
///
/// The SHA-1 hash as a lowercase hexadecimal string.
///
/// # Errors
///
/// Returns an IO error if the reader fails.
pub fn sha1_reader<R: Read>(reader: &mut R) -> std::io::Result<String> {
    let mut hasher = sha1::Sha1::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

/// Computes SHA-256 hash of a file.
///
/// # Arguments
///
/// * `path` - Path to the file to hash.
///
/// # Returns
///
/// The SHA-256 hash as a lowercase hexadecimal string.
///
/// # Errors
///
/// Returns an IO error if the file cannot be opened or read.
///
/// # Example
///
/// ```no_run
/// use ut_core::hash::sha256_file;
/// use std::path::Path;
///
/// let hash = sha256_file(Path::new("file.txt"))?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    sha256_reader(&mut reader)
}
