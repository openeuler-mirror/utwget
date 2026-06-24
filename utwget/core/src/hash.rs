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

/// Computes SHA-256 hash from a reader.
///
/// # Arguments
///
/// * `reader` - A reader providing the data to hash.
///
/// # Returns
///
/// The SHA-256 hash as a lowercase hexadecimal string.
///
/// # Errors
///
/// Returns an IO error if the reader fails.
pub fn sha256_reader<R: Read>(reader: &mut R) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
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

/// Computes MD5 hash of a file.
///
/// # Arguments
///
/// * `path` - Path to the file to hash.
///
/// # Returns
///
/// The MD5 hash as a lowercase hexadecimal string.
///
/// # Errors
///
/// Returns an IO error if the file cannot be opened or read.
///
/// # Example
///
/// ```no_run
/// use ut_core::hash::md5_file;
/// use std::path::Path;
///
/// let hash = md5_file(Path::new("file.txt"))?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn md5_file(path: &std::path::Path) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    md5_reader(&mut reader)
}

/// Computes MD5 hash from a reader.
///
/// # Arguments
///
/// * `reader` - A reader providing the data to hash.
///
/// # Returns
///
/// The MD5 hash as a lowercase hexadecimal string.
///
/// # Errors
///
/// Returns an IO error if the reader fails.
pub fn md5_reader<R: Read>(reader: &mut R) -> std::io::Result<String> {
    let mut hasher = Md5Computer::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

/// Converts bytes to lowercase hexadecimal string.
///
/// # Arguments
///
/// * `bytes` - The bytes to encode.
///
/// # Returns
///
/// A string of two hex digits per byte.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// MD5 hash computation state.
///
/// Implements the MD5 algorithm as specified in RFC 1321.
struct Md5Computer {
    /// State variable A.
    a: u32,
    /// State variable B.
    b: u32,
    /// State variable C.
    c: u32,
    /// State variable D.
    d: u32,
    /// Buffer for partial blocks.
    buffer: Vec<u8>,
    /// Total length of input data.
    len: u64,
}

const MD5_BLOCK: usize = 64;
const MD5_DIGEST: usize = 16;

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
