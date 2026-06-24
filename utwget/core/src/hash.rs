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

const MD5_K: [u32; 64] = [
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

impl Md5Computer {
    /// Creates a new MD5 hash computer with initial state.
    fn new() -> Self {
        Md5Computer {
            a: 0x67452301,
            b: 0xefcdab89,
            c: 0x98badcfe,
            d: 0x10325476,
            buffer: Vec::with_capacity(MD5_BLOCK),
            len: 0,
        }
    }

    /// Updates the hash with additional data.
    ///
    /// # Arguments
    ///
    /// * `data` - Additional bytes to hash.
    fn update(&mut self, data: &[u8]) {
        self.len += data.len() as u64;
        self.buffer.extend_from_slice(data);
        while self.buffer.len() >= MD5_BLOCK {
            let block: [u8; MD5_BLOCK] = self.buffer[..MD5_BLOCK].try_into().unwrap();
            self.buffer.drain(..MD5_BLOCK);
            self.process_block(&block);
        }
    }

    /// Finalizes the hash computation and returns the digest.
    ///
    /// # Returns
    ///
    /// The 16-byte MD5 digest.
    fn finalize(mut self) -> [u8; MD5_DIGEST] {
        let bit_len = self.len as u64 * 8;
        self.buffer.push(0x80);
        while (self.buffer.len() % MD5_BLOCK) != 56 {
            self.buffer.push(0);
        }
        self.buffer.extend_from_slice(&bit_len.to_le_bytes());
        self.buffer.extend_from_slice(&((bit_len >> 32) as u32).to_le_bytes());

        while self.buffer.len() >= MD5_BLOCK {
            let block: [u8; MD5_BLOCK] = self.buffer[..MD5_BLOCK].try_into().unwrap();
            self.buffer.drain(..MD5_BLOCK);
            self.process_block(&block);
        }

        let mut result = [0u8; MD5_DIGEST];
        result[0..4].copy_from_slice(&self.a.to_le_bytes());
        result[4..8].copy_from_slice(&self.b.to_le_bytes());
        result[8..12].copy_from_slice(&self.c.to_le_bytes());
        result[12..16].copy_from_slice(&self.d.to_le_bytes());
        result
    }

    /// Processes a single 64-byte block.
    ///
    /// Implements the MD5 compression function.
    ///
    /// # Arguments
    ///
    /// * `block` - A 64-byte block to process.
    fn process_block(&mut self, block: &[u8; MD5_BLOCK]) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }

        let (mut a, mut b, mut c, mut d) = (self.a, self.b, self.c, self.d);

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
            let f = f.wrapping_add(MD5_K[i]).wrapping_add(m[g]).wrapping_add(a);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(MD5_S[i]));
        }

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
    }
}
