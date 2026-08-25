//! Checksum verification module for Metalink downloads.
//!
//! This module provides checksum types and verification functions for validating
//! downloaded files against expected hash values specified in Metalink documents.

use std::io::Read;
use std::path::Path;

use md5::Digest;

use crate::MetalinkError;

/// Supported checksum hash algorithm types.
///
/// These are the hash algorithms supported by the Metalink specification
/// for file integrity verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumType {
    /// MD5 hash algorithm (128-bit).
    Md5,
    /// SHA-1 hash algorithm (160-bit).
    Sha1,
    /// SHA-256 hash algorithm (256-bit).
    Sha256,
}

impl ChecksumType {
    /// Parses a checksum type from a string representation.
    ///
    /// Supports common variations of hash algorithm names, case-insensitively.
    ///
    /// # Arguments
    ///
    /// * `s` - The string representation of the hash algorithm.
    ///
    /// # Returns
    ///
    /// Returns `Some(ChecksumType)` if the string is recognized, otherwise `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ut_metalink::checksum::ChecksumType;
    /// assert_eq!(ChecksumType::from_str("md5"), Some(ChecksumType::Md5));
    /// assert_eq!(ChecksumType::from_str("SHA-256"), Some(ChecksumType::Sha256));
    /// assert_eq!(ChecksumType::from_str("unknown"), None);
    /// ```
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "md5" => Some(ChecksumType::Md5),
            "sha1" | "sha-1" => Some(ChecksumType::Sha1),
            "sha256" | "sha-256" => Some(ChecksumType::Sha256),
            _ => None,
        }
    }
}

/// Represents a file checksum with its hash type and expected value.
///
/// This struct is used to store checksum information parsed from a Metalink
/// document and provides methods to verify downloaded files.
#[derive(Debug, Clone)]
pub struct FileChecksum {
    /// The hash algorithm used for this checksum.
    pub hash_type: ChecksumType,
    /// The expected hash value as a lowercase hexadecimal string.
    pub expected: String,
}

impl FileChecksum {
    /// Verifies a file against the expected checksum.
    ///
    /// Computes the hash of the file at the given path and compares it
    /// with the expected value.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to verify.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - The file hash matches the expected checksum.
    /// * `Ok(false)` - The file hash does not match.
    /// * `Err(MetalinkError)` - An I/O error occurred while reading the file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or read.
    pub fn verify(&self, path: &Path) -> Result<bool, MetalinkError> {
        let file = std::fs::File::open(path).map_err(MetalinkError::Io)?;
        let mut reader = std::io::BufReader::new(file);
        let actual = Self::compute(self.hash_type.clone(), &mut reader)?;
        Ok(actual.eq_ignore_ascii_case(&self.expected))
    }

    /// Computes the MD5 hash of data from a reader.
    ///
    /// Reads all data from the reader and computes its MD5 hash.
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
    /// Returns an error if reading from the reader fails.
    pub fn compute_md5(mut reader: impl Read) -> Result<String, MetalinkError> {
        let mut hasher = md5::Md5::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf).map_err(MetalinkError::Io)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect())
    }

    /// Computes the SHA-1 hash of data from a reader.
    ///
    /// Reads all data from the reader and computes its SHA-1 hash.
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
    /// Returns an error if reading from the reader fails.
    pub fn compute_sha1(mut reader: impl Read) -> Result<String, MetalinkError> {
        let mut hasher = sha1::Sha1::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf).map_err(MetalinkError::Io)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect())
    }

    /// Computes the SHA-256 hash of data from a reader.
    ///
    /// Reads all data from the reader and computes its SHA-256 hash.
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
    /// Returns an error if reading from the reader fails.
    pub fn compute_sha256(mut reader: impl Read) -> Result<String, MetalinkError> {
        let mut hasher = sha2::Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf).map_err(MetalinkError::Io)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect())
    }

    /// Computes a hash of data from a reader using the specified algorithm.
    ///
    /// Dispatches to the appropriate hash function based on the checksum type.
    ///
    /// # Arguments
    ///
    /// * `hash_type` - The hash algorithm to use.
    /// * `reader` - A reader providing the data to hash.
    ///
    /// # Returns
    ///
    /// The computed hash as a lowercase hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the reader fails.
    pub fn compute(hash_type: ChecksumType, reader: impl Read) -> Result<String, MetalinkError> {
        match hash_type {
            ChecksumType::Md5 => Self::compute_md5(reader),
            ChecksumType::Sha1 => Self::compute_sha1(reader),
            ChecksumType::Sha256 => Self::compute_sha256(reader),
        }
    }
}
