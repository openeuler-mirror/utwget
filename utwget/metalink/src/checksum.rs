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
