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
