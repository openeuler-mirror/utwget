//! Metalink XML document parser module.
//!
//! This module provides structures and functions for parsing Metalink XML
//! documents, which describe files available for download from multiple
//! mirrors with checksum verification.

use std::io::BufRead;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::checksum::ChecksumType;
use crate::FileChecksum;

/// Represents a file entry in a Metalink document.
///
/// Contains all metadata about a downloadable file including its name,
/// size, checksums, piece hashes, and available download resources.
#[derive(Debug, Clone)]
pub struct MetalinkFile {
    /// The name of the file.
    pub name: String,
    /// The file size in bytes, if specified.
    pub size: Option<u64>,
    /// Full file checksums for verification.
    pub hashes: Vec<FileChecksum>,
    /// Piece (chunk) hashes for partial verification.
    pub pieces: Vec<MetalinkPiece>,
    /// Available download resources (mirrors).
    pub resources: Vec<MetalinkResource>,
    /// Identity string for the file, if specified.
    pub identity: Option<String>,
    /// Version string for the file, if specified.
    pub version: Option<String>,
    /// Human-readable description of the file.
    pub description: Option<String>,
}

/// Represents a download resource (mirror) in a Metalink document.
///
/// Each resource provides a URL from which the file can be downloaded,
/// along with metadata about the resource's protocol and preference.
#[derive(Debug, Clone)]
pub struct MetalinkResource {
    /// The URL for downloading the file.
    pub url: String,
    /// The protocol type (e.g., "HTTP", "HTTPS", "FTP").
    pub type_: Option<String>,
    /// Preference value (higher is better).
    pub preference: Option<i32>,
    /// Maximum number of concurrent connections allowed.
    pub max_connections: Option<u32>,
    /// Geographic location code (e.g., "CN", "US", "DE").
    pub location: Option<String>,
}

/// Represents a piece (chunk) hash for partial file verification.
///
/// Metalink documents can specify hashes for individual pieces of a file,
/// allowing verification during download or for partial recovery.
#[derive(Debug, Clone)]
pub struct MetalinkPiece {
    /// Length of this piece in bytes.
    pub length: u64,
    /// Expected hash value as a hexadecimal string.
    pub hash: String,
    /// The hash algorithm used.
    pub hash_type: ChecksumType,
}

/// Error types for Metalink operations.
///
/// These errors can occur during parsing, downloading, or verification
/// of Metalink documents and their associated files.
#[derive(Debug, thiserror::Error)]
pub enum MetalinkError {
    /// Error parsing the Metalink document structure.
    #[error("metalink parse error: {0}")]
    Parse(String),
    /// Error parsing the XML structure.
    #[error("metalink XML error: {0}")]
    Xml(#[from] quick_xml::Error),
    /// I/O error during file operations.
    #[error("metalink I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Error during checksum computation or verification.
    #[error("metalink checksum error: {0}")]
    Checksum(String),
    /// Error during file download.
    #[error("metalink download error: {0}")]
    Download(String),
    /// No download resources available for a file.
    #[error("no resources available for download")]
    NoResources,
}
