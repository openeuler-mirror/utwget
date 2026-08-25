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
