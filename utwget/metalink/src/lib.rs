//! Metalink support for utwget.
//!
//! This crate provides parsing and downloading support for Metalink files
//! (RFC 5854 / RFC 6249), which describe downloadable files along with their
//! checksums, mirrors, and other metadata.  It is used by utwget when the
//! `--metalink` option is active.
//!
//! # Submodules
//!
//! * [`checksum`] — Checksum types and operations.
//! * [`downloader`] — The high-level Metalink download engine.
//! * [`parser`] — Metalink XML parsing, file/resource/piece types, and error handling.

/// Checksum computation and verification support.
pub mod checksum;

/// Metalink-aware download logic and result reporting.
pub mod downloader;

/// Metalink XML parser, data types, and error enums.
pub mod parser;

/// Re-exported checksum types for convenience.
pub use checksum::{ChecksumType, FileChecksum};

/// Re-exported downloader types for convenience.
pub use downloader::{DownloadResult, MetalinkDownloader};

/// Re-exported parser types for convenience.
pub use parser::{MetalinkError, MetalinkFile, MetalinkParser, MetalinkPiece, MetalinkResource};
