//! Metalink file downloader module.
//!
//! This module provides the `MetalinkDownloader` struct for downloading files
//! described in Metalink documents, with support for mirror selection,
//! protocol filtering, and checksum verification.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use crate::checksum::FileChecksum;
use crate::parser::{MetalinkError, MetalinkFile, MetalinkPiece, MetalinkResource};

/// Function type for performing the actual download.
///
/// Takes a URL and destination path, returns success or an error.
type DownloadFn = fn(&str, &Path) -> Result<(), MetalinkError>;

/// Result of a Metalink file download operation.
///
/// Contains information about the downloaded file including its path,
/// size, download duration, and checksum verification status.
#[derive(Debug)]
pub struct DownloadResult {
    /// Path where the file was saved.
    pub file_path: PathBuf,
    /// Number of bytes downloaded.
    pub bytes_downloaded: u64,
    /// Time elapsed during the download.
    pub elapsed: Duration,
    /// Whether the checksum verification passed.
    ///
    /// `true` if verification succeeded, `false` if verification failed
    /// or no checksums were available.
    pub checksum_verified: bool,
}
