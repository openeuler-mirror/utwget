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
