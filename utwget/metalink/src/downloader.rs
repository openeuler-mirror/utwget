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

/// Metalink file downloader with configurable mirror selection.
///
/// Handles downloading files from Metalink resources, selecting the best
/// mirror based on location, protocol, and preference settings.
///
/// # Example
///
/// ```no_run
/// use ut_metalink::downloader::MetalinkDownloader;
/// use ut_metalink::parser::MetalinkError;
/// use std::path::Path;
///
/// fn my_download(url: &str, path: &Path) -> Result<(), MetalinkError> {
///     // Implementation of actual download
///     Ok(())
/// }
///
/// let downloader = MetalinkDownloader::new(my_download)
///     .with_location("CN")
///     .with_protocols(vec!["HTTP".into(), "HTTPS".into()]);
/// ```
pub struct MetalinkDownloader {
    /// The function used to perform actual downloads.
    download_fn: DownloadFn,
    /// Preferred geographic location for mirror selection.
    preferred_location: Option<String>,
    /// List of allowed protocols for downloads.
    allowed_protocols: Vec<String>,
}

impl MetalinkDownloader {
    /// Creates a new Metalink downloader with the given download function.
    ///
    /// # Arguments
    ///
    /// * `download_fn` - Function that performs the actual file download.
    ///
    /// # Returns
    ///
    /// A new `MetalinkDownloader` instance with no location or protocol filters.
    pub fn new(download_fn: DownloadFn) -> Self {
        MetalinkDownloader {
            download_fn,
            preferred_location: None,
            allowed_protocols: Vec::new(),
        }
    }

    /// Sets the preferred geographic location for mirror selection.
    ///
    /// When set, mirrors in the preferred location will be prioritized
    /// over mirrors in other locations.
    ///
    /// # Arguments
    ///
    /// * `location` - The preferred location code (e.g., "CN", "US", "DE").
    ///
    /// # Returns
    ///
    /// The downloader instance for method chaining.
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.preferred_location = Some(location.into());
        self
    }

    /// Sets the allowed protocols for downloads.
    ///
    /// When set, only resources using the specified protocols will be
    /// considered for download.
    ///
    /// # Arguments
    ///
    /// * `protocols` - List of allowed protocol names (e.g., "HTTP", "HTTPS", "FTP").
    ///
    /// # Returns
    ///
    /// The downloader instance for method chaining.
    pub fn with_protocols(mut self, protocols: Vec<String>) -> Self {
        self.allowed_protocols = protocols;
        self
    }

    /// Downloads a file described in a Metalink document.
    ///
    /// Selects the best resource from the available mirrors, downloads the file,
    /// and verifies its checksum if available.
    ///
    /// # Arguments
    ///
    /// * `file` - The Metalink file entry to download.
    /// * `output_dir` - Directory where the file should be saved.
    ///
    /// # Returns
    ///
    /// A `DownloadResult` containing download information on success.
    ///
    /// # Errors
    ///
    /// * `MetalinkError::NoResources` - No suitable download resources available.
    /// * `MetalinkError::Download` - The download operation failed.
    /// * `MetalinkError::Io` - An I/O error occurred during verification.
    pub fn download(&self, file: &MetalinkFile, output_dir: &Path) -> Result<DownloadResult, MetalinkError> {
        let resource = self.select_best_resource(&file.resources)?;
        let output_path = output_dir.join(&file.name);

        info!("downloading {} from {}", file.name, resource.url);

        let start = Instant::now();
        (self.download_fn)(&resource.url, &output_path)
            .map_err(|e| MetalinkError::Download(format!("failed to download from {}: {}", resource.url, e)))?;
        let elapsed = start.elapsed();

        let bytes_downloaded = std::fs::metadata(&output_path)
            .map(|m| m.len())
            .unwrap_or(0);

        let checksum_verified = self.verify_file(file, &output_path)?;

        Ok(DownloadResult {
            file_path: output_path,
            bytes_downloaded,
            elapsed,
            checksum_verified,
        })
    }

    /// Selects the best resource from a list of available mirrors.
    ///
    /// Selection is performed in the following order:
    /// 1. Filter by allowed protocols (if configured).
    /// 2. Filter by preferred location (if configured).
    /// 3. Sort by preference value (higher is better).
    /// 4. Select the first resource with a non-empty URL.
    ///
    /// # Arguments
    ///
    /// * `resources` - List of available Metalink resources.
    ///
    /// # Returns
    ///
    /// A reference to the best resource on success.
    ///
    /// # Errors
    ///
    /// Returns `MetalinkError::NoResources` if no suitable resource is found.
    pub fn select_best_resource<'a>(&self, resources: &'a [MetalinkResource]) -> Result<&'a MetalinkResource, MetalinkError> {
        if resources.is_empty() {
            return Err(MetalinkError::NoResources);
        }

        let mut indices: Vec<usize> = (0..resources.len()).collect();

        if !self.allowed_protocols.is_empty() {
            let allowed: Vec<usize> = indices
                .iter()
                .filter(|&&i| {
                    resources[i]
                        .type_
                        .as_ref()
                        .map(|t| {
                            self.allowed_protocols
                                .iter()
                                .any(|p| t.eq_ignore_ascii_case(p))
                        })
                        .unwrap_or(true)
                })
                .copied()
                .collect();
            if !allowed.is_empty() {
                indices = allowed;
            }
        }

        if let Some(ref preferred_loc) = self.preferred_location {
            let local: Vec<usize> = indices
                .iter()
                .filter(|&&i| {
                    resources[i]
                        .location
                        .as_ref()
                        .map(|l| l.eq_ignore_ascii_case(preferred_loc))
                        .unwrap_or(false)
                })
                .copied()
                .collect();
            if !local.is_empty() {
                indices = local;
            }
        }

        indices.sort_by(|&a, &b| {
            let pa = resources[a].preference.unwrap_or(0);
            let pb = resources[b].preference.unwrap_or(0);
            pb.cmp(&pa)
        });

        indices
            .into_iter()
            .map(|i| &resources[i])
            .find(|r| !r.url.is_empty())
            .ok_or(MetalinkError::NoResources)
    }

    /// Verifies a downloaded file against the Metalink checksums.
    ///
    /// First tries to verify against full file hashes. If no hashes are
    /// available, verifies against piece hashes (chunk checksums).
    ///
    /// # Arguments
    ///
    /// * `file` - The Metalink file entry containing checksum information.
    /// * `path` - Path to the downloaded file.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Checksum verification passed.
    /// * `Ok(false)` - Checksum verification failed or no checksums available.
    ///
    /// # Errors
    ///
    /// Returns an error if an I/O error occurs during verification.
    pub fn verify_file(&self, file: &MetalinkFile, path: &Path) -> Result<bool, MetalinkError> {
        if !file.hashes.is_empty() {
            // Verify the first hash - if it matches, we're done
            if let Some(checksum) = file.hashes.first() {
                match checksum.verify(path) {
                    Ok(true) => {
                        debug!("checksum verified ({:?})", checksum.hash_type);
                        return Ok(true);
                    }
                    Ok(false) => {
                        warn!(
                            "checksum mismatch ({:?}): expected {}",
                            checksum.hash_type, checksum.expected
                        );
                        return Ok(false);
                    }
                    Err(e) => {
                        warn!("checksum verification error: {}", e);
                        return Err(e);
                    }
                }
            }
        }

        if !file.pieces.is_empty() {
            return self.verify_pieces(&file.pieces, path);
        }

        debug!("no checksums available for verification");
        Ok(false)
    }

    /// Verifies a file against piece hashes (chunk checksums).
    ///
    /// Reads the file in chunks and verifies each chunk against its
    /// expected hash value.
    ///
    /// # Arguments
    ///
    /// * `pieces` - List of piece hash specifications.
    /// * `path` - Path to the file to verify.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - All piece hashes match.
    /// * `Ok(false)` - One or more piece hashes do not match.
    ///
    /// # Errors
    ///
    /// Returns an error if an I/O error occurs while reading the file.
    fn verify_pieces(&self, pieces: &[MetalinkPiece], path: &Path) -> Result<bool, MetalinkError> {
        let file = std::fs::File::open(path).map_err(MetalinkError::Io)?;
        let mut reader = std::io::BufReader::new(file);

        let mut all_ok = true;
        for (i, piece) in pieces.iter().enumerate() {
            let mut buf = vec![0u8; piece.length as usize];
            let mut total_read: usize = 0;

            while total_read < buf.len() {
                let n = reader
                    .read(&mut buf[total_read..])
                    .map_err(MetalinkError::Io)?;
                if n == 0 {
                    break;
                }
                total_read += n;
            }

            buf.truncate(total_read);
            let actual =
                FileChecksum::compute(piece.hash_type.clone(), buf.as_slice())?;

            if actual.eq_ignore_ascii_case(&piece.hash) {
                debug!("piece {} verified", i);
            } else {
                warn!("piece {} hash mismatch: expected {}, got {}", i, piece.hash, actual);
                all_ok = false;
            }
        }

        Ok(all_ok)
    }
}
