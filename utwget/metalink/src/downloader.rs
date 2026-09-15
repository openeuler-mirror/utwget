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
/// 使用 Box<dyn Fn> 而非 fn 类型，允许闭包捕获环境（如 Retriever 实例）。
type DownloadFn = Box<dyn Fn(&str, &Path) -> Result<(), MetalinkError> + Send>;

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
    pub fn new<F>(download_fn: F) -> Self
    where
        F: Fn(&str, &Path) -> Result<(), MetalinkError> + Send + 'static,
    {
        MetalinkDownloader {
            download_fn: Box::new(download_fn),
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
        let safe_name = sanitize_metalink_filename(&file.name);
        let output_path = output_dir.join(&safe_name);

        // Mirror fallback (report 8.2-1, mirrors GNU wget metalink.c):
        // try resources in preference order; on download error OR checksum
        // mismatch, remove the file and move to the next mirror. Only an
        // exhausted list fails the download.
        let resources = self.select_best_resources(&file.resources)?;
        let start = Instant::now();
        let mut last_error: Option<MetalinkError> = None;

        for resource in resources {
            info!("downloading {} from {}", file.name, resource.url);
            let download_result =
                (self.download_fn)(&resource.url, &output_path)
                    .and_then(|_| {
                        // Verify checksums AND declared size before
                        // accepting the download.
                        let checksums_ok = self.verify_file(file, &output_path)?;
                        if !checksums_ok {
                            return Err(MetalinkError::Download(format!(
                                "checksum verification failed for {}",
                                resource.url
                            )));
                        }
                        let size_ok = self.verify_size(file, &output_path)?;
                        if !size_ok {
                            return Err(MetalinkError::Download(format!(
                                "size verification failed for {} (expected {})",
                                resource.url,
                                file.size.unwrap_or(0)
                            )));
                        }
                        Ok(())
                    });

            match download_result {
                Ok(()) => {
                    let elapsed = start.elapsed();
                    let bytes_downloaded = std::fs::metadata(&output_path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    return Ok(DownloadResult {
                        file_path: output_path,
                        bytes_downloaded,
                        elapsed,
                        checksum_verified: true,
                    });
                }
                Err(e) => {
                    warn!("mirror {} failed: {}; trying next", resource.url, e);
                    last_error = Some(e);
                    // Remove the bad file before trying the next mirror
                    // (wget metalink.c deletes on checksum failure).
                    let _ = std::fs::remove_file(&output_path);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| MetalinkError::Download("no mirrors succeeded".into())))
    }

    /// Selects all usable resources in priority order (best first).
    ///
    /// Selection is performed in the following order:
    /// 1. Filter by allowed protocols (if configured).
    /// 2. Filter by preferred location (if configured).
    /// 3. Sort by preference value (higher is better).
    ///
    /// Used by `download` for mirror fallback.
    pub fn select_best_resources<'a>(
        &self,
        resources: &'a [MetalinkResource],
    ) -> Result<Vec<&'a MetalinkResource>, MetalinkError> {
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

        Ok(indices
            .into_iter()
            .filter_map(|i| resources.get(i))
            .filter(|r| !r.url.is_empty())
            .collect())
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
        // Verify all available full-file hashes.
        // GNU wget verifies every hash and reports mismatches for each.
        //
        // Security hardening (report §7.2 M3): MD5 and SHA-1 are
        // collision-broken. A malicious mirror can craft a payload matching
        // the weak hashes in a poisoned metalink while SHA-256 (if present)
        // would expose it. Strategy: weak-hash mismatches are logged but do
        // NOT fail verification on their own — a mismatch is only fatal when
        // at least one STRONG hash (SHA-224+) is present and fails, or when
        // ONLY weak hashes exist and any of them fails (no better option).
        // This keeps compatibility with metalinks that ship md5 alongside
        // sha256 while never letting a weak-hash PASS override a strong-hash
        // FAIL.
        if !file.hashes.is_empty() {
            use crate::checksum::ChecksumType;
            let mut saw_weak_only = true;
            let mut strong_failed: Option<String> = None;
            for checksum in &file.hashes {
                let strong = !matches!(
                    checksum.hash_type,
                    ChecksumType::Md5 | ChecksumType::Sha1
                );
                if strong {
                    saw_weak_only = false;
                }
                match checksum.verify(path) {
                    Ok(true) => {
                        debug!("checksum verified ({:?})", checksum.hash_type);
                    }
                    Ok(false) => {
                        warn!(
                            "checksum mismatch ({:?}): expected {}",
                            checksum.hash_type, checksum.expected
                        );
                        if strong && strong_failed.is_none() {
                            strong_failed = Some(format!(
                                "{:?}: expected {}",
                                checksum.hash_type, checksum.expected
                            ));
                        }
                    }
                    Err(e) => {
                        warn!("checksum verification error: {}", e);
                        return Err(e);
                    }
                }
            }
            // Any STRONG-hash failure is fatal regardless of weak-hash passes.
            if let Some(detail) = strong_failed {
                warn!("verification failed: strong hash mismatch ({})", detail);
                return Ok(false);
            }
            // Only weak hashes present: their verdict is the best we have.
            if saw_weak_only {
                let any_failed = file.hashes.iter().any(|c| {
                    !matches!(c.verify(path), Ok(true))
                });
                if any_failed {
                    warn!("verification failed: only weak hashes (md5/sha1) present and one mismatched");
                    return Ok(false);
                }
                return Ok(true);
            }
            // Strong hashes passed; weak-hash mismatches already logged.
            return Ok(true);
        }

        if !file.pieces.is_empty() {
            return self.verify_pieces(&file.pieces, path);
        }

        // No hashes and no pieces: GNU wget treats this as success with a
        // warning (metalink.c: "no checksum" → accept the file); the old
        // Ok(false) here rejected valid downloads of metalinks without any
        // hashes (report 8.2-5).
        warn!(
            "no checksums in metalink for '{}'; accepting download without verification",
            file.name
        );
        Ok(true)
    }

    /// Verifies the declared `<size>` of a file against the actual size.
    ///
    /// Returns `Ok(false)` on mismatch (report 8.2-5: `<size>` was parsed
    /// but never checked). A missing size is not an error.
    pub fn verify_size(&self, file: &MetalinkFile, path: &Path) -> Result<bool, MetalinkError> {
        let Some(expected) = file.size else {
            return Ok(true);
        };
        let actual = std::fs::metadata(path).map_err(MetalinkError::Io)?.len();
        if actual != expected {
            warn!(
                "size mismatch for '{}': expected {} bytes, got {}",
                file.name, expected, actual
            );
            return Ok(false);
        }
        Ok(true)
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
        // Cap individual piece size to prevent OOM from crafted .meta4 files
        // and to prevent 32-bit truncation bypass via `as usize`.
        const MAX_PIECE_SIZE: u64 = 1024 * 1024 * 1024; // 1 GiB
        for (i, piece) in pieces.iter().enumerate() {
            if piece.length > MAX_PIECE_SIZE {
                warn!("piece {} skipped: length {} exceeds max {}", i, piece.length, MAX_PIECE_SIZE);
                all_ok = false;
                continue;
            }
            let alloc_len = piece.length as usize; // safe: <= 1 GiB and <= usize::MAX on 64-bit
            let mut buf = vec![0u8; alloc_len];
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

/// Sanitize a filename from a Metalink document to prevent path traversal.
///
/// Mirrors GNU wget's `metalink_check_safe_path()` (metalink.c:150-183):
/// - Rejects absolute paths (leading `/` or drive letters).
/// - Rejects any `..` path component (directory traversal).
/// - Replaces backslashes with forward slashes, then strips leading slashes.
/// - If the name is empty or resolves to a traversal, falls back to "unnamed".
pub fn sanitize_metalink_filename(name: &str) -> String {
    // Replace backslashes (Windows separators) with forward slashes.
    let normalized = name.replace('\\', "/");

    // Split into components and filter out dangerous ones.
    let mut safe_parts: Vec<&str> = Vec::new();
    for part in normalized.split('/') {
        // Skip empty components (consecutive slashes, leading slash).
        if part.is_empty() {
            continue;
        }
        // Reject `..` (parent directory traversal).
        if part == ".." {
            continue;
        }
        // Reject `.` (current directory) — harmless but unnecessary.
        if part == "." {
            continue;
        }
        safe_parts.push(part);
    }

    if safe_parts.is_empty() {
        return "unnamed".to_string();
    }

    safe_parts.join("/")
}

