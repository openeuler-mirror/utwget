use sha1::Digest;

use crate::Result;

/// A streaming SHA-1 digest wrapper for computing WARC block digests.
///
/// WARC records require a `WARC-Block-Digest` header containing a SHA-1
/// hash of the block content. This struct wraps the `sha1::Sha1` hasher
/// and provides a convenient interface for incremental updates and
/// finalization into the standard `sha1:<hex>` format.
pub struct WarcDigest {
    /// The underlying SHA-1 hasher instance.
    sha1: sha1::Sha1,
}

impl WarcDigest {
    /// Creates a new `WarcDigest` with an initialised SHA-1 hasher.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use warc::digest::WarcDigest;
    ///
    /// let digest = WarcDigest::new();
    /// ```
    pub fn new() -> Self {
        WarcDigest {
            sha1: sha1::Sha1::new(),
        }
    }

    /// Feeds data into the running digest computation.
    ///
    /// This method can be called multiple times as data arrives (e.g.,
    /// streaming from a network socket or a file reader).
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice containing the next chunk of data to hash.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use warc::digest::WarcDigest;
    ///
    /// let mut digest = WarcDigest::new();
    /// digest.update(b"hello ");
    /// digest.update(b"world");
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        self.sha1.update(data);
    }

    /// Finalises the digest and returns the result as a `sha1:<hex>` string.
    ///
    /// This method clones the internal hasher so the struct remains usable
    /// for further updates if needed (though in typical WARC usage the
    /// digest is discarded after finalisation).
    ///
    /// # Returns
    ///
    /// A string in the format `sha1:<40-hex-digit-checksum>`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use warc::digest::WarcDigest;
    ///
    /// let mut digest = WarcDigest::new();
    /// digest.update(b"hello world");
    /// let result = digest.finalize();
    /// assert_eq!(result, "sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
    /// ```
    pub fn finalize(&self) -> String {
        let hash = self.sha1.clone().finalize();
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        format!("sha1:{}", hex)
    }
}

/// Computes a SHA-1 digest of the given data and returns it in
/// `sha1:<hex>` format.
///
/// This is a convenience function for one-shot hashing without creating a
/// `WarcDigest` instance.
///
/// # Arguments
///
/// * `data` - The byte slice to hash.
///
/// # Returns
///
/// A string in the format `sha1:<40-hex-digit-checksum>`.
///
/// # Examples
///
/// ```ignore
/// use warc::digest::compute_sha1;
///
/// let digest = compute_sha1(b"hello world");
/// assert_eq!(digest, "sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
/// ```
pub fn compute_sha1(data: &[u8]) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    format!("sha1:{}", hex)
}

/// Reads a file from disk and computes its SHA-1 digest in
/// `sha1:<hex>` format.
///
/// # Arguments
///
/// * `path` - The filesystem path to the file to hash.
///
/// # Returns
///
/// A `Result` containing the digest string in `sha1:<hex>` format on
/// success, or a `WarcError::Io` error if the file cannot be read.
///
/// # Errors
///
/// Returns `WarcError::Io` if the file does not exist, is not readable,
/// or an I/O error occurs during reading.
///
/// # Examples
///
/// ```ignore
/// use warc::digest::compute_file_sha1;
/// use std::path::Path;
///
/// let digest = compute_file_sha1(Path::new("/tmp/example.bin"))
///     .expect("failed to compute digest");
/// println!("{}", digest);
/// ```
pub fn compute_file_sha1(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path).map_err(crate::WarcError::Io)?;
    Ok(compute_sha1(&data))
}
