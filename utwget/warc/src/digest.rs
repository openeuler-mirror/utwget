use sha1::Digest;

use crate::Result;

/// Encode a byte slice as lowercase base32 (RFC 4648), matching GNU wget's
/// `base32_encode` (warc.c:587-600).
///
/// GNU wget writes WARC digests as `sha1:<base32>`, not `sha1:<hex>`. Using
/// hex makes utwget's WARC output incompatible with wget and breaks
/// `--warc-dedup` cross-tool dedup.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            result.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        result.push(BASE32_ALPHABET[idx] as char);
    }
    // No padding (wget doesn't pad either).
    result
}

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

    /// Finalises the digest and returns the result as a `sha1:<base32>` string.
    ///
    /// This method clones the internal hasher so the struct remains usable
    /// for further updates if needed (though in typical WARC usage the
    /// digest is discarded after finalisation).
    ///
    /// # Returns
    ///
    /// A string in the format `sha1:<base32-checksum>`, matching GNU wget.
    pub fn finalize(&self) -> String {
        let hash = self.sha1.clone().finalize();
        format!("sha1:{}", base32_encode(&hash))
    }
}

/// Computes a SHA-1 digest of the given data and returns it in
/// `sha1:<base32>` format.
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
/// A string in the format `sha1:<base32-checksum>`, matching GNU wget.
pub fn compute_sha1(data: &[u8]) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(data);
    let hash = hasher.finalize();
    format!("sha1:{}", base32_encode(&hash))
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
