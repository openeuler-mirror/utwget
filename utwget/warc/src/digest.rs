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
