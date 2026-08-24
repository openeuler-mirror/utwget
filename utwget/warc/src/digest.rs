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
