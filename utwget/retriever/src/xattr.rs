//! Extended attributes (xattr) support for downloaded files.
//!
//! This module provides functionality to store metadata in file extended attributes,
//! compatible with GNU wget's `--xattr` option. On Linux, this uses the `user`
//! namespace for xattr keys.
//!
//! # Stored Attributes
//!
//! - `user.xdg.origin.url`: The original download URL
//! - `user.xdg.content.type`: The Content-Type from the server
//! - `user.wget.last_modified`: The Last-Modified timestamp
//! - `user.wget.etag`: The ETag from the server
//!
//! # Example
//!
//! ```no_run
//! use ut_retriever::xattr::{FileMetadata, set_xattr};
//! use std::path::Path;
//!
//! let metadata = FileMetadata {
//!     url: "http://example.com/file.txt".to_string(),
//!     content_type: Some("text/plain".to_string()),
//!     last_modified: None,
//!     etag: None,
//! };
//! set_xattr(Path::new("file.txt"), &metadata).ok();
//! ```

use std::path::Path;
use std::io;

/// Metadata to store in extended attributes.
///
/// This struct holds the metadata that will be written to a file's
/// extended attributes when `--xattr` is enabled.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Original URL from which the file was downloaded.
    pub url: String,
    /// Content-Type header value from the server response.
    pub content_type: Option<String>,
    /// Last-Modified timestamp from the server, formatted as RFC 2822.
    pub last_modified: Option<String>,
    /// ETag header value from the server response.
    pub etag: Option<String>,
}

/// Permission information from remote server.
///
/// Used with `--preserve-permissions` to maintain the original file
/// permissions from the remote server.
#[derive(Debug, Clone, Copy)]
pub struct RemotePermissions {
    /// Unix file mode (permissions bits).
    pub mode: u32,
    /// Whether the remote resource is a directory.
    pub is_dir: bool,
    /// Whether the remote resource is a symbolic link.
    pub is_symlink: bool,
}

impl Default for RemotePermissions {
    /// Create default permissions (644 for files, 755 for directories).
    fn default() -> Self {
        RemotePermissions {
            mode: 0o644, // Default: rw-r--r--
            is_dir: false,
            is_symlink: false,
        }
    }
}

/// Apply permissions to a local file.
///
/// This preserves the remote file permissions when `--preserve-permissions` is used.
/// On Unix systems, this sets the file mode bits. On non-Unix systems, this is a no-op.
///
/// # Arguments
///
/// * `path` - Path to the local file.
/// * `permissions` - Permission information to apply.
///
/// # Returns
///
/// `Ok(())` on success, or an `io::Error` on failure.
///
/// # Errors
///
/// Returns an error if the file permissions cannot be set.
pub fn apply_permissions(path: &Path, permissions: &RemotePermissions) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if permissions.is_dir {
            permissions.mode | 0o111 // Ensure directory has execute bit
        } else {
            permissions.mode
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, permissions);
    }
    Ok(())
}

/// Set extended attributes on a file.
///
/// On Linux, this uses the `user` namespace for xattr keys:
/// - `user.xdg.origin.url`: The download URL
/// - `user.xdg.content.type`: The Content-Type
/// - `user.wget.last_modified`: The Last-Modified timestamp
/// - `user.wget.etag`: The ETag
///
/// On unsupported platforms, this is a no-op that returns `Ok(())`.
///
/// # Arguments
///
/// * `path` - Path to the local file.
/// * `metadata` - Metadata to store in extended attributes.
///
/// # Returns
///
/// `Ok(())` on success, or an `io::Error` on failure.
///
/// # Errors
///
/// Returns an error if any extended attribute cannot be set.
///
/// # Example
///
/// ```no_run
/// use ut_retriever::xattr::{FileMetadata, set_xattr};
/// use std::path::Path;
///
/// let metadata = FileMetadata {
///     url: "http://example.com/file.txt".to_string(),
///     content_type: Some("text/plain".to_string()),
///     last_modified: Some("Mon, 15 Jun 2026 12:00:00 GMT".to_string()),
///     etag: Some("\"abc123\"".to_string()),
/// };
/// set_xattr(Path::new("file.txt"), &metadata).expect("failed to set xattr");
/// ```
pub fn set_xattr(path: &Path, metadata: &FileMetadata) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        set_xattr_linux(path, metadata)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, metadata);
        Ok(())
    }
}

/// Set extended attributes on Linux using libc.
///
/// This is the Linux-specific implementation that uses the `setxattr` syscall.
///
/// # Arguments
///
/// * `path` - Path to the local file.
/// * `metadata` - Metadata to store.
///
/// # Returns
///
/// `Ok(())` on success, or an `io::Error` on failure.
#[cfg(target_os = "linux")]
fn set_xattr_linux(path: &Path, metadata: &FileMetadata) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStringExt;

    // Set user.xdg.origin.url (the download URL)
    let url_key = CString::new("user.xdg.origin.url").unwrap();
    let url_value = CString::new(metadata.url.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    unsafe {
        let path_c = CString::new(path.as_os_str().to_os_string().into_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let ret = libc::setxattr(
            path_c.as_ptr(),
            url_key.as_ptr(),
            url_value.as_ptr() as *const libc::c_void,
            metadata.url.len(),
            0,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // Set user.xdg.content.type if available
    if let Some(ref ct) = metadata.content_type {
        let ct_key = CString::new("user.xdg.content.type").unwrap();
        let ct_value = CString::new(ct.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        unsafe {
            let path_c = CString::new(path.as_os_str().to_os_string().into_vec())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let ret = libc::setxattr(
                path_c.as_ptr(),
                ct_key.as_ptr(),
                ct_value.as_ptr() as *const libc::c_void,
                ct.len(),
                0,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    // Set user.wget.last_modified if available
    if let Some(ref lm) = metadata.last_modified {
        let lm_key = CString::new("user.wget.last_modified").unwrap();
        let lm_value = CString::new(lm.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        unsafe {
            let path_c = CString::new(path.as_os_str().to_os_string().into_vec())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let ret = libc::setxattr(
                path_c.as_ptr(),
                lm_key.as_ptr(),
                lm_value.as_ptr() as *const libc::c_void,
                lm.len(),
                0,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    // Set user.wget.etag if available
    if let Some(ref etag) = metadata.etag {
        let etag_key = CString::new("user.wget.etag").unwrap();
        let etag_value = CString::new(etag.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        unsafe {
            let path_c = CString::new(path.as_os_str().to_os_string().into_vec())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let ret = libc::setxattr(
                path_c.as_ptr(),
                etag_key.as_ptr(),
                etag_value.as_ptr() as *const libc::c_void,
                etag.len(),
                0,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(())
}
