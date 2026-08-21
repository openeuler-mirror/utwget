//! Type definitions for the retriever module.
//!
//! This module defines the core types used throughout the retriever,
//! including request options, response metadata, error types, and
//! document flags.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ut_core::types::HttpMethod;
use ut_core::WgetError;

bitflags::bitflags! {
    /// Flags describing document properties and retrieval behavior.
    ///
    /// These flags are used to track document characteristics and
    /// control how documents are processed during retrieval.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DocumentFlags: u16 {
        /// Document is HTML content.
        const TEXT_HTML = 0x0001;
        /// Document is ready for retrieval.
        const RETRIEVAL_OK = 0x0002;
        /// Only HEAD request needed.
        const HEAD_ONLY = 0x0004;
        /// Do not cache this document.
        const NO_CACHE = 0x0008;
        /// Server accepts range requests.
        const ACCEPT_RANGES = 0x0010;
        /// HTML extension was added to filename.
        const HTML_EXT_ADDED = 0x0020;
        /// Document is CSS content.
        const TEXT_CSS = 0x0040;
        /// Conditional request (If-Modified-Since).
        const IF_MODIFIED = 0x0080;
        /// Document contains Metalink metadata.
        const METALINK_META = 0x0100;
    }
}
