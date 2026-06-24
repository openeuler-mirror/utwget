//! .netrc file parsing for automatic authentication.
//!
//! This module parses .netrc files as specified in the FTP client
//! documentation, providing automatic credential lookup for hosts.

use crate::types::Credentials;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// A single .netrc entry for a machine.
///
/// Contains login credentials and optional macro definitions.
#[derive(Debug, Clone)]
pub struct NetrcEntry {
    /// The machine hostname (empty for default entry).
    pub machine: String,
    /// Optional account name.
    pub account: Option<String>,
    /// Login username.
    pub login: Option<String>,
    /// Login password.
    pub password: Option<String>,
    /// Macro definitions for FTP.
    pub macros: HashMap<String, String>,
}

/// Database of .netrc entries.
///
/// Provides credential lookup for hosts, with fallback to a default entry.
#[derive(Debug, Clone)]
pub struct NetrcDb {
    /// Machine-specific entries.
    entries: Vec<NetrcEntry>,
    /// Default entry for unmatched hosts.
    default: Option<NetrcEntry>,
}
