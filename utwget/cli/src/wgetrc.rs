//! wgetrc configuration file parser.
//!
//! This module provides parsing and application of wgetrc configuration files,
//! which contain wget settings in a simple `key = value` format. The parser
//! supports both system-wide (`/etc/wgetrc`) and user-specific (`~/.wgetrc`)
//! configuration files.
//!
//! # File Format
//!
//! wgetrc files use a simple line-based format:
//!
//! ```text
//! # This is a comment
//! key = value
//! flag = on
//! other_flag = off
//! ```
//!
//! Lines starting with `#` are comments. Settings can be:
//! - Key-value pairs: `key = value`
//! - Boolean flags: `flag = on` or `flag = off`
//! - Commands with arguments: `command arg1 arg2 ...`
//!
//! # Configuration Priority
//!
//! Settings are applied in this order (later overrides earlier):
//! 1. System-wide `/etc/wgetrc`
//! 2. User-specific `~/.wgetrc`
//! 3. Custom config file specified with `--config`
//! 4. Commands from `--execute` options
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use utwget::cli::wgetrc::{WgetrcParser, WgetrcCommand};
//!
//! // Parse a wgetrc file
//! let commands = WgetrcParser::parse(Path::new("/etc/wgetrc"))?;
//!
//! // Apply commands to configuration
//! let mut config = ut_core::Config::default();
//! WgetrcParser::apply(&commands, &mut config)?;
//! # Ok::<(), ut_core::error::WgetError>(())
//! ```

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use ut_core::error::{ConfigError, WgetError};

/// A parsed command from a wgetrc configuration file.
///
/// Commands can take three forms:
/// - `Set(key, value)` - A key-value assignment like `dir_prefix = /downloads`
/// - `OnOff(key, flag)` - A boolean toggle like `quiet = on`
/// - `Command(name, args)` - A command with arguments like `accept *.html *.css`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WgetrcCommand {
    /// A key-value setting: `key = value`.
    Set(String, String),
    /// A boolean toggle: `key = on` or `key = off`.
    OnOff(String, bool),
    /// A command with space-separated arguments.
    Command(String, Vec<String>),
}
