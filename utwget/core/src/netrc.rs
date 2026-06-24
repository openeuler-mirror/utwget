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

impl NetrcDb {
    /// Creates a new empty netrc database.
    ///
    /// # Returns
    ///
    /// A new `NetrcDb` with no entries.
    pub fn new() -> Self {
        NetrcDb {
            entries: Vec::new(),
            default: None,
        }
    }

    /// Loads entries from a .netrc file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the .netrc file.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an IO error on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn load_from_file(&mut self, path: &Path) -> io::Result<()> {
        let content = fs::read_to_string(path)?;
        self.parse(&content);
        Ok(())
    }

    /// Loads entries from a string.
    ///
    /// Clears any existing entries before parsing.
    ///
    /// # Arguments
    ///
    /// * `content` - The .netrc file content.
    pub fn load_from_str(&mut self, content: &str) {
        self.entries.clear();
        self.default = None;
        self.parse(content);
    }

    /// Parses .netrc content into entries.
    fn parse(&mut self, content: &str) {
        let tokens = tokenize(content);
        let mut i = 0;
        let mut current_entry: Option<NetrcEntry> = None;

        while i < tokens.len() {
            let token = &tokens[i];
            let token_lc = token.to_ascii_lowercase();

            match token_lc.as_str() {
                "machine" => {
                    if let Some(entry) = current_entry.take() {
                        self.entries.push(entry);
                    }
                    if i + 1 < tokens.len() {
                        i += 1;
                        current_entry = Some(NetrcEntry {
                            machine: tokens[i].clone(),
                            account: None,
                            login: None,
                            password: None,
                            macros: HashMap::new(),
                        });
                    }
                }
                "default" => {
                    if let Some(entry) = current_entry.take() {
                        self.entries.push(entry);
                    }
                    current_entry = Some(NetrcEntry {
                        machine: String::new(),
                        account: None,
                        login: None,
                        password: None,
                        macros: HashMap::new(),
                    });
                }
                "login" => {
                    if let Some(ref mut entry) = current_entry {
                        if i + 1 < tokens.len() {
                            i += 1;
                            entry.login = Some(tokens[i].clone());
                        }
                    }
                }
                "password" => {
                    if let Some(ref mut entry) = current_entry {
                        if i + 1 < tokens.len() {
                            i += 1;
                            entry.password = Some(tokens[i].clone());
                        }
                    }
                }
                "account" => {
                    if let Some(ref mut entry) = current_entry {
                        if i + 1 < tokens.len() {
                            i += 1;
                            entry.account = Some(tokens[i].clone());
                        }
                    }
                }
                "macdef" => {
                    if let Some(ref mut entry) = current_entry {
                        if i + 1 < tokens.len() {
                            i += 1;
                            let macro_name = tokens[i].clone();
                            i += 1;
                            let mut macro_body = String::new();
                            while i < tokens.len() && !tokens[i].is_empty() {
                                if macro_body.is_empty() {
                                    macro_body.push_str(&tokens[i]);
                                } else {
                                    macro_body.push(' ');
                                    macro_body.push_str(&tokens[i]);
                                }
                                i += 1;
                            }
                            entry.macros.insert(macro_name, macro_body);
                            continue;
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }

        if let Some(entry) = current_entry.take() {
            if entry.machine.is_empty() {
                self.default = Some(entry);
            } else {
                self.entries.push(entry);
            }
        }
    }

    /// Looks up credentials for a host.
    ///
    /// Searches machine-specific entries first, then falls back to
    /// the default entry if no match is found.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to look up.
    ///
    /// # Returns
    ///
    /// `Some(Credentials)` if a matching entry with login and password exists,
    /// `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use ut_core::netrc::NetrcDb;
    ///
    /// let mut db = NetrcDb::new();
    /// db.load_from_str("machine example.com\nlogin user\npassword pass");
    /// let creds = db.lookup("example.com");
    /// ```
    pub fn lookup(&self, host: &str) -> Option<Credentials> {
        let host_lc = host.to_ascii_lowercase();

        for entry in &self.entries {
            if entry.machine.to_ascii_lowercase() == host_lc {
                if let (Some(user), Some(pass)) = (&entry.login, &entry.password) {
                    return Some(Credentials {
                        username: user.clone(),
                        password: pass.clone(),
                    });
                }
            }
        }

        if let Some(ref def) = self.default {
            if let (Some(user), Some(pass)) = (&def.login, &def.password) {
                return Some(Credentials {
                    username: user.clone(),
                    password: pass.clone(),
                });
            }
        }

        None
    }

    /// Checks if the database contains no entries.
    ///
    /// # Returns
    ///
    /// `true` if there are no machine entries and no default entry.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.default.is_none()
    }
}

impl Default for NetrcDb {
    fn default() -> Self {
        Self::new()
    }
}
