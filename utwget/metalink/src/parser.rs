//! Metalink XML document parser module.
//!
//! This module provides structures and functions for parsing Metalink XML
//! documents, which describe files available for download from multiple
//! mirrors with checksum verification.

use std::io::BufRead;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::checksum::ChecksumType;
use crate::FileChecksum;

/// Represents a file entry in a Metalink document.
///
/// Contains all metadata about a downloadable file including its name,
/// size, checksums, piece hashes, and available download resources.
#[derive(Debug, Clone)]
pub struct MetalinkFile {
    /// The name of the file.
    pub name: String,
    /// The file size in bytes, if specified.
    pub size: Option<u64>,
    /// Full file checksums for verification.
    pub hashes: Vec<FileChecksum>,
    /// Piece (chunk) hashes for partial verification.
    pub pieces: Vec<MetalinkPiece>,
    /// Available download resources (mirrors).
    pub resources: Vec<MetalinkResource>,
    /// Identity string for the file, if specified.
    pub identity: Option<String>,
    /// Version string for the file, if specified.
    pub version: Option<String>,
    /// Human-readable description of the file.
    pub description: Option<String>,
}

/// Represents a download resource (mirror) in a Metalink document.
///
/// Each resource provides a URL from which the file can be downloaded,
/// along with metadata about the resource's protocol and preference.
#[derive(Debug, Clone)]
pub struct MetalinkResource {
    /// The URL for downloading the file.
    pub url: String,
    /// The protocol type (e.g., "HTTP", "HTTPS", "FTP").
    pub type_: Option<String>,
    /// Preference value (higher is better).
    pub preference: Option<i32>,
    /// Maximum number of concurrent connections allowed.
    pub max_connections: Option<u32>,
    /// Geographic location code (e.g., "CN", "US", "DE").
    pub location: Option<String>,
}

/// Represents a piece (chunk) hash for partial file verification.
///
/// Metalink documents can specify hashes for individual pieces of a file,
/// allowing verification during download or for partial recovery.
#[derive(Debug, Clone)]
pub struct MetalinkPiece {
    /// Length of this piece in bytes.
    pub length: u64,
    /// Expected hash value as a hexadecimal string.
    pub hash: String,
    /// The hash algorithm used.
    pub hash_type: ChecksumType,
}

/// Error types for Metalink operations.
///
/// These errors can occur during parsing, downloading, or verification
/// of Metalink documents and their associated files.
#[derive(Debug, thiserror::Error)]
pub enum MetalinkError {
    /// Error parsing the Metalink document structure.
    #[error("metalink parse error: {0}")]
    Parse(String),
    /// Error parsing the XML structure.
    #[error("metalink XML error: {0}")]
    Xml(#[from] quick_xml::Error),
    /// I/O error during file operations.
    #[error("metalink I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Error during checksum computation or verification.
    #[error("metalink checksum error: {0}")]
    Checksum(String),
    /// Error during file download.
    #[error("metalink download error: {0}")]
    Download(String),
    /// No download resources available for a file.
    #[error("no resources available for download")]
    NoResources,
}

/// Parser for Metalink XML documents.
///
/// Parses Metalink version 3.0 XML documents and extracts file information
/// including names, sizes, checksums, and download URLs.
///
/// # Example
///
/// ```no_run
/// use ut_metalink::parser::MetalinkParser;
/// use std::io::Cursor;
///
/// let metalink_xml = r#"
/// <?xml version="1.0" encoding="utf-8"?>
/// <metalink version="3.0">
///   <file name="example.zip">
///     <size>12345</size>
///     <hash type="sha-256">abc123...</hash>
///     <url preference="100">http://example.com/example.zip</url>
///   </file>
/// </metalink>
/// "#;
///
/// let files = MetalinkParser::parse(Cursor::new(metalink_xml)).unwrap();
/// ```
pub struct MetalinkParser;

impl MetalinkParser {
    /// Parses a Metalink XML document from a reader.
    ///
    /// Reads and parses a Metalink version 3.0 XML document, extracting
    /// all file entries with their metadata, checksums, and download URLs.
    ///
    /// # Arguments
    ///
    /// * `reader` - A reader providing the XML document content.
    ///
    /// # Returns
    ///
    /// A vector of `MetalinkFile` entries on success.
    ///
    /// # Errors
    ///
    /// * `MetalinkError::Parse` - The document contains no files or has invalid structure.
    /// * `MetalinkError::Xml` - XML parsing error occurred.
    /// * `MetalinkError::Io` - I/O error while reading.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ut_metalink::parser::MetalinkParser;
    /// use std::fs::File;
    ///
    /// let file = File::open("example.metalink")?;
    /// let files = MetalinkParser::parse(std::io::BufReader::new(file))?;
    /// for file in &files {
    ///     println!("File: {} ({} bytes)", file.name, file.size.unwrap_or(0));
    /// }
    /// # Ok::<(), ut_metalink::parser::MetalinkError>(())
    /// ```
    pub fn parse(reader: impl BufRead) -> Result<Vec<MetalinkFile>, MetalinkError> {
        let mut xml_reader = Reader::from_reader(reader);
        xml_reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut files: Vec<MetalinkFile> = Vec::new();
        let mut current_file: Option<MetalinkFile> = None;
        let mut current_resource: Option<MetalinkResource> = None;

        let mut path_stack: Vec<String> = Vec::new();

        loop {
            let event = xml_reader.read_event_into(&mut buf)?;
            match event {
                Event::Start(ref e) | Event::Empty(ref e) => {
                    let local_name = e.local_name();
                    let tag = String::from_utf8_lossy(local_name.as_ref()).to_string();
                    path_stack.push(tag.clone());

                    match tag.as_str() {
                        "file" => {
                            let name = e
                                .attributes()
                                .find(|a| a.as_ref().map(|a| a.key.as_ref() == b"name").unwrap_or(false))
                                .and_then(|a| a.ok())
                                .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
                                .unwrap_or_default();
                            current_file = Some(MetalinkFile {
                                name,
                                size: None,
                                hashes: Vec::new(),
                                pieces: Vec::new(),
                                resources: Vec::new(),
                                identity: None,
                                version: None,
                                description: None,
                            });
                        }
                        "size" => {
                            if current_file.is_some() {
                                let text = read_text(&mut xml_reader, &mut buf)?;
                                if let Ok(size) = text.parse::<u64>() {
                                    if let Some(ref mut f) = current_file {
                                        f.size = Some(size);
                                    }
                                }
                                path_stack.pop();
                            }
                        }
                        "hash" => {
                            let hash_type = e
                                .attributes()
                                .find(|a| a.as_ref().map(|a| a.key.as_ref() == b"type").unwrap_or(false))
                                .and_then(|a| a.ok())
                                .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
                                .and_then(|t| ChecksumType::from_str(&t));
                            if let Some(ht) = hash_type {
                                let value = read_text(&mut xml_reader, &mut buf)?;
                                if let Some(ref mut f) = current_file {
                                    f.hashes.push(FileChecksum {
                                        hash_type: ht,
                                        expected: value,
                                    });
                                }
                            }
                            path_stack.pop();
                        }
                        "pieces" => {
                            if let Some(ref mut f) = current_file {
                                let piece_length = e
                                    .attributes()
                                    .find(|a| a.as_ref().map(|a| a.key.as_ref() == b"length").unwrap_or(false))
                                    .and_then(|a| a.ok())
                                    .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
                                    .and_then(|v| v.parse::<u64>().ok());
                                let piece_hash_type = e
                                    .attributes()
                                    .find(|a| a.as_ref().map(|a| a.key.as_ref() == b"type").unwrap_or(false))
                                    .and_then(|a| a.ok())
                                    .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
                                    .and_then(|t| ChecksumType::from_str(&t));

                                if let (Some(length), Some(hash_type)) = (piece_length, piece_hash_type) {
                                    f.pieces.push(MetalinkPiece {
                                        length,
                                        hash: String::new(),
                                        hash_type,
                                    });
                                }
                            }
                        }
                        "resources" => {}
                        "url" => {
                            // Parse URL attributes
                            let type_ = e
                                .attributes()
                                .find(|a| a.as_ref().map(|a| a.key.as_ref() == b"type").unwrap_or(false))
                                .and_then(|a| a.ok())
                                .and_then(|a| String::from_utf8(a.value.to_vec()).ok());
                            let preference = e
                                .attributes()
                                .find(|a| a.as_ref().map(|a| a.key.as_ref() == b"preference").unwrap_or(false))
                                .and_then(|a| a.ok())
                                .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
                                .and_then(|v| v.parse::<i32>().ok());

                            let text = read_text(&mut xml_reader, &mut buf)?;
                            if !text.is_empty() {
                                let resource = MetalinkResource {
                                    url: text,
                                    type_,
                                    preference,
                                    max_connections: None,
                                    location: None,
                                };
                                if let Some(ref mut f) = current_file {
                                    f.resources.push(resource);
                                }
                            }
                            path_stack.pop();
                        }
                        "identity" => {
                            let text = read_text(&mut xml_reader, &mut buf)?;
                            if let Some(ref mut f) = current_file {
                                f.identity = Some(text);
                            }
                            path_stack.pop();
                        }
                        "version" => {
                            let text = read_text(&mut xml_reader, &mut buf)?;
                            if let Some(ref mut f) = current_file {
                                f.version = Some(text);
                            }
                            path_stack.pop();
                        }
                        "description" => {
                            let text = read_text(&mut xml_reader, &mut buf)?;
                            if let Some(ref mut f) = current_file {
                                f.description = Some(text);
                            }
                            path_stack.pop();
                        }
                        _ => {}
                    }
                }
                Event::End(ref e) => {
                    let local_name = e.local_name();
                    let tag = String::from_utf8_lossy(local_name.as_ref()).to_string();

                    match tag.as_str() {
                        "url" => {
                            if let Some(res) = current_resource.take() {
                                if let Some(ref mut f) = current_file {
                                    f.resources.push(res);
                                }
                            }
                        }
                        "file" => {
                            if let Some(f) = current_file.take() {
                                files.push(f);
                            }
                        }
                        _ => {}
                    }

                    while let Some(top) = path_stack.last() {
                        if top == &tag {
                            path_stack.pop();
                            break;
                        }
                        path_stack.pop();
                    }
                }
                Event::Text(ref e) => {
                    let text = e.unescape().unwrap_or_default();
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        if let Some("url") = path_stack.last().map(|s| s.as_str()) {
                            if let Some(ref mut res) = current_resource {
                                if res.url.is_empty() {
                                    res.url = trimmed.to_string();
                                }
                            }
                        }
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }

        if files.is_empty() {
            return Err(MetalinkError::Parse("no files found in metalink document".into()));
        }

        Ok(files)
    }
}

/// Reads text content from an XML element.
///
/// Reads events until an end tag or empty tag is encountered,
/// concatenating all text content.
///
/// # Arguments
///
/// * `reader` - The XML reader.
/// * `buf` - Buffer for event reading.
///
/// # Returns
///
/// The trimmed text content of the element.
///
/// # Errors
///
/// Returns an error if XML parsing fails.
fn read_text<R: BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<String, MetalinkError> {
    let mut text = String::new();
    loop {
        let event = reader.read_event_into(buf)?;
        match event {
            Event::Text(e) => {
                if let Ok(decoded) = e.unescape() {
                    text.push_str(&decoded);
                }
            }
            Event::End(_) | Event::Empty(_) => break,
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(text.trim().to_string())
}
