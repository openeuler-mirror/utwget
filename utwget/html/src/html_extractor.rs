//! HTML URL extractor for finding links and embedded resources.
//!
//! This module provides functionality to parse HTML documents and extract
//! URLs from various elements including links, images, scripts, and meta tags.

use std::io::{BufReader, Read};
use std::sync::{Arc, Mutex};

use lol_html::element;
use lol_html::{HtmlRewriter, Settings, MemorySettings};

use crate::converter::ConvertError;
use crate::types::{ContentExtractor, ContentKind};
use crate::url_position::{ExtractOptions, LinkType, UrlPosition};

/// HTML elements that represent inline resources.
///
/// These elements embed resources directly in the page rather than
/// linking to separate documents.
const INLINE_TAGS: &[&str] = &[
    "img", "script", "link", "embed", "object", "source", "video",
];
