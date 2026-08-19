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

/// Mapping of HTML element names to their URL-containing attributes.
///
/// Each tuple represents (tag_name, attribute_name) where the attribute
/// contains a URL that should be extracted.
const URL_ATTR_MAP: &[(&str, &str)] = &[
    ("a", "href"),
    ("area", "href"),
    ("link", "href"),
    ("img", "src"),
    ("script", "src"),
    ("iframe", "src"),
    ("frame", "src"),
    ("embed", "src"),
    ("object", "data"),
    ("source", "src"),
    ("track", "src"),
    ("video", "poster"),
    ("body", "background"),
    ("applet", "codebase"),
    ("meta", "content"),
    ("base", "href"),
];
