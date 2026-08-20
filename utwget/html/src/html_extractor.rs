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

/// CSS selector for all elements with URL attributes.
///
/// This selector matches all elements that have URL-containing attributes
/// and should be processed during URL extraction.
const SELECTOR: &str = concat![
    "a[href], area[href], link[href], img[src], script[src], ",
    "iframe[src], frame[src], embed[src], object[data], ",
    "source[src], track[src], video[poster], body[background], ",
    "applet[codebase], meta[content], base[href]",
];

/// Checks if a tag represents an inline resource.
///
/// Inline resources are embedded directly in the page (images, scripts, etc.)
/// rather than linking to separate documents.
///
/// # Arguments
///
/// * `tag` - The HTML tag name (lowercase).
///
/// # Returns
///
/// `true` if the tag represents an inline resource, `false` otherwise.
fn is_inline_tag(tag: &str) -> bool {
    INLINE_TAGS.contains(&tag)
}

/// Returns the URL attribute name for a given HTML tag.
///
/// Looks up the attribute that contains a URL for the specified tag.
///
/// # Arguments
///
/// * `tag` - The HTML tag name (lowercase).
///
/// # Returns
///
/// `Some(attr_name)` if the tag has a URL attribute, `None` otherwise.
fn url_attr_for_tag(tag: &str) -> Option<&'static str> {
    for (t, a) in URL_ATTR_MAP {
        if *t == tag {
            return Some(a);
        }
    }
    None
}
