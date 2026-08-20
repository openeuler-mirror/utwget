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

/// Classifies a URL as absolute or relative.
///
/// # Arguments
///
/// * `url` - The URL to classify.
///
/// # Returns
///
/// - `LinkType::Absolute` if the URL contains a scheme, starts with `//`,
///   or starts with `/`.
/// - `LinkType::Relative` otherwise.
fn classify_link(url: &str) -> LinkType {
    if url.contains("://") || url.starts_with("//") || url.starts_with('/') {
        LinkType::Absolute
    } else {
        LinkType::Relative
    }
}

/// Parses a URL from a meta refresh content attribute.
///
/// Extracts the URL from content like `"5;url=http://example.com/"`.
///
/// # Arguments
///
/// * `content` - The content attribute value from a meta refresh element.
///
/// # Returns
///
/// `Some(url)` if a valid URL was found, `None` otherwise.
fn parse_meta_refresh_url(content: &str) -> Option<String> {
    let content = content.trim();
    let lower = content.to_ascii_lowercase();

    let url_idx = lower.find("url=")?;

    let url = if url_idx + 4 < lower.len()
        && (lower.as_bytes()[url_idx + 4] == b'\''
            || lower.as_bytes()[url_idx + 4] == b'"')
    {
        let quote = content.as_bytes()[url_idx + 4];
        let end = content[url_idx + 5..].find(quote as char);
        match end {
            Some(e) => &content[url_idx + 5..url_idx + 5 + e],
            None => &content[url_idx + 5..],
        }
    } else {
        let rest = &content[url_idx + 4..];
        let end = rest.find(|c: char| c == ';' || c.is_whitespace());
        match end {
            Some(e) => &rest[..e],
            None => rest,
        }
    };

    let url = url.trim();
    if url.is_empty() {
        None
    } else {
        Some(url.to_string())
    }
}

/// HTML content extractor for URL extraction.
///
/// Parses HTML documents and extracts URLs from:
/// - Anchor tags (`<a href="...">`)
/// - Image tags (`<img src="...">`)
/// - Script tags (`<script src="...">`)
/// - Link tags (`<link href="...">`)
/// - Iframe/frame tags
/// - Meta refresh redirects
/// - Base elements
///
/// # Example
///
/// ```ignore
/// use html::html_extractor::HtmlExtractor;
/// use html::types::ContentExtractor;
///
/// let extractor = HtmlExtractor;
/// let html = r#"<html><body><a href="page.html">Link</a></body></html>"#;
/// let urls = extractor.extract_urls(&mut html.as_bytes(), "http://example.com/", &ExtractOptions::default())?;
/// ```
pub struct HtmlExtractor;

impl ContentExtractor for HtmlExtractor {
    /// Extracts URLs from HTML content.
    ///
    /// Parses the HTML document and finds all URL-containing elements,
    /// returning information about each URL found.
    ///
    /// # Arguments
    ///
    /// * `reader` - A reader providing the HTML content.
    /// * `_base_url` - Base URL for resolving relative URLs (currently unused).
    /// * `opts` - Options controlling which tags to follow or ignore.
    ///
    /// # Returns
    ///
    /// A vector of `UrlPosition` objects for each URL found, or a
    /// `ConvertError` if parsing fails.
    ///
    /// # Processing Details
    ///
    /// - Skips `javascript:` and `data:` URLs
    /// - Handles meta robots `nofollow` directives
    /// - Extracts meta refresh redirect URLs
    /// - Identifies inline vs. navigational links
    /// - Detects CSS stylesheets from link tags
    fn extract_urls(
        &self,
        reader: &mut dyn Read,
        _base_url: &str,
        opts: &ExtractOptions,
    ) -> Result<Vec<UrlPosition>, ConvertError> {
        let results: Arc<Mutex<Vec<UrlPosition>>> = Arc::new(Mutex::new(Vec::new()));
        let nofollow_flag: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let ignore_tags: Vec<String> = opts.ignore_tags.clone();
        let follow_tags: Vec<String> = opts.follow_tags.clone();

        let results_clone = results.clone();
        let nofollow_clone = nofollow_flag.clone();

        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![
                    element!(SELECTOR, move |el| {
                        let tag = el.tag_name().to_lowercase();
                        let tag_str = tag.as_str();

                        if ignore_tags.iter().any(|t| t.eq_ignore_ascii_case(tag_str)) {
                            return Ok(());
                        }

                        if !follow_tags.iter().any(|t| t.eq_ignore_ascii_case(tag_str)) {
                            return Ok(());
                        }

                        if tag_str == "meta" {
                            if let Some(name) = el.get_attribute("name") {
                                if name.eq_ignore_ascii_case("robots") {
                                    if let Some(content) = el.get_attribute("content") {
                                        if content.to_ascii_lowercase().contains("nofollow") {
                                            *nofollow_clone.lock().unwrap() = true;
                                        }
                                    }
                                }
                            }

                            if let Some(equiv) = el.get_attribute("http-equiv") {
                                if equiv.eq_ignore_ascii_case("refresh") {
                                    if let Some(content) = el.get_attribute("content") {
                                        if let Some(refresh_url) = parse_meta_refresh_url(&content) {
                                            results_clone.lock().unwrap().push(UrlPosition {
                                                url: refresh_url,
                                                link_type: LinkType::RefreshRedirect,
                                                inline: false,
                                                attr_name: Some("content".to_string()),
                                                expect_html: true,
                                                expect_css: false,
                                                meta_disallow_follow: *nofollow_clone.lock().unwrap(),
                                            });
                                        }
                                    }
                                }
                            }

                            return Ok(());
                        }

                        if tag_str == "base" {
                            if let Some(href) = el.get_attribute("href") {
                                if !href.trim().is_empty() {
                                    results_clone.lock().unwrap().push(UrlPosition {
                                        url: href.trim().to_string(),
                                        link_type: LinkType::BaseHref,
                                        inline: false,
                                        attr_name: Some("href".to_string()),
                                        expect_html: false,
                                        expect_css: false,
                                        meta_disallow_follow: false,
                                    });
                                }
                            }
                            return Ok(());
                        }

                        if let Some(attr_name) = url_attr_for_tag(tag_str) {
                            if let Some(url) = el.get_attribute(attr_name) {
                                let url = url.trim().to_string();
                                if url.is_empty() || url.starts_with('#')
                                    || url.starts_with("javascript:")
                                    || url.starts_with("data:")
                                {
                                    return Ok(());
                                }

                                let link_type = classify_link(&url);
                                let inline = is_inline_tag(tag_str);
                                let expect_html = matches!(tag_str, "a" | "iframe" | "frame");
                                let expect_css = tag_str == "link"
                                    && el.get_attribute("rel")
                                        .map(|r| r.eq_ignore_ascii_case("stylesheet"))
                                        .unwrap_or(false);

                                results_clone.lock().unwrap().push(UrlPosition {
                                    url,
                                    link_type,
                                    inline,
                                    attr_name: Some(attr_name.to_string()),
                                    expect_html,
                                    expect_css,
                                    meta_disallow_follow: *nofollow_clone.lock().unwrap(),
                                });
                            }
                        }

                        Ok(())
                    }),
                ],
                memory_settings: MemorySettings::default(),
                ..Default::default()
            },
            |_output: &[u8]| {},
        );

        let mut buf_reader = BufReader::new(reader);
        let mut chunk = [0u8; 8192];
        loop {
            let n = buf_reader.read(&mut chunk).map_err(ConvertError::Io)?;
            if n == 0 {
                break;
            }
            rewriter.write(&chunk[..n]).map_err(|e| ConvertError::Rewrite(e.to_string()))?;
        }
        rewriter.end().map_err(|e| ConvertError::Rewrite(e.to_string()))?;

        let mut final_results = match Arc::try_unwrap(results) {
            Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
            Err(arc) => arc.lock().unwrap().clone(),
        };

        let nofollow = match Arc::try_unwrap(nofollow_flag) {
            Ok(mutex) => mutex.into_inner().unwrap_or(false),
            Err(arc) => *arc.lock().unwrap(),
        };

        if nofollow {
            for pos in &mut final_results {
                pos.meta_disallow_follow = true;
            }
        }

        Ok(final_results)
    }

    /// Returns the content kind handled by this extractor.
    ///
    /// # Returns
    ///
    /// Always returns `ContentKind::Html`.
    fn content_kind(&self) -> ContentKind {
        ContentKind::Html
    }

    /// Indicates whether the full content must be loaded.
    ///
    /// HTML extraction can process content incrementally using a streaming parser.
    ///
    /// # Returns
    ///
    /// Always returns `false`.
    fn requires_full_load(&self) -> bool {
        false
    }
}
