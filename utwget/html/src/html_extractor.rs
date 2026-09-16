//! HTML URL extractor for finding links and embedded resources.
//!
//! This module provides functionality to parse HTML documents and extract
//! URLs from various elements including links, images, scripts, and meta tags.

use std::io::{BufReader, Read};
use std::sync::{Arc, Mutex};

use lol_html::element;
use lol_html::text;
use lol_html::{HtmlRewriter, Settings, MemorySettings};

use crate::converter::ConvertError;
use crate::css_extractor::extract_css_urls_from_str;
use crate::types::{ContentExtractor, ContentKind};
use crate::url_position::{ExtractOptions, LinkType, UrlPosition};

/// HTML elements that represent inline resources.
///
/// These elements embed resources directly in the page rather than
/// linking to separate documents.
const INLINE_TAGS: &[&str] = &[
    "img", "script", "link", "embed", "object", "source", "video",
    // wget ATTR_INLINE tags (html-url.c:141-169): applet code, bgsound src,
    // body background, fig/layer/overlay src, input src, table/td/th
    // background, audio/video src+poster, frames.
    "applet", "bgsound", "body", "fig", "frame", "iframe", "input",
    "layer", "overlay", "table", "td", "th", "audio",
];

/// Mapping of HTML element names to their URL-containing attributes.
///
/// Each tuple represents (tag_name, attribute_name) where the attribute
/// contains a URL that should be extracted. A tag may appear multiple
/// times (wget tag_url_attributes, html-url.c:141-169).
const URL_ATTR_MAP: &[(&str, &str)] = &[
    ("a", "href"),
    ("applet", "code"),
    ("applet", "codebase"),
    ("area", "href"),
    ("audio", "src"),
    ("audio", "poster"),
    ("bgsound", "src"),
    ("body", "background"),
    ("embed", "href"),
    ("embed", "src"),
    ("fig", "src"),
    ("form", "action"),
    ("frame", "src"),
    ("iframe", "src"),
    ("img", "src"),
    ("img", "href"),
    ("img", "lowsrc"),
    ("input", "src"),
    ("layer", "src"),
    ("link", "href"),
    ("object", "data"),
    ("overlay", "src"),
    ("script", "src"),
    ("source", "src"),
    ("table", "background"),
    ("td", "background"),
    ("th", "background"),
    ("track", "src"),
    ("video", "src"),
    ("video", "poster"),
    ("meta", "content"),
    ("base", "href"),
];

/// CSS selector for all elements with URL attributes.
///
/// This selector matches all elements that have URL-containing attributes
/// and should be processed during URL extraction.
/// Also matches elements with `srcset` or `style` attributes, and
/// `<style>` blocks for CSS URL extraction.
const SELECTOR: &str = concat![
    "a[href], area[href], link[href], img[src], script[src], ",
    "iframe[src], frame[src], embed[src], embed[href], object[data], ",
    "source[src], track[src], video[src], video[poster], ",
    "audio[src], audio[poster], bgsound[src], fig[src], ",
    "form[action], input[src], layer[src], overlay[src], ",
    "table[background], td[background], th[background], ",
    "applet[code], applet[codebase], img[lowsrc], img[href], ",
    "body[background], meta[content], base[href], ",
    "img[srcset], source[srcset], [style]",
];

/// Parses a `srcset` attribute value and extracts individual URLs.
///
/// The srcset format is a comma-separated list of URL-descriptor pairs:
///   `srcset="url1 1x, url2 2x"` or `srcset="url1 100w, url2 200w"`
///
/// Each URL is separated from its descriptor by whitespace, and entries
/// are separated by commas. URLs themselves should not contain commas
/// (per the HTML spec).
///
/// # Arguments
///
/// * `srcset` - The srcset attribute value.
///
/// # Returns
///
/// A vector of extracted URL strings.
fn parse_srcset_urls(srcset: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for entry in srcset.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // URL is the first whitespace-delimited token; the rest is the descriptor
        let url_end = entry.find(|c: char| c.is_ascii_whitespace());
        let url = match url_end {
            Some(idx) => &entry[..idx],
            None => entry,
        };
        let url = url.trim();
        if !url.is_empty() && !url.starts_with("data:") && !url.starts_with('#') {
            urls.push(url.to_string());
        }
    }
    urls
}

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

/// Returns every URL-containing attribute for the given tag.
///
/// wget's tag_url_attributes table (html-url.c:141-169) lists multiple
/// attributes per tag (img: src/lowsrc/href; video/audio: src/poster;
/// embed: href/src). All of them are harvested.
fn url_attrs_for_tag(tag: &str) -> Vec<&'static str> {
    URL_ATTR_MAP
        .iter()
        .filter(|(t, _)| *t == tag)
        .map(|(_, a)| *a)
        .collect()
}

/// Classifies a URL as absolute or relative.
///
/// # Arguments
///
/// * `url` - The URL to classify.
///
/// # Returns
///
/// - `LinkType::Absolute` if the URL contains a scheme or starts with `//`
///   (scheme-relative).
/// - `LinkType::Relative` otherwise — including path-absolute URLs starting
///   with `/` (e.g. `/style.css`). RFC 3986 §5: a path-absolute reference
///   has no scheme and must be resolved against the base URL. Classifying
///   it as Absolute made the recursive engine push `/style.css` straight
///   into `ParsedUrl::parse`, which fails without a scheme — silently
///   dropping every site-root-relative stylesheet/link (report 8.4-1's
///   root cause).
fn classify_link(url: &str) -> LinkType {
    if url.contains("://") || url.starts_with("//") {
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
        let results_clone2 = results.clone();
        let nofollow_clone = nofollow_flag.clone();
        let nofollow_clone2 = nofollow_flag.clone();

        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![
                    element!(SELECTOR, move |el| {
                        let tag = el.tag_name().to_lowercase();
                        let tag_str = tag.as_str();

                        if ignore_tags.iter().any(|t| t.eq_ignore_ascii_case(tag_str)) {
                            return Ok(());
                        }

                        // Extract URLs from inline style attribute for ALL elements,
                        // regardless of follow_tags filter (matches GNU wget behavior
                        // where check_style_attr is called for every tag).
                        if let Some(style) = el.get_attribute("style") {
                            for url in extract_css_urls_from_str(&style) {
                                let link_type = classify_link(&url);
                                results_clone.lock().unwrap_or_else(|e| e.into_inner()).push(UrlPosition {
                                    url,
                                    link_type,
                                    inline: true,
                                    attr_name: Some("style".to_string()),
                                    expect_html: false,
                                    expect_css: false,
                                    meta_disallow_follow: *nofollow_clone.lock().unwrap_or_else(|e| e.into_inner()),
                                });
                            }
                        }

                        if !follow_tags.iter().any(|t| t.eq_ignore_ascii_case(tag_str)) {
                            return Ok(());
                        }

                        if tag_str == "meta" {
                            if let Some(name) = el.get_attribute("name") {
                                if name.eq_ignore_ascii_case("robots") {
                                    if let Some(content) = el.get_attribute("content") {
                                        if content.to_ascii_lowercase().contains("nofollow") {
                                            *nofollow_clone.lock().unwrap_or_else(|e| e.into_inner()) = true;
                                        }
                                    }
                                }
                            }

                            if let Some(equiv) = el.get_attribute("http-equiv") {
                                if equiv.eq_ignore_ascii_case("refresh") {
                                    if let Some(content) = el.get_attribute("content") {
                                        if let Some(refresh_url) = parse_meta_refresh_url(&content) {
                                            results_clone.lock().unwrap_or_else(|e| e.into_inner()).push(UrlPosition {
                                                url: refresh_url,
                                                link_type: LinkType::RefreshRedirect,
                                                inline: false,
                                                attr_name: Some("content".to_string()),
                                                expect_html: true,
                                                expect_css: false,
                                                meta_disallow_follow: *nofollow_clone.lock().unwrap_or_else(|e| e.into_inner()),
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
                                    results_clone.lock().unwrap_or_else(|e| e.into_inner()).push(UrlPosition {
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

                        // Harvest EVERY URL attribute of the tag (wget
                        // tag_url_attributes, html-url.c:141-169): img has
                        // src/lowsrc/href, video/audio have src/poster,
                        // embed has href/src, form has action, table/td/th
                        // have background, etc. The previous single-attr map
                        // silently dropped the rest.
                        for attr_name in url_attrs_for_tag(tag_str) {
                            if let Some(url) = el.get_attribute(attr_name) {
                                let url = url.trim().to_string();
                                if url.is_empty() || url.starts_with('#')
                                    || url.starts_with("javascript:")
                                    || url.starts_with("data:")
                                {
                                    // Continue to check srcset/style below
                                } else {
                                    let link_type = classify_link(&url);
                                    let inline = is_inline_tag(tag_str);
                                    let expect_html = matches!(tag_str,
                                        "a" | "area" | "iframe" | "frame" | "embed" | "layer" | "overlay");
                                    let expect_css = tag_str == "link"
                                        && el.get_attribute("rel")
                                            .map(|r| r.eq_ignore_ascii_case("stylesheet"))
                                            .unwrap_or(false);

                                    results_clone.lock().unwrap_or_else(|e| e.into_inner()).push(UrlPosition {
                                        url,
                                        link_type,
                                        inline,
                                        attr_name: Some(attr_name.to_string()),
                                        expect_html,
                                        expect_css,
                                        meta_disallow_follow: *nofollow_clone.lock().unwrap_or_else(|e| e.into_inner()),
                                    });
                                }
                            }
                        }

                        // Extract URLs from srcset attribute (img, source)
                        if matches!(tag_str, "img" | "source") {
                            if let Some(srcset) = el.get_attribute("srcset") {
                                for url in parse_srcset_urls(&srcset) {
                                    let link_type = classify_link(&url);
                                    results_clone.lock().unwrap_or_else(|e| e.into_inner()).push(UrlPosition {
                                        url,
                                        link_type,
                                        inline: true,
                                        attr_name: Some("srcset".to_string()),
                                        expect_html: false,
                                        expect_css: false,
                                        meta_disallow_follow: *nofollow_clone.lock().unwrap_or_else(|e| e.into_inner()),
                                    });
                                }
                            }
                        }

                        Ok(())
                    }),
                    // Extract URLs from <style> block text content
                    text!("style", move |t| {
                        let css = t.as_str();
                        for url in extract_css_urls_from_str(css) {
                            let link_type = classify_link(&url);
                            results_clone2.lock().unwrap_or_else(|e| e.into_inner()).push(UrlPosition {
                                url,
                                link_type,
                                inline: true,
                                attr_name: None,
                                expect_html: false,
                                expect_css: true,
                                meta_disallow_follow: *nofollow_clone2.lock().unwrap_or_else(|e| e.into_inner()),
                            });
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
            Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        };

        let nofollow = match Arc::try_unwrap(nofollow_flag) {
            Ok(mutex) => mutex.into_inner().unwrap_or(false),
            Err(arc) => *arc.lock().unwrap_or_else(|e| e.into_inner()),
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

