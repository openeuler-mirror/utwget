//! CSS URL extractor for finding embedded resources in stylesheets.
//!
//! This module provides functionality to parse CSS files and extract
//! URLs from `url()` functions and `@import` rules.

use std::io::Read;

use cssparser::{ParseError, Parser, ParserInput, Token};

use crate::converter::ConvertError;
use crate::types::{ContentExtractor, ContentKind};
use crate::url_position::{ExtractOptions, LinkType, UrlPosition};

/// CSS content extractor for URL extraction.
///
/// Parses CSS stylesheets and extracts URLs from:
/// - `url()` function values (background, content, etc.)
/// - `@import` rules
///
/// # Example
///
/// ```ignore
/// use html::css_extractor::CssExtractor;
/// use html::types::ContentExtractor;
///
/// let extractor = CssExtractor;
/// let css = r#"
///     body { background: url(bg.png); }
///     @import url("reset.css");
/// "#;
/// let urls = extractor.extract_urls(&mut css.as_bytes(), "http://example.com/", &ExtractOptions::default())?;
/// ```
pub struct CssExtractor;

/// Checks if a URL should be skipped during extraction.
///
/// Skips URLs that are:
/// - Empty strings
/// - Data URLs (`data:`)
/// - Fragment identifiers (`#`)
/// - Blob URLs (`blob:`)
///
/// # Arguments
///
/// * `url` - The URL to check.
///
/// # Returns
///
/// `true` if the URL should be skipped, `false` otherwise.
fn is_skippable_url(url: &str) -> bool {
    url.is_empty()
        || url.starts_with("data:")
        || url.starts_with('#')
        || url.starts_with("blob:")
}

/// Attempts to parse a URL from a CSS `url()` function.
///
/// Handles both quoted and unquoted URL tokens within the function.
///
/// # Arguments
///
/// * `parser` - The CSS parser positioned inside a `url()` function.
///
/// # Returns
///
/// `Some(url)` if a valid URL token was found, `None` otherwise.
fn try_parse_url_token(parser: &mut Parser) -> Option<String> {
    let result: Result<Option<String>, ParseError<()>> = parser.parse_nested_block(|inner| {
        let token = inner.next()?;
        match token {
            Token::QuotedString(s) => Ok(Some(s.to_string())),
            Token::UnquotedUrl(s) => Ok(Some(s.to_string())),
            Token::Ident(s) => Ok(Some(s.to_string())),
            _ => Ok(None),
        }
    });
    result.ok().flatten()
}

/// Recursively extracts URLs from CSS content.
///
/// Walks through CSS tokens and extracts URLs from:
/// - Unquoted URL tokens (`url(path)`)
/// - Quoted URL function values (`url("path")`)
/// - Handles `@import` rules specially to mark imported stylesheets
///
/// # Arguments
///
/// * `parser` - The CSS parser to read tokens from.
/// * `results` - Vector to append extracted URL positions to.
/// * `at_import_found` - Flag indicating if the previous token was `@import`.
fn extract_urls_recursive(
    parser: &mut Parser,
    results: &mut Vec<UrlPosition>,
    at_import_found: &mut bool,
) {
    while let Ok(token) = parser.next_including_whitespace_and_comments() {
        match token {
            Token::UnquotedUrl(ref url) => {
                let url = url.to_string();
                if !is_skippable_url(&url) {
                    results.push(UrlPosition {
                        url,
                        link_type: if *at_import_found {
                            *at_import_found = false;
                            LinkType::CssImport
                        } else {
                            LinkType::Relative
                        },
                        inline: false,
                        attr_name: None,
                        expect_html: false,
                        expect_css: true,
                        meta_disallow_follow: false,
                    });
                }
                *at_import_found = false;
            }
            Token::Function(ref name) if name.eq_ignore_ascii_case("url") => {
                let url = try_parse_url_token(parser);
                if let Some(url) = url {
                    if !is_skippable_url(&url) {
                        results.push(UrlPosition {
                            url,
                            link_type: if *at_import_found {
                                *at_import_found = false;
                                LinkType::CssImport
                            } else {
                                LinkType::Relative
                            },
                            inline: false,
                            attr_name: None,
                            expect_html: false,
                            expect_css: true,
                            meta_disallow_follow: false,
                        });
                    }
                }
                *at_import_found = false;
            }
            Token::AtKeyword(ref keyword) if keyword.eq_ignore_ascii_case("import") => {
                *at_import_found = true;
            }
            Token::CurlyBracketBlock | Token::ParenthesisBlock | Token::SquareBracketBlock => {
                let _: Result<(), ParseError<()>> = parser.parse_nested_block(|inner| {
                    extract_urls_recursive(inner, results, at_import_found);
                    Ok(())
                });
                *at_import_found = false;
            }
            Token::Function(_) => {
                let _: Result<(), ParseError<()>> = parser.parse_nested_block(|inner| {
                    extract_urls_recursive(inner, results, at_import_found);
                    Ok(())
                });
                *at_import_found = false;
            }
            _ => {}
        }
    }
}
