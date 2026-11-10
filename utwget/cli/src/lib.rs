//! utwget CLI library.
//!
//! This crate provides the command-line interface for utwget,
//! including argument parsing, application logic, and internationalization.

pub mod args;
pub mod app;
pub mod wgetrc;
pub mod i18n;
pub mod signal;
pub mod config_reload;

// Re-export commonly used items
pub use i18n::{translate, translate_with_args, set_locale, current_locale, get_supported_locales, is_locale_supported};
