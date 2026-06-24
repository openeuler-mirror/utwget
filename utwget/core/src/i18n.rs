use std::sync::OnceLock;

static CURRENT_LOCALE: OnceLock<String> = OnceLock::new();
const DEFAULT_LOCALE: &str = "en";
pub const SUPPORTED_LOCALES: &[&str] = &["en", "zh-CN"];

pub fn init_locale() {
    if let Ok(lang) = std::env::var("LANGUAGE") {
        if let Some(first) = lang.split(':').next() {
            let normalized = first.replace('_', "-");
            if SUPPORTED_LOCALES.contains(&normalized.as_str()) {
                let _ = CURRENT_LOCALE.set(normalized);
                return;
            }
            if let Some(lang_part) = normalized.split('-').next() {
                if SUPPORTED_LOCALES.contains(&lang_part) {
                    let _ = CURRENT_LOCALE.set(lang_part.to_string());
                    return;
                }
            }
        }
    }
    if let Ok(lang) = std::env::var("LANG") {
        let lang = lang.split('.').next().unwrap_or("en");
        let normalized = lang.replace('_', "-");
        if SUPPORTED_LOCALES.contains(&normalized.as_str()) {
            let _ = CURRENT_LOCALE.set(normalized);
            return;
        }
        if let Some(lang_part) = normalized.split('-').next() {
            if SUPPORTED_LOCALES.contains(&lang_part) {
                let _ = CURRENT_LOCALE.set(lang_part.to_string());
                return;
            }
        }
    }
    let _ = CURRENT_LOCALE.set(DEFAULT_LOCALE.to_string());
}

pub fn set_locale(locale: &str) {
    let locale = if SUPPORTED_LOCALES.contains(&locale) {
        locale.to_string()
    } else {
        let normalized = locale.replace('_', "-");
        if SUPPORTED_LOCALES.contains(&normalized.as_str()) {
            normalized
        } else {
            DEFAULT_LOCALE.to_string()
        }
    };
    let _ = CURRENT_LOCALE.set(locale);
}
