use std::sync::OnceLock;

static CURRENT_LOCALE: OnceLock<String> = OnceLock::new();
const DEFAULT_LOCALE: &str = "en";
pub const SUPPORTED_LOCALES: &[&str] = &["en", "zh-CN"];
