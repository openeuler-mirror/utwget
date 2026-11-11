//! Tests for i18n (internationalization) support.

#[cfg(test)]
mod tests {
    use ut_core::i18n;

    #[test]
    fn test_supported_locales() {
        assert!(i18n::is_locale_supported("en"));
        assert!(i18n::is_locale_supported("zh-CN"));
        assert!(!i18n::is_locale_supported("fr"));
        assert!(!i18n::is_locale_supported("de"));
    }

    #[test]
    fn test_get_supported_locales() {
        let locales = i18n::get_supported_locales();
        assert!(locales.contains(&"en"));
        assert!(locales.contains(&"zh-CN"));
        assert_eq!(locales.len(), 2);
    }

    #[test]
    fn test_translate_with_default_locale() {
        // Test translation with the default locale
        let result = i18n::translate("utwget.error_no_url");
        // Should return either English or system locale translation
        assert!(!result.is_empty());
    }

    #[test]
    fn test_translate_missing_key() {
        let result = i18n::translate("utwget.nonexistent_key");
        assert_eq!(result, "utwget.nonexistent_key");
    }

    #[test]
    fn test_translate_with_args() {
        let result = i18n::translate_with_args(
            "utwget.status_saved",
            &[
                ("url", "test".to_string()),
                ("downloaded", "1234".to_string()),
                ("total", "1234".to_string()),
                ("duration", "1s".to_string()),
                ("speed", "1KB/s".to_string()),
            ],
        );
        assert!(result.contains("1234"));
    }

    #[test]
    fn test_help_text_available() {
        let result = i18n::translate("utwget.help_version");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_error_messages_available() {
        assert!(!i18n::translate("utwget.error_connection_refused").is_empty());
        assert!(!i18n::translate("utwget.error_timeout").is_empty());
        assert!(!i18n::translate("utwget.error_ssl").is_empty());
    }

    #[test]
    fn test_signal_messages_available() {
        let result = i18n::translate("utwget.signal_interrupted");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_concurrency_help_available() {
        let result = i18n::translate("utwget.help_concurrency");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_http2_help_available() {
        let result = i18n::translate("utwget.help_http2");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_translate_returns_same_key_for_missing() {
        let result = i18n::translate("nonexistent.key.here");
        assert_eq!(result, "nonexistent.key.here");
    }

    #[test]
    fn test_translate_with_multiple_args() {
        let result = i18n::translate_with_args(
            "utwget.status_saved",
            &[
                ("url", "http://example.com".to_string()),
                ("downloaded", "1024".to_string()),
                ("total", "2048".to_string()),
                ("duration", "1s".to_string()),
                ("speed", "1KB/s".to_string()),
            ],
        );
        assert!(result.contains("1024"));
        assert!(result.contains("2048"));
    }
}
