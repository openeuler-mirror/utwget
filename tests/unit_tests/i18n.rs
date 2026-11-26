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

// ============================================================================
// locales/*.yml documentation snapshot consistency (report 9.4)
// ============================================================================

fn utwget_has_key(locale: &str, key: &str) -> bool {
    let saved = ut_core::i18n::current_locale().to_string();
    ut_core::i18n::set_locale(locale);
    // translate() falls back to the key itself when the key is missing.
    let present = ut_core::i18n::translate(key) != key;
    ut_core::i18n::set_locale(&saved);
    present
}

#[test]
fn yaml_doc_keys_subset_of_i18n_table() {
    // locales/*.yml are documentation snapshots; the embedded table in
    // core/src/i18n.rs is the source of truth. Keys present in the YAML
    // but missing from the table would mislead contributors; this test
    // pins the snapshots to the table.
    for (yaml_path, locale) in [("locales/en.yml", "en"), ("locales/zh-CN.yml", "zh-CN")] {
        let Ok(content) = std::fs::read_to_string(yaml_path) else {
            continue; // repo layout may differ
        };
        let mut in_utwget_block = false;
        for line in content.lines() {
            let trimmed_line = line.trim();
            if trimmed_line.starts_with('#') || trimmed_line.is_empty() {
                continue;
            }
            if !line.starts_with(' ') {
                // Top-level key: enter the utwget block, skip metadata keys.
                in_utwget_block = trimmed_line == "utwget:";
                continue;
            }
            if !in_utwget_block {
                continue;
            }
            // Only single-line quoted values are snapshot keys; block
            // scalars (e.g. `version_features: |`) span many lines and
            // their continuation lines must not be treated as keys.
            if !trimmed_line.ends_with('"') {
                continue;
            }
            let Some((key, _)) = trimmed_line.split_once(": ") else {
                continue;
            };
            let key = key.trim().trim_matches('"');
            if key.is_empty() || key.contains(' ') {
                continue;
            }
            let full = format!("utwget.{}", key);
            assert!(
                utwget_has_key(locale, &full),
                "locales/{} key '{}' missing from core/src/i18n.rs table",
                yaml_path,
                full
            );
        }
    }
}
