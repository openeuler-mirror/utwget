//! Tests for async retriever support.

#[cfg(test)]
mod tests {
    use ut_core::Config;

    #[test]
    fn test_config_default_features() {
        let config = Config::default();
        
        // HTTP/2 settings
        assert!(!config.http.force_http2);
        assert!(!config.http.force_http1_1);
        
        // Basic settings
        assert!(!config.quiet);
        assert!(config.verbose >= -1);
        assert_eq!(config.tries, 20);
    }

    #[test]
    fn test_config_http2_options() {
        let mut config = Config::default();
        
        // Test setting HTTP/2 options
        config.http.force_http2 = true;
        assert!(config.http.force_http2);
        
        config.http.force_http1_1 = true;
        assert!(config.http.force_http1_1);
    }
