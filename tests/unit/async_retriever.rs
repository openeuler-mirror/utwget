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

    #[test]
    fn test_config_concurrent_downloads() {
        let mut config = Config::default();
        
        // Default should be 1 (sequential)
        assert_eq!(config.concurrent_downloads, 1);
        
        // Set concurrent downloads
        config.concurrent_downloads = 4;
        assert_eq!(config.concurrent_downloads, 4);
    }

    #[test]
    fn test_config_keep_alive() {
        let config = Config::default();
        assert!(config.http.keep_alive);
    }

    #[test]
    fn test_config_proxy() {
        let mut config = Config::default();
        
        // Default proxy settings
        assert!(config.proxy.use_proxy);
        assert!(config.proxy.no_proxy.is_empty());
        
        // Set proxy
        config.proxy.http_proxy = Some("http://proxy:8080".to_string());
        assert!(config.proxy.use_proxy);
        assert_eq!(config.proxy.http_proxy.unwrap(), "http://proxy:8080");
    }

    #[test]
    fn test_config_tls() {
        let config = Config::default();
        
        // Default TLS settings
        assert!(config.tls.check_certificate != ut_core::CheckCertMode::Off);
    }

    #[test]
    fn test_config_recursive() {
        let mut config = Config::default();
        
        // Default recursive settings
        assert!(!config.recursive.enabled);
        assert_eq!(config.recursive.max_level, Some(5));
        
        // Set recursive
        config.recursive.enabled = true;
        config.recursive.max_level = None; // Unlimited
        assert!(config.recursive.enabled);
        assert!(config.recursive.max_level.is_none());
    }

    #[test]
    fn test_config_cookie() {
        let config = Config::default();
        
        // Default cookie settings
        assert!(config.cookie.enabled);
        assert!(!config.cookie.keep_session_cookies);
    }
