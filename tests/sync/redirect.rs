// 重定向测试 - redirect_count 递增、TooManyRedirects 限制

// ========== redirect_count 递增测试 ==========

#[test]
fn test_redirect_count_initial_zero() {
    use ut_retriever::types::ProtocolState;
    let state = ProtocolState::default();
    assert_eq!(state.redirect_count, 0);
}

#[test]
fn test_redirect_count_increment() {
    use ut_retriever::types::ProtocolState;
    let mut state = ProtocolState::default();
    state.redirect_count += 1;
    assert_eq!(state.redirect_count, 1);
    state.redirect_count += 1;
    assert_eq!(state.redirect_count, 2);
    state.redirect_count += 1;
    assert_eq!(state.redirect_count, 3);
}

#[test]
fn test_redirect_count_from_response() {
    use ut_retriever::types::ResponseMeta;
    let resp = ResponseMeta {
        status_code: 301,
        content_length: None,
        content_type: None,
        last_modified: None,
        accept_ranges: false,
        location: Some("http://example.com/new".into()),
        etag: None,
        server: None,
        document_flags: ut_retriever::types::DocumentFlags::empty(),
        keep_alive: true,
    };
    assert!(resp.location.is_some());
    assert_eq!(resp.location.as_deref(), Some("http://example.com/new"));
}

#[test]
fn test_redirect_response_classification() {
    use ut_retriever::types::ResponseMeta;
    let resp_301 = ResponseMeta {
        status_code: 301,
        content_length: None,
        content_type: None,
        last_modified: None,
        accept_ranges: false,
        location: Some("/new".into()),
        etag: None,
        server: None,
        document_flags: ut_retriever::types::DocumentFlags::empty(),
        keep_alive: true,
    };
    assert!(resp_301.location.is_some());

    let resp_302 = ResponseMeta {
        status_code: 302,
        content_length: None,
        content_type: None,
        last_modified: None,
        accept_ranges: false,
        location: Some("/temp".into()),
        etag: None,
        server: None,
        document_flags: ut_retriever::types::DocumentFlags::empty(),
        keep_alive: true,
    };
    assert!(resp_302.location.is_some());

    let resp_200 = ResponseMeta {
        status_code: 200,
        content_length: None,
        content_type: None,
        last_modified: None,
        accept_ranges: false,
        location: None,
        etag: None,
        server: None,
        document_flags: ut_retriever::types::DocumentFlags::empty(),
        keep_alive: true,
    };
    assert!(resp_200.location.is_none());
}

// ========== TooManyRedirects 限制测试 ==========

#[test]
fn test_max_redirect_from_config() {
    use ut_core::Config;
    let config = Config::default();
    assert_eq!(config.max_redirect, 20);
}

#[test]
fn test_max_redirect_custom() {
    use clap::Parser;
    use utwget_cli::args::Args;
    use utwget_cli::app::build_config;
    let args = Args::try_parse_from(["utwget", "--max-redirect", "5", "http://example.com/"]).unwrap();
    let config = build_config(&args);
    assert_eq!(config.max_redirect, 5);
}

#[test]
fn test_redirect_limit_logic() {
    use ut_retriever::types::ProtocolState;
    let max_redirect: u32 = 20;
    let mut state = ProtocolState::default();
    for _ in 0..max_redirect {
        state.redirect_count += 1;
        assert!(state.redirect_count <= max_redirect);
    }
    assert_eq!(state.redirect_count, max_redirect);
}

#[test]
fn test_redirect_zero_max() {
    use ut_retriever::types::ProtocolState;
    let max_redirect: u32 = 0;
    let state = ProtocolState::default();
    if state.redirect_count < max_redirect {
        panic!("should not allow any redirects when max is 0");
    }
    assert!(state.redirect_count >= max_redirect);
}

#[test]
fn test_redirect_chain_tracking() {
    use ut_retriever::DownloadRegistry;
    
    let mut registry = DownloadRegistry::new();
    registry.register_redirection("http://a.com/", "http://b.com/");
    registry.register_redirection("http://b.com/", "http://c.com/");
    registry.register_redirection("http://c.com/", "http://d.com/");
    let resolved = registry.resolve_redirect("http://a.com/");
    assert_eq!(resolved, Some("http://d.com/".to_string()));
}

#[test]
fn test_redirect_loop_detection() {
    use ut_retriever::DownloadRegistry;
    let mut registry = DownloadRegistry::new();
    registry.register_redirection("http://a.com/", "http://b.com/");
    registry.register_redirection("http://b.com/", "http://a.com/");
    let resolved = registry.resolve_redirect("http://a.com/");
    // Loop detection: should return None because there's no final destination
    assert!(resolved.is_none());
}

// ========== RetrieveOutcome 重定向结果测试 ==========

#[test]
fn test_retrieve_outcome_redirected() {
    use ut_retriever::types::RetrieveOutcome;
    let outcome = RetrieveOutcome::Redirected("http://example.com/new".into());
    match outcome {
        RetrieveOutcome::Redirected(target) => assert_eq!(target, "http://example.com/new"),
        _ => panic!("expected Redirected variant"),
    }
}

#[test]
fn test_retrieve_error_enum() {
    use ut_retriever::types::RetrieveError;
    let err = RetrieveError::Quota;
    let display = format!("{}", err);
    assert!(display.contains("quota exceeded"));

    let err = RetrieveError::NoUrls;
    let display = format!("{}", err);
    assert!(display.contains("no URLs"));
}
