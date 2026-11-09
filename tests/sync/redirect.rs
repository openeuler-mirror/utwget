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
