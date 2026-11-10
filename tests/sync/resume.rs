// 断点续传测试 - ProtocolState、RequestOptions、DocumentFlags

// ========== ProtocolState 初始状态测试 ==========

#[test]
fn test_protocol_state_default_initial() {
    use ut_retriever::types::ProtocolState;
    let state = ProtocolState::default();
    assert_eq!(state.retry_count, 0);
    assert_eq!(state.redirect_count, 0);
    assert_eq!(state.resume_position, 0);
    assert!(!state.head_done);
    assert!(state.last_content_length.is_none());
    assert!(!state.ntlm_seen);
    assert!(!state.auth_finished);
}

#[test]
fn test_protocol_state_field_mutations() {
    use ut_retriever::types::ProtocolState;
    let mut state = ProtocolState::default();
    state.retry_count = 3;
    state.redirect_count = 2;
    state.resume_position = 1024;
    state.head_done = true;
    state.last_content_length = Some(5000);
    state.ntlm_seen = true;
    state.auth_finished = true;
    assert_eq!(state.retry_count, 3);
    assert_eq!(state.redirect_count, 2);
    assert_eq!(state.resume_position, 1024);
    assert!(state.head_done);
    assert_eq!(state.last_content_length, Some(5000));
    assert!(state.ntlm_seen);
    assert!(state.auth_finished);
}

// ========== RequestOptions range_start 设置测试 ==========

#[test]
fn test_request_options_default() {
    use ut_retriever::types::RequestOptions;
    let opts = RequestOptions::default();
    assert!(opts.use_proxy);
    assert!(matches!(opts.method, ut_core::types::HttpMethod::Get));
    assert!(opts.headers.is_empty());
    assert!(opts.post_data.is_none());
    assert!(opts.body_data.is_none());
    assert!(opts.referer.is_none());
    assert!(opts.range_start.is_none());
    assert!(opts.if_modified_since.is_none());
    assert!(opts.if_none_match.is_none());
    assert!(!opts.auth_without_challenge);
    assert!(!opts.save_headers);
    assert!(!opts.content_on_error);
}

#[test]
fn test_request_options_resume_from_position() {
    use ut_retriever::types::RequestOptions;
    let mut opts = RequestOptions::default();
    opts.range_start = Some(2048);
    assert_eq!(opts.range_start, Some(2048));
}

#[test]
fn test_request_options_with_headers() {
    use ut_retriever::types::RequestOptions;
    let mut opts = RequestOptions::default();
    opts.headers.push(("Accept".into(), "application/json".into()));
    opts.headers.push(("X-Custom".into(), "value".into()));
    assert_eq!(opts.headers.len(), 2);
}

#[test]
fn test_request_options_post_method() {
    use ut_retriever::types::RequestOptions;
    let mut opts = RequestOptions::default();
    opts.method = ut_core::types::HttpMethod::Post;
    opts.post_data = Some(b"key=value".to_vec());
    assert!(matches!(opts.method, ut_core::types::HttpMethod::Post));
    assert!(opts.post_data.is_some());
}

#[test]
fn test_request_options_conditional_get() {
    use ut_retriever::types::RequestOptions;
    use chrono::Utc;
    let mut opts = RequestOptions::default();
    let now = Utc::now();
    opts.if_modified_since = Some(now);
    opts.if_none_match = Some("\"etag-value\"".into());
    assert!(opts.if_modified_since.is_some());
    assert_eq!(opts.if_none_match.as_deref(), Some("\"etag-value\""));
}

// ========== DocumentFlags bitflags 操作测试 ==========

#[test]
fn test_document_flags_empty() {
    use ut_retriever::types::DocumentFlags;
    let flags = DocumentFlags::empty();
    assert!(!flags.contains(DocumentFlags::TEXT_HTML));
    assert!(!flags.contains(DocumentFlags::RETRIEVAL_OK));
    assert!(flags.is_empty());
}
