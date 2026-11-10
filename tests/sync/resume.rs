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
