// 认证测试 - AuthDispatcher、DigestAuthenticator、BasicAuthenticator

use base64::Engine;

// ========== AuthDispatcher 调度逻辑测试 ==========

#[test]
fn test_auth_dispatcher_basic_scheme() {
    use ut_http::auth::{AuthDispatcher, AuthChallenge, AuthScheme, Authenticator};
    use ut_core::types::Credentials;
    let mut dispatcher = AuthDispatcher::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Basic,
        realm: Some("test".into()),
        nonce: None, opaque: None, qop: None,
        algorithm: None, charset: None, userhash: None,
        stale: None, domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "user".into(), password: "pass".into() };
    let result = dispatcher.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_some());
    assert!(result.unwrap().starts_with("Basic "));
}

#[test]
fn test_auth_dispatcher_unsupported_scheme_returns_none() {
    use ut_http::auth::{AuthDispatcher, AuthChallenge, AuthScheme};
    use ut_core::types::Credentials;
    let mut dispatcher = AuthDispatcher::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Bearer,
        realm: None, nonce: None, opaque: None, qop: None,
        algorithm: None, charset: None, userhash: None,
        stale: None, domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "u".into(), password: "p".into() };
    let result = dispatcher.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_auth_dispatcher_preemptive_auth() {
    use ut_http::auth::AuthDispatcher;
    use ut_core::types::Credentials;
    let mut dispatcher = AuthDispatcher::new();
    let creds = Credentials { username: "admin".into(), password: "secret".into() };
    let result = dispatcher.preemptive_auth(&creds, "/admin");
    assert!(result.is_some());
    let header = result.unwrap();
    assert!(header.starts_with("Basic "));
}
