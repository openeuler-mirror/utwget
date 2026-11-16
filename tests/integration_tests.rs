// 集成测试模块
//
// 被 tests/integration.rs 通过 `mod integration_tests;` 引用；用 #[path] 显式
// 指向 integration_tests/ 子目录，保证两种入口都能正确解析。

#[path = "integration_tests/auth.rs"] mod auth;
#[path = "integration_tests/basic_download.rs"] mod basic_download;
#[path = "integration_tests/recursive.rs"] mod recursive;
#[path = "integration_tests/redirect.rs"] mod redirect;
#[path = "integration_tests/resume.rs"] mod resume;
#[path = "integration_tests/warc.rs"] mod warc;
