// 兼容性测试模块
//
// 与原 GNU wget 1.21.4 的行为对比测试。被 tests/compatibility.rs 通过
// `mod compatibility_tests;` 引用；用 #[path] 显式指向 compatibility_tests/ 子目录。

#[path = "compatibility_tests/common.rs"] mod common;
#[path = "compatibility_tests/http.rs"] mod http;
#[path = "compatibility_tests/https.rs"] mod https;
#[path = "compatibility_tests/options.rs"] mod options;
#[path = "compatibility_tests/output.rs"] mod output;
