// 单元测试模块
//
// 被 tests/unit.rs 通过 `mod unit_tests;` 引用；同时也可被 Cargo 自动发现为
// `--test unit_tests` 入口。每个子模块用 #[path] 显式指向 unit_tests/ 子目录，
// 以保证两种入口都能正确解析。

#[path = "unit_tests/cli_wgetrc.rs"] mod cli_wgetrc;
#[path = "unit_tests/cli_args.rs"] mod cli_args;
#[path = "unit_tests/dns_ssrf.rs"] mod dns_ssrf;
#[path = "unit_tests/connection_pool.rs"] mod connection_pool;
#[path = "unit_tests/core_cookie.rs"] mod core_cookie;
#[path = "unit_tests/core_hsts.rs"] mod core_hsts;
#[path = "unit_tests/core_netrc.rs"] mod core_netrc;
#[path = "unit_tests/core_robots.rs"] mod core_robots;
#[path = "unit_tests/core_url.rs"] mod core_url;
#[path = "unit_tests/core_utils.rs"] mod core_utils;
#[path = "unit_tests/ftp_listing.rs"] mod ftp_listing;
#[path = "unit_tests/ftps.rs"] mod ftps;
#[path = "unit_tests/ftp_opie.rs"] mod ftp_opie;
#[path = "unit_tests/html_extractor.rs"] mod html_extractor;
#[path = "unit_tests/html_converter.rs"] mod html_converter;
#[path = "unit_tests/h2_integration.rs"] mod h2_integration;
#[path = "unit_tests/http2.rs"] mod http2;
#[path = "unit_tests/http_auth.rs"] mod http_auth;
#[path = "unit_tests/http_headers.rs"] mod http_headers;
#[path = "unit_tests/http_request.rs"] mod http_request;
#[path = "unit_tests/http_response.rs"] mod http_response;
#[path = "unit_tests/i18n.rs"] mod i18n;
#[path = "unit_tests/metalink_parser.rs"] mod metalink_parser;
#[path = "unit_tests/metalink_downloader.rs"] mod metalink_downloader;
#[path = "unit_tests/net_proxy.rs"] mod net_proxy;
#[path = "unit_tests/progress_bar.rs"] mod progress_bar;
#[path = "unit_tests/retriever_types.rs"] mod retriever_types;
#[path = "unit_tests/retriever_response.rs"] mod retriever_response;
#[path = "unit_tests/retriever_url_queue.rs"] mod retriever_url_queue;
#[path = "unit_tests/signal.rs"] mod signal;
#[path = "unit_tests/warc_digest.rs"] mod warc_digest;
#[path = "unit_tests/warc_format.rs"] mod warc_format;
#[path = "unit_tests/async_retriever.rs"] mod async_retriever;
