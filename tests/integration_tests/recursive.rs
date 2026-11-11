// 递归相关测试 - UrlQueue、DownloadRegistry、RecursiveRetriever

// ========== UrlQueue BFS 测试 ==========

#[test]
fn test_url_queue_push_and_pop_bfs() {
    use ut_retriever::UrlQueue;
    use ut_retriever::QueueEntry;
    let mut queue = UrlQueue::new(Some(5));
    queue.push(QueueEntry {
        url: "http://example.com/a".into(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });
    queue.push(QueueEntry {
        url: "http://example.com/b".into(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });
    assert_eq!(queue.len(), 2);
    let first = queue.pop().unwrap();
    assert_eq!(first.url, "http://example.com/a");
    let second = queue.pop().unwrap();
    assert_eq!(second.url, "http://example.com/b");
    assert!(queue.is_empty());
}

#[test]
fn test_url_queue_dedup() {
    use ut_retriever::UrlQueue;
    use ut_retriever::QueueEntry;
    let mut queue = UrlQueue::new(Some(5));
    queue.push(QueueEntry {
        url: "http://example.com/page".into(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });
    queue.push(QueueEntry {
        url: "http://example.com/page".into(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });
    assert_eq!(queue.len(), 1);
}

#[test]
fn test_url_queue_dedup_ignores_fragment() {
    use ut_retriever::UrlQueue;
    use ut_retriever::QueueEntry;
    let mut queue = UrlQueue::new(Some(5));
    queue.push(QueueEntry {
        url: "http://example.com/page#section1".into(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });
    queue.push(QueueEntry {
        url: "http://example.com/page#section2".into(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });
    assert_eq!(queue.len(), 1);
}

#[test]
fn test_url_queue_max_depth_filter() {
    use ut_retriever::UrlQueue;
    use ut_retriever::QueueEntry;
    let mut queue = UrlQueue::new(Some(1));
    queue.push(QueueEntry {
        url: "http://example.com/a".into(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });
    queue.push(QueueEntry {
        url: "http://example.com/b".into(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });
    queue.push(QueueEntry {
        url: "http://example.com/c".into(),
        referer: None,
        depth: 2,
        expect_html: true,
        expect_css: false,
    });
    assert_eq!(queue.len(), 2);
}

#[test]
fn test_url_queue_visited_tracking() {
    use ut_retriever::UrlQueue;
    use ut_retriever::QueueEntry;
    let mut queue = UrlQueue::new(None);
    queue.push(QueueEntry {
        url: "http://example.com/a".into(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });
    let _ = queue.pop();
    assert!(queue.is_visited("http://example.com/a"));
    assert!(!queue.is_visited("http://example.com/b"));
}

#[test]
fn test_url_queue_mark_visited() {
    use ut_retriever::UrlQueue;
    let mut queue = UrlQueue::new(None);
    queue.mark_visited("http://example.com/seen");
    assert!(queue.is_visited("http://example.com/seen"));
    assert_eq!(queue.visited_count(), 1);
}

#[test]
fn test_url_queue_clear() {
    use ut_retriever::UrlQueue;
    use ut_retriever::QueueEntry;
    let mut queue = UrlQueue::new(None);
    queue.push(QueueEntry {
        url: "http://example.com/a".into(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });
    assert_eq!(queue.len(), 1);
    queue.clear();
    assert!(queue.is_empty());
    assert_eq!(queue.visited_count(), 0);
}

// ========== DownloadRegistry 测试 ==========

#[test]
fn test_download_registry_register_and_query() {
    use ut_retriever::DownloadRegistry;
    use std::path::PathBuf;
    let mut registry = DownloadRegistry::new();
    let local = PathBuf::from("/tmp/page.html");
    registry.register_download("http://example.com/page.html", &local);
    assert!(registry.is_downloaded("http://example.com/page.html"));
    assert_eq!(registry.get_local("http://example.com/page.html"), Some(&local));
}

#[test]
fn test_download_registry_redirect() {
    use ut_retriever::DownloadRegistry;
    use std::path::Path;
    let mut registry = DownloadRegistry::new();
    registry.register_download("http://example.com/final", Path::new("/tmp/final.html"));
    registry.register_redirection("http://example.com/old", "http://example.com/final");
    assert!(registry.is_visited("http://example.com/old"));
    let local = registry.get_local("http://example.com/old");
    assert!(local.is_some());
}

#[test]
fn test_download_registry_resolve_redirect_chain() {
    use ut_retriever::DownloadRegistry;
    use std::path::Path;
    let mut registry = DownloadRegistry::new();
    registry.register_download("http://example.com/dest", Path::new("/tmp/dest.html"));
    registry.register_redirection("http://example.com/a", "http://example.com/b");
    registry.register_redirection("http://example.com/b", "http://example.com/dest");
    let resolved = registry.resolve_redirect("http://example.com/a");
    assert_eq!(resolved, Some("http://example.com/dest".to_string()));
}

#[test]
fn test_download_registry_not_downloaded() {
    use ut_retriever::DownloadRegistry;
    let registry = DownloadRegistry::new();
    assert!(!registry.is_downloaded("http://example.com/unknown"));
    assert!(registry.get_local("http://example.com/unknown").is_none());
}

#[test]
fn test_download_registry_url_to_local_map() {
    use ut_retriever::DownloadRegistry;
    use std::path::Path;
    let mut registry = DownloadRegistry::new();
    registry.register_download("http://example.com/a", Path::new("/tmp/a.html"));
    registry.register_download("http://example.com/b", Path::new("/tmp/b.html"));
    let map = registry.url_to_local_map();
    assert_eq!(map.len(), 2);
}

// ========== RecursiveRetriever 配置组装测试 ==========

#[test]
fn test_recursive_config_defaults() {
    use ut_core::Config;
    let config = Config::default();
    assert!(!config.recursive.enabled);
    assert_eq!(config.recursive.max_level, Some(5));
    assert!(!config.recursive.span_hosts);
    assert!(!config.recursive.no_parent);
    assert!(!config.recursive.relative_only);
    assert!(!config.recursive.spider);
    assert!(config.recursive.use_robots);
    assert!(!config.recursive.follow_tags.is_empty());
    assert!(config.recursive.ignore_tags.is_empty());
    assert!(config.recursive.accept_patterns.is_empty());
    assert!(config.recursive.reject_patterns.is_empty());
}

#[test]
fn test_recursive_mirror_sets_flags() {
    use clap::Parser;
    use utwget_cli::args::Args;
    use utwget_cli::app::build_config;
    let args = Args::try_parse_from(["utwget", "-m", "http://example.com/"]).unwrap();
    let config = build_config(&args);
    assert!(config.recursive.enabled);
    assert!(config.timestamping);
    assert!(config.convert_links);
    assert!(config.page_requisites);
    assert!(config.continue_download);
    assert_eq!(config.recursive.max_level, Some(0));
    assert!(!config.recursive.use_robots);
}

// ========== ContentExtractor trait 接口一致性 ==========

#[test]
fn test_content_extractor_trait_objects() {
    use ut_html::{HtmlExtractor, CssExtractor, ContentExtractor};
    use ut_html::ExtractOptions;
    use std::io::Cursor;
    let opts = ExtractOptions::default();

    let html_extractor: Box<dyn ContentExtractor> = Box::new(HtmlExtractor);
    let mut html_cursor = Cursor::new(b"<a href='/'>link</a>".as_slice());
    let _ = html_extractor.extract_urls(&mut html_cursor, "", &opts).unwrap();
    assert!(matches!(html_extractor.content_kind(), ut_html::ContentKind::Html));

    let css_extractor: Box<dyn ContentExtractor> = Box::new(CssExtractor);
    let mut css_cursor = Cursor::new(b"a { url(/bg.png); }".as_slice());
    let _ = css_extractor.extract_urls(&mut css_cursor, "", &opts).unwrap();
    assert!(matches!(css_extractor.content_kind(), ut_html::ContentKind::Css));
}
