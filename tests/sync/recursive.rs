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
