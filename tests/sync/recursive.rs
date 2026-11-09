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
