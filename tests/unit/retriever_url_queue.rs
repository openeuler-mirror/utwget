//! Unit tests for retriever URL queue module.
//!
//! Tests for URL queue push/pop, visited marking, and URL deduplication.

use ut_retriever::*;

// ========== UrlQueue basic tests ==========

#[test]
fn test_url_queue_new() {
    let queue = UrlQueue::new(None);
    assert!(queue.is_empty());
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.visited_count(), 0);
}

#[test]
fn test_url_queue_new_with_max_depth() {
    let queue = UrlQueue::new(Some(3));
    assert!(queue.is_empty());
    assert_eq!(queue.len(), 0);
}

// ========== UrlQueue push/pop tests ==========

#[test]
fn test_url_queue_push_pop_single() {
    let mut queue = UrlQueue::new(None);
    queue.push(QueueEntry {
        url: "http://example.com/".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    assert!(!queue.is_empty());
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.visited_count(), 1);

    let entry = queue.pop();
    assert!(entry.is_some());
    let entry = entry.unwrap();
    assert_eq!(entry.url, "http://example.com/");
    assert_eq!(entry.depth, 0);
    assert!(entry.expect_html);
    assert!(!entry.expect_css);

    assert!(queue.is_empty());
    assert_eq!(queue.len(), 0);
    // visited_count should still be 1 after pop
    assert_eq!(queue.visited_count(), 1);
}
