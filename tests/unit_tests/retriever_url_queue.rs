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

#[test]
fn test_url_queue_push_pop_multiple() {
    let mut queue = UrlQueue::new(None);

    // Push multiple entries
    for i in 0..5 {
        queue.push(QueueEntry {
            url: format!("http://example.com/page{}.html", i),
            referer: Some("http://example.com/".to_string()),
            depth: 1,
            expect_html: true,
            expect_css: false,
        });
    }

    assert_eq!(queue.len(), 5);

    // Pop all entries (FIFO order)
    for i in 0..5 {
        let entry = queue.pop().unwrap();
        assert_eq!(entry.url, format!("http://example.com/page{}.html", i));
    }

    assert!(queue.is_empty());
}

#[test]
fn test_url_queue_pop_empty() {
    let mut queue = UrlQueue::new(None);
    assert!(queue.pop().is_none());
}

// ========== URL deduplication tests ==========

#[test]
fn test_url_queue_dedup_exact_match() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    // Push same URL again - should be ignored
    queue.push(QueueEntry {
        url: "http://example.com/page.html".to_string(),
        referer: Some("http://other.com/".to_string()),
        depth: 1,
        expect_html: false,
        expect_css: true,
    });

    // Only one entry should be in queue
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.visited_count(), 1);
}

#[test]
fn test_url_queue_dedup_fragment() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    // URL with fragment should be considered the same
    queue.push(QueueEntry {
        url: "http://example.com/page.html#section".to_string(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });

    // Only one entry should be in queue
    assert_eq!(queue.len(), 1);
}

#[test]
fn test_url_queue_dedup_different_fragments() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page.html#section1".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    // Different fragment but same base URL
    queue.push(QueueEntry {
        url: "http://example.com/page.html#section2".to_string(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });

    // Only one entry should be in queue
    assert_eq!(queue.len(), 1);
}

#[test]
fn test_url_queue_dedup_whitespace() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    // URL with leading/trailing whitespace should be considered the same
    queue.push(QueueEntry {
        url: "  http://example.com/page.html  ".to_string(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });

    // Only one entry should be in queue
    assert_eq!(queue.len(), 1);
}

#[test]
fn test_url_queue_different_urls_not_deduped() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page1.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    queue.push(QueueEntry {
        url: "http://example.com/page2.html".to_string(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });

    // Both entries should be in queue
    assert_eq!(queue.len(), 2);
}

// ========== Max depth tests ==========

#[test]
fn test_url_queue_max_depth_exceeded() {
    let mut queue = UrlQueue::new(Some(2));

    // Depth 0 - should be added
    queue.push(QueueEntry {
        url: "http://example.com/".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    // Depth 1 - should be added
    queue.push(QueueEntry {
        url: "http://example.com/page1.html".to_string(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });

    // Depth 2 - should be added (equal to max_depth)
    queue.push(QueueEntry {
        url: "http://example.com/page2.html".to_string(),
        referer: None,
        depth: 2,
        expect_html: true,
        expect_css: false,
    });

    // Depth 3 - should NOT be added (exceeds max_depth)
    queue.push(QueueEntry {
        url: "http://example.com/page3.html".to_string(),
        referer: None,
        depth: 3,
        expect_html: true,
        expect_css: false,
    });

    assert_eq!(queue.len(), 3);
}

#[test]
fn test_url_queue_no_max_depth() {
    let mut queue = UrlQueue::new(None);

    // Any depth should be allowed
    for depth in 0..=100 {
        queue.push(QueueEntry {
            url: format!("http://example.com/page{}.html", depth),
            referer: None,
            depth,
            expect_html: true,
            expect_css: false,
        });
    }

    assert_eq!(queue.len(), 101);
}

// ========== is_visited tests ==========

#[test]
fn test_url_queue_is_visited_after_push() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    assert!(queue.is_visited("http://example.com/page.html"));
    assert!(!queue.is_visited("http://example.com/other.html"));
}

#[test]
fn test_url_queue_is_visited_with_fragment() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    // URL with fragment should also be considered visited
    assert!(queue.is_visited("http://example.com/page.html#section"));
}

#[test]
fn test_url_queue_is_visited_after_pop() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    queue.pop();

    // URL should still be marked as visited after pop
    assert!(queue.is_visited("http://example.com/page.html"));
}

// ========== mark_visited tests ==========

#[test]
fn test_url_queue_mark_visited() {
    let mut queue = UrlQueue::new(None);

    queue.mark_visited("http://example.com/excluded.html");

    assert!(queue.is_visited("http://example.com/excluded.html"));
    // URL should not be in queue (only in blacklist)
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.visited_count(), 1);
}

#[test]
fn test_url_queue_mark_visited_prevents_push() {
    let mut queue = UrlQueue::new(None);

    queue.mark_visited("http://example.com/page.html");

    // Pushing the same URL should be ignored
    queue.push(QueueEntry {
        url: "http://example.com/page.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    assert_eq!(queue.len(), 0);
}

// ========== clear tests ==========

#[test]
fn test_url_queue_clear() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page1.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    queue.push(QueueEntry {
        url: "http://example.com/page2.html".to_string(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });

    assert_eq!(queue.len(), 2);
    assert_eq!(queue.visited_count(), 2);

    queue.clear();

    assert!(queue.is_empty());
    assert_eq!(queue.visited_count(), 0);
    assert!(!queue.is_visited("http://example.com/page1.html"));
}

// ========== visited_count tests ==========

#[test]
fn test_url_queue_visited_count() {
    let mut queue = UrlQueue::new(None);

    assert_eq!(queue.visited_count(), 0);

    queue.push(QueueEntry {
        url: "http://example.com/page1.html".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });
    assert_eq!(queue.visited_count(), 1);

    queue.push(QueueEntry {
        url: "http://example.com/page2.html".to_string(),
        referer: None,
        depth: 1,
        expect_html: true,
        expect_css: false,
    });
    assert_eq!(queue.visited_count(), 2);

    // Duplicate should not increase count
    queue.push(QueueEntry {
        url: "http://example.com/page1.html".to_string(),
        referer: None,
        depth: 2,
        expect_html: true,
        expect_css: false,
    });
    assert_eq!(queue.visited_count(), 2);

    // mark_visited should increase count
    queue.mark_visited("http://example.com/page3.html");
    assert_eq!(queue.visited_count(), 3);
}

// ========== QueueEntry tests ==========

#[test]
fn test_queue_entry_clone() {
    let entry = QueueEntry {
        url: "http://example.com/".to_string(),
        referer: Some("http://referer.com/".to_string()),
        depth: 2,
        expect_html: true,
        expect_css: false,
    };

    let cloned = entry.clone();
    assert_eq!(entry.url, cloned.url);
    assert_eq!(entry.referer, cloned.referer);
    assert_eq!(entry.depth, cloned.depth);
    assert_eq!(entry.expect_html, cloned.expect_html);
    assert_eq!(entry.expect_css, cloned.expect_css);
}

// ========== FIFO order tests ==========

#[test]
fn test_url_queue_fifo_order() {
    let mut queue = UrlQueue::new(None);

    // Push URLs in order
    let urls = [
        "http://example.com/first.html",
        "http://example.com/second.html",
        "http://example.com/third.html",
    ];

    for url in &urls {
        queue.push(QueueEntry {
            url: url.to_string(),
            referer: None,
            depth: 0,
            expect_html: true,
            expect_css: false,
        });
    }

    // Pop should return in same order (FIFO)
    for url in &urls {
        let entry = queue.pop().unwrap();
        assert_eq!(entry.url, *url);
    }
}

// ========== Edge cases ==========

#[test]
fn test_url_queue_empty_url() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    // Empty URL should still be added
    assert_eq!(queue.len(), 1);
    assert!(queue.is_visited(""));
}

#[test]
fn test_url_queue_fragment_only() {
    let mut queue = UrlQueue::new(None);

    queue.push(QueueEntry {
        url: "http://example.com/page.html#".to_string(),
        referer: None,
        depth: 0,
        expect_html: true,
        expect_css: false,
    });

    // URL ending with # should be normalized
    assert!(queue.is_visited("http://example.com/page.html"));
    assert!(queue.is_visited("http://example.com/page.html#"));
}
