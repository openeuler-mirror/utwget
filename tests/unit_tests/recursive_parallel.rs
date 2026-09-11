//! Regression test for the parallel-recursive `active_count` leak (H-5).
//!
//! The worker loop used a manual `fetch_sub` at the end of the loop body
//! that three early-exit paths skipped (quota break, visited continue,
//! robots continue). Any URL taking one of those paths permanently
//! inflated `active_count`, and all workers then spun in the queue-empty
//! wait loop: `retrieve_tree_parallel` never returned.
//!
//! The fix replaces the manual increment/decrement with an RAII guard.
//! These tests exercise the guard directly and run the parallel path
//! end-to-end with a server serving one HTML page linking an
//! already-visited URL (the exact scenario that previously hung).

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ut_core::Config;


// ============================================================================
// ActiveGuard unit tests
// ============================================================================

#[test]
fn active_guard_increments_and_decrements() {
    let counter = AtomicUsize::new(0);
    {
        let _g = ut_retriever::recursive::test_guard(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        // Nested guards (multiple workers active).
        let _g2 = ut_retriever::recursive::test_guard(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }
    assert_eq!(counter.load(Ordering::Relaxed), 0, "guards must fully unwind");
}

#[test]
fn active_guard_decrements_on_early_return() {
    // Mirrors the `continue` paths that previously leaked.
    let counter = AtomicUsize::new(0);
    fn early_return(counter: &AtomicUsize) {
        let _g = ut_retriever::recursive::test_guard(counter);
        // 'visited' check failing → continue → guard drops here
        return;
    }
    early_return(&counter);
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn active_guard_decrements_on_panic() {
    // Even a panic through the loop body must not leak (the original bug
    // left active_count inflated with NO recovery path).
    let counter = AtomicUsize::new(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _g = ut_retriever::recursive::test_guard(&counter);
        panic!("simulated worker panic");
    }));
    assert!(result.is_err());
    assert_eq!(
        counter.load(Ordering::Relaxed),
        0,
        "guard must decrement even on unwind"
    );
}

// ============================================================================
// End-to-end: parallel recursive with a continue-path URL must terminate
// ============================================================================

/// Single-shot HTTP server: accepts one connection, writes `response`,
/// closes. Returns the bound port.
fn one_shot_server(response: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if std::time::Instant::now() > deadline {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    listener.set_nonblocking(false).ok();
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(response);
                    let _ = stream.flush();
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    port
}

#[test]
fn parallel_recursive_with_visited_url_terminates() {
    // Page A links to page B; A is downloaded first, B is already in the
    // visited set (registered by the queue/registry pre-marking), so the
    // worker takes the `visited → continue` path — the path that leaked
    // active_count and hung the process. The test asserts termination via
    // timeout: with the bug this call never returns.
    let port = one_shot_server(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 55\r\n\r\n\
          <html><body><a href=\"/b\">b</a></body></html>\r\n".as_slice(),
    );

    let mut config = Config::default();
    config.recursive.enabled = true;
    config.recursive.max_level = Some(1);
    config.quiet = true;

    let progress = ut_progress::create_progress_display(ut_core::ProgressStyle::Silent, true);
    let mut retriever = ut_retriever::RecursiveRetriever::new(Arc::new(config), progress);
    let url = format!("http://127.0.0.1:{}/a", port);

    // Run in a thread with a watchdog: with the leak, join times out.
    let handle = std::thread::spawn(move || retriever.retrieve_tree_parallel(&url, 2));
    // Watchdog: with the leak, the worker threads never finish and
    // retrieve_tree_parallel never returns — recv_timeout fires.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = handle.join();
        let _ = tx.send(result);
    });
    let joined = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("retrieve_tree_parallel must terminate; hanging indicates the active_count leak regressed");
    let _ = joined;
}
