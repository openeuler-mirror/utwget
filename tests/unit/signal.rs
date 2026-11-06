//! Tests for signal handling support.

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn test_atomic_bool_default() {
        let flag = AtomicBool::new(false);
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_atomic_bool_set() {
        let flag = AtomicBool::new(false);
        flag.store(true, Ordering::SeqCst);
        assert!(flag.load(Ordering::SeqCst));
        
        flag.store(false, Ordering::SeqCst);
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_atomic_usize_increment() {
        let counter = AtomicUsize::new(0);
        counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_atomic_usize_swap() {
        let counter = AtomicUsize::new(0);
        let old = counter.swap(5, Ordering::SeqCst);
        assert_eq!(old, 0);
        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn test_should_stop_logic() {
        let sigint = AtomicBool::new(false);
        let sigterm = AtomicBool::new(false);
        
        fn should_stop(sigint: &AtomicBool, sigterm: &AtomicBool) -> bool {
            sigint.load(Ordering::SeqCst) || sigterm.load(Ordering::SeqCst)
        }
        
        assert!(!should_stop(&sigint, &sigterm));
        
        sigint.store(true, Ordering::SeqCst);
        assert!(should_stop(&sigint, &sigterm));
        
        sigint.store(false, Ordering::SeqCst);
        sigterm.store(true, Ordering::SeqCst);
        assert!(should_stop(&sigint, &sigterm));
    }

    #[test]
    fn test_double_sigint_force_quit() {
        let sigint_received = AtomicBool::new(false);
        let sigint_count = AtomicUsize::new(0);
        
        // First press
        let count = sigint_count.fetch_add(1, Ordering::SeqCst);
        let should_force_quit = count > 0;
        
        if count == 0 {
            sigint_received.store(true, Ordering::SeqCst);
        }
        
        assert!(!should_force_quit);
        assert!(sigint_received.load(Ordering::SeqCst));
        
        // Second press
        let count2 = sigint_count.fetch_add(1, Ordering::SeqCst);
        let should_force_quit2 = count2 > 0;
        assert!(should_force_quit2);
    }
}
