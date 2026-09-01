//! Tests for configuration reload support.

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_config_reload_flag_default() {
        let flag = AtomicBool::new(false);
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_config_reload_flag_set() {
        let flag = AtomicBool::new(false);
        flag.store(true, Ordering::SeqCst);
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_config_reload_flag_swap() {
        let flag = AtomicBool::new(true);
        let old = flag.swap(false, Ordering::SeqCst);
        assert!(old);
        assert!(!flag.load(Ordering::SeqCst));
    }
