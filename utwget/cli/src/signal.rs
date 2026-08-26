use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Global flag indicating SIGINT was received (Ctrl+C).
pub static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Global flag indicating SIGHUP/SIGUSR1 was received (redirect output).
pub static SIGHUP_RECEIVED: AtomicBool = AtomicBool::new(false);
