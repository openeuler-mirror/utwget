use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Global flag indicating SIGINT was received (Ctrl+C).
pub static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Global flag indicating SIGHUP/SIGUSR1 was received (redirect output).
pub static SIGHUP_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Global flag indicating SIGTERM was received (graceful shutdown).
pub static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Counter for SIGINT — after 2 presses, force-quit immediately.
pub static SIGINT_COUNT: AtomicUsize = AtomicUsize::new(0);
