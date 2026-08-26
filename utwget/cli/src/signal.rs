use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Global flag indicating SIGINT was received (Ctrl+C).
pub static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Global flag indicating SIGHUP/SIGUSR1 was received (redirect output).
pub static SIGHUP_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Global flag indicating SIGTERM was received (graceful shutdown).
pub static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Counter for SIGINT — after 2 presses, force-quit immediately.
pub static SIGINT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Install signal handlers for SIGINT, SIGTERM, SIGHUP, SIGUSR1.
///
/// This should be called once at program startup, before the main loop.
///
/// # Safety
///
/// Uses `libc::signal` which is unsafe. The signal handlers only set
/// atomic flags, which is async-signal-safe.
pub unsafe fn install_signal_handlers() {
    extern "C" fn handle_sigint(_: libc::c_int) {
        let count = SIGINT_COUNT.fetch_add(1, Ordering::SeqCst);
        if count == 0 {
            // First Ctrl+C: set flag, main loop will stop current download
            SIGINT_RECEIVED.store(true, Ordering::SeqCst);
        } else {
            // Second Ctrl+C: force immediate exit
            // We call _exit directly to avoid running destructors
            // that might hang (e.g., waiting for network I/O)
            unsafe { libc::_exit(130); }
        }
    }

    extern "C" fn handle_sigterm(_: libc::c_int) {
        SIGTERM_RECEIVED.store(true, Ordering::SeqCst);
    }

    extern "C" fn handle_sighup(_: libc::c_int) {
        SIGHUP_RECEIVED.store(true, Ordering::SeqCst);
    }

    libc::signal(libc::SIGINT, handle_sigint as *const () as libc::sighandler_t);
    libc::signal(libc::SIGTERM, handle_sigterm as *const () as libc::sighandler_t);
    libc::signal(libc::SIGHUP, handle_sighup as *const () as libc::sighandler_t);
    libc::signal(libc::SIGUSR1, handle_sighup as *const () as libc::sighandler_t);

    // Ignore SIGPIPE (broken pipe) — write errors are handled in code
    libc::signal(libc::SIGPIPE, libc::SIG_IGN);
}

/// Check if we should stop the current download (SIGINT or SIGTERM received).
pub fn should_stop() -> bool {
    SIGINT_RECEIVED.load(Ordering::SeqCst) || SIGTERM_RECEIVED.load(Ordering::SeqCst)
}

/// Reset the SIGINT flag after handling it (for continuing to next URL).
#[allow(dead_code)]
pub fn reset_sigint() {
    SIGINT_RECEIVED.store(false, Ordering::SeqCst);
}

/// Check if output should be redirected to a log file (SIGHUP/SIGUSR1 received).
#[allow(dead_code)]
pub fn should_redirect_output() -> bool {
    SIGHUP_RECEIVED.load(Ordering::SeqCst)
}

/// Reset the SIGHUP flag after handling it.
#[allow(dead_code)]
pub fn reset_sighup() {
    SIGHUP_RECEIVED.store(false, Ordering::SeqCst);
}
