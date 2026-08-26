use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

/// Global flag indicating configuration should be reloaded.
pub static CONFIG_RELOAD_FLAG: AtomicBool = AtomicBool::new(false);

/// Configuration reload manager.
///
/// Monitors configuration files for changes and triggers reload when needed.
/// This is a utwget extension (not in original wget).
pub struct ConfigReloader {
    /// Paths to watch for changes.
    watch_paths: Vec<PathBuf>,
    /// Last modification times for each path.
    last_modified: Vec<Option<SystemTime>>,
    /// Shared configuration to update on reload.
    config: Arc<Mutex<ut_core::Config>>,
}
