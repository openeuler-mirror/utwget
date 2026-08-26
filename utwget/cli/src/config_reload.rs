use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

/// Global flag indicating configuration should be reloaded.
pub static CONFIG_RELOAD_FLAG: AtomicBool = AtomicBool::new(false);
