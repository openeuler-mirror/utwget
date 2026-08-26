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

impl ConfigReloader {
    /// Create a new configuration reloader.
    ///
    /// # Arguments
    ///
    /// * `watch_paths` - Paths to configuration files to monitor.
    /// * `config` - Shared configuration to update on reload.
    pub fn new(watch_paths: Vec<PathBuf>, config: Arc<Mutex<ut_core::Config>>) -> Self {
        let last_modified = watch_paths.iter().map(|_| None).collect();
        
        ConfigReloader {
            watch_paths,
            last_modified,
            config,
        }
    }

    /// Start the configuration reload monitor in a background thread.
    ///
    /// # Arguments
    ///
    /// * `interval` - How often to check for changes (default: 5 seconds).
    pub fn start(&mut self, interval: Duration) {
        // Record initial modification times
        for (i, path) in self.watch_paths.iter().enumerate() {
            if let Ok(metadata) = std::fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    self.last_modified[i] = Some(modified);
                    log::debug!("watching config file: {} (mtime: {:?})", path.display(), modified);
                }
            }
        }
        
        let watch_paths = self.watch_paths.clone();
        let mut last_modified = self.last_modified.clone();
        let config = self.config.clone();
        
        thread::spawn(move || {
            loop {
                thread::sleep(interval);
                
                // Check for file changes by comparing modification times
                let mut changed = false;
                for (i, path) in watch_paths.iter().enumerate() {
                    match std::fs::metadata(path) {
                        Ok(metadata) => {
                            if let Ok(modified) = metadata.modified() {
                                let prev = last_modified[i];
                                if prev.is_none() || prev.unwrap() != modified {
                                    log::info!("config file changed: {}", path.display());
                                    last_modified[i] = Some(modified);
                                    changed = true;
                                }
                            }
                        }
                        Err(_) => {
                            // File may have been deleted
                            if last_modified[i].is_some() {
                                log::info!("config file deleted: {}", path.display());
                                last_modified[i] = None;
                                changed = true;
                            }
                        }
                    }
                }
                
                if changed {
                    CONFIG_RELOAD_FLAG.store(true, Ordering::SeqCst);
                    Self::reload_config(&watch_paths, &config);
                }
            }
        });
    }

    /// Reload configuration from files.
    fn reload_config(paths: &[PathBuf], config: &Arc<Mutex<ut_core::Config>>) {
        let mut new_config = ut_core::Config::default();
        
        for path in paths {
            if path.exists() {
                match crate::wgetrc::WgetrcParser::parse(path) {
                    Ok(commands) => {
                        if let Err(e) = crate::wgetrc::WgetrcParser::apply(&commands, &mut new_config) {
                            log::warn!("error applying {}: {}", path.display(), e);
                        }
                    }
                    Err(e) => {
                        log::warn!("error reading {}: {}", path.display(), e);
                    }
                }
            }
        }
        
        if let Ok(mut config) = config.lock() {
            *config = new_config;
            log::info!("configuration reloaded");
        }
    }

    /// Check if a reload has been requested.
    pub fn should_reload() -> bool {
        CONFIG_RELOAD_FLAG.swap(false, Ordering::SeqCst)
    }
}
