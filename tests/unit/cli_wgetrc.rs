//! Unit tests for wgetrc configuration file parsing.
//!
//! These tests verify the parsing and application of wgetrc configuration files,
//! including key-value settings, boolean toggles, and error handling.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use utwget_cli::wgetrc::{WgetrcCommand, WgetrcParser};
use ut_core::Config;

// ============================================================================
// Helper Functions
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
