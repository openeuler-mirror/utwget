//! Async file retriever implementation.
//!
//! This module provides async versions of the `Retriever` methods using tokio.
//! The async methods use `tokio::task::spawn_blocking` to run the synchronous
//! I/O operations in a dedicated thread pool, allowing the tokio runtime to
//! manage concurrent downloads efficiently.

use std::sync::Arc;

use tokio::sync::{Semaphore, OwnedSemaphorePermit};
use ut_core::{Config, WgetError};
use ut_progress::ProgressDisplay;

use crate::retriever::Retriever;
use crate::types::{RetrieveError, RetrieveOutcome};

/// Async retriever wrapper that provides async versions of download operations.
///
/// This struct wraps the synchronous `Retriever` and provides async methods
/// that can be used with tokio's async runtime.
#[derive(Clone)]
pub struct AsyncRetriever {
    /// Shared configuration.
    config: Arc<Config>,
    /// Concurrency limit semaphore.
    semaphore: Arc<Semaphore>,
}
