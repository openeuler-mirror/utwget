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

impl AsyncRetriever {
    /// Create a new async retriever.
    ///
    /// # Arguments
    ///
    /// * `config` - Shared configuration.
    /// * `max_concurrent` - Maximum number of concurrent downloads.
    pub fn new(config: Arc<Config>, max_concurrent: usize) -> Self {
        AsyncRetriever {
            config,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    /// Download a URL asynchronously.
    ///
    /// This method acquires a permit from the semaphore (blocking if at max
    /// concurrency), then runs the synchronous retriever in a blocking thread.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to download.
    ///
    /// # Returns
    ///
    /// A `RetrieveOutcome` on success.
    pub async fn retrieve(&self, url: &str) -> Result<RetrieveOutcome, RetrieveError> {
        let _permit = self.acquire_permit().await;
        let config = self.config.clone();
        let url = url.to_string();

        tokio::task::spawn_blocking(move || {
            let progress = create_silent_progress();
            let mut retriever = Retriever::new(config, progress);
            retriever.retrieve_with_retry(&url)
        })
        .await
        .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("task join error: {}", e))))?
    }

    /// Download a URL with a custom progress display.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to download.
    /// * `progress` - Progress display for this download.
    ///
    /// # Returns
    ///
    /// A `RetrieveOutcome` on success.
    pub async fn retrieve_with_progress(
        &self,
        url: &str,
        progress: Box<dyn ProgressDisplay>,
    ) -> Result<RetrieveOutcome, RetrieveError> {
        let _permit = self.acquire_permit().await;
        let config = self.config.clone();
        let url = url.to_string();

        tokio::task::spawn_blocking(move || {
            let mut retriever = Retriever::new(config, progress);
            retriever.retrieve_with_retry(&url)
        })
        .await
        .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("task join error: {}", e))))?
    }

    /// Download multiple URLs concurrently.
    ///
    /// Returns a vector of (url, result) pairs.
    ///
    /// # Arguments
    ///
    /// * `urls` - The URLs to download.
    ///
    /// # Returns
    ///
    /// A vector of tuples (url, Result<RetrieveOutcome, RetrieveError>).
    pub async fn retrieve_many(
        &self,
        urls: &[String],
    ) -> Vec<(String, Result<RetrieveOutcome, RetrieveError>)> {
        let mut handles = Vec::new();

        for url in urls {
            let url = url.clone();
            let config = self.config.clone();
            let semaphore = self.semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await.unwrap();
                let url_clone = url.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let progress = create_silent_progress();
                    let mut retriever = Retriever::new(config, progress);
                    retriever.retrieve_with_retry(&url_clone)
                })
                .await
                .map_err(|e| {
                    RetrieveError::Protocol(WgetError::Other(format!("task join error: {}", e)))
                })?;
                Ok::<_, RetrieveError>((url, result))
            });
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok((url, result))) => results.push((url, result)),
                Ok(Err(e)) => results.push(("unknown".to_string(), Err(e))),
                Err(e) => results.push(("unknown".to_string(), Err(RetrieveError::Protocol(
                    WgetError::Other(format!("task join error: {}", e)),
                )))),
            }
        }
        results
    }

    /// Acquire a permit from the concurrency semaphore.
    async fn acquire_permit(&self) -> OwnedSemaphorePermit {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed")
    }

    /// Get the shared configuration.
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }
}
