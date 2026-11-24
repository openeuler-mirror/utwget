//! Concurrent file retriever implementation.
//!
//! This module provides a concurrent wrapper around the synchronous
//! `Retriever` using `tokio::task::spawn_blocking`. Each "async" download
//! runs the fully blocking synchronous I/O path on a dedicated tokio
//! blocking thread. This gives thread-level parallelism (equivalent to
//! `std::thread::spawn` with a bounded pool) rather than true async I/O.
//!
//! The download path uses `std::net::TcpStream` and blocking `read`/`write`.
//! A future rewrite to `tokio::net::TcpStream` + async TLS would convert
//! these to true async I/O. Until then, `-j N` provides N parallel OS
//! threads blocked on synchronous I/O, which is adequate for the CLI
//! download use case.

use std::sync::Arc;

use tokio::sync::{Semaphore, OwnedSemaphorePermit};
use ut_core::{Config, WgetError};
use ut_progress::ProgressDisplay;

use crate::retriever::Retriever;
use crate::tls_pool::TlsConnectionPool;
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
    /// 共享 TLS 连接池。所有 `spawn_blocking` 任务 clone 同一池，从而
    /// 真正复用 keep-alive 连接（之前每次 Retriever::new 新建一个 pool，
    /// 8 个并发下载到同一 host 互不可见）。
    connection_pool: TlsConnectionPool,
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
            connection_pool: TlsConnectionPool::new(5),
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
        let _permit = self.acquire_permit().await?;
        let config = self.config.clone();
        let pool = self.connection_pool.clone();
        let url = url.to_string();

        tokio::task::spawn_blocking(move || {
            let progress = create_silent_progress();
            let mut retriever = Retriever::with_connection_pool(config, progress, pool);
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
        let _permit = self.acquire_permit().await?;
        let config = self.config.clone();
        let pool = self.connection_pool.clone();
        let url = url.to_string();

        tokio::task::spawn_blocking(move || {
            let mut retriever = Retriever::with_connection_pool(config, progress, pool);
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
            let pool = self.connection_pool.clone();

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await
                    .map_err(|_| RetrieveError::Protocol(WgetError::Other("semaphore closed".into())))?;
                let url_clone = url.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let progress = create_silent_progress();
                    let mut retriever = Retriever::with_connection_pool(config, progress, pool);
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
    async fn acquire_permit(&self) -> Result<OwnedSemaphorePermit, RetrieveError> {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RetrieveError::Protocol(WgetError::Other("semaphore closed".into())))
    }

    /// Get the shared configuration.
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }
}

/// Create a silent progress display for background downloads.
fn create_silent_progress() -> Box<dyn ProgressDisplay> {
    // Use Verbose style (no progress bar, just download start/end lines)
    // instead of Silent so the user sees activity during -j N downloads.
    // Verbose is safe for concurrent use: it only prints to stderr on
    // begin/finish, with no animated bar that would interleave.
    if std::env::var("UTWGET_CONCURRENT_SILENT").is_ok() {
        ut_progress::create_progress_display(ut_core::ProgressStyle::Silent, true)
    } else {
        ut_progress::create_progress_display(ut_core::ProgressStyle::Verbose, true)
    }
}

/// Download a single URL asynchronously using the default configuration.
///
/// This is a convenience function for simple async downloads.
///
/// # Arguments
///
/// * `url` - The URL to download.
/// * `config` - Shared configuration.
///
/// # Returns
///
/// A `RetrieveOutcome` on success.
pub async fn download(url: &str, config: Arc<Config>) -> Result<RetrieveOutcome, RetrieveError> {
    let retriever = AsyncRetriever::new(config, 1);
    retriever.retrieve(url).await
}

/// Download multiple URLs concurrently with a concurrency limit.
///
/// # Arguments
///
/// * `urls` - The URLs to download.
/// * `config` - Shared configuration.
/// * `max_concurrent` - Maximum number of concurrent downloads.
///
/// # Returns
///
/// A vector of (url, result) pairs.
pub async fn download_many(
    urls: &[String],
    config: Arc<Config>,
    max_concurrent: usize,
) -> Vec<(String, Result<RetrieveOutcome, RetrieveError>)> {
    let retriever = AsyncRetriever::new(config, max_concurrent);
    retriever.retrieve_many(urls).await
}
