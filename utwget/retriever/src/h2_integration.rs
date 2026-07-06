//! HTTP/2 integration with the retriever.
//!
//! This module provides integration between the HTTP/2 client and the retriever,
//! allowing transparent use of HTTP/2 when available, including over proxies.
//!
//! # Connection Multiplexing
//!
//! HTTP/2 supports multiple streams over a single connection. This module
//! caches established HTTP/2 connections keyed by (host, port) so that
//! repeated requests to the same host reuse the same connection, avoiding
//! the expensive TLS + HTTP/2 handshake on every request.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, OnceLock};
use log::debug;

use crate::types::RetrieveError;
use ut_core::{Config, WgetError};
use ut_core::url::ParsedUrl;
use ut_http::request::HttpRequest;
use ut_http::response::{HeaderMap, HttpResponse};

/// Process-wide cache of HTTP/2 connections, keyed by (host, port).
///
/// Reusing an HTTP/2 connection avoids the TLS + h2 handshake on every
/// request to the same host, and enables stream multiplexing (multiple
/// requests share one connection). Entries are evicted when the cache is
/// full (LRU-ish: oldest entry dropped).
static H2_POOL: OnceLock<H2ConnectionPool> = OnceLock::new();

/// Maximum number of HTTP/2 connections to cache.
const H2_POOL_MAX_ENTRIES: usize = 8;

/// Returns the process-wide HTTP/2 connection pool.
pub fn h2_pool() -> &'static H2ConnectionPool {
    H2_POOL.get_or_init(|| H2ConnectionPool::new(H2_POOL_MAX_ENTRIES))
}

/// Process-wide tokio runtime for HTTP/2 operations.
///
/// Sharing a single runtime avoids creating (and leaking) a new runtime per
/// HTTP/2 connection, which would spawn a fresh thread pool each time and
/// could exhaust system threads under heavy use. The runtime drives the H2
/// connection driver task and runs async handshakes via `block_on`.
static H2_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Returns the process-wide tokio runtime for HTTP/2 operations.
fn h2_runtime() -> &'static tokio::runtime::Runtime {
    H2_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to create H2 runtime")
    })
}

/// A generic connection pool keyed by (host, port).
///
/// Generic over the connection type `T` so the pool logic can be unit-tested
/// with a mock connection type. In production, `T = ut_http::h2::H2Client`.
pub struct ConnectionPool<T> {
    cache: Mutex<std::collections::HashMap<(String, u16), T>>,
    max_entries: usize,
}

impl<T> ConnectionPool<T> {
    /// Create a new pool with the given maximum number of entries.
    pub fn new(max_entries: usize) -> Self {
        ConnectionPool {
            cache: Mutex::new(std::collections::HashMap::new()),
            max_entries: max_entries.max(1),
        }
    }

    /// Take a connection from the pool, if one exists for (host, port).
    ///
    /// The connection is removed from the pool (not cloned) so the caller
    /// takes ownership. If the connection turns out to be dead, the caller
    /// should not return it via `put`.
    pub fn take(&self, host: &str, port: u16) -> Option<T> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.remove(&(host.to_string(), port))
    }

    /// Return a connection to the pool for reuse.
    ///
    /// If the pool is full, the oldest entry (by `HashMap` iteration order)
    /// is evicted to make room.
    pub fn put(&self, host: String, port: u16, conn: T) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        // Evict an arbitrary entry if at capacity. HashMap iteration order is
        // effectively random, providing simple eviction.
        if cache.len() >= self.max_entries && !cache.contains_key(&(host.clone(), port)) {
            if let Some(key) = cache.keys().next().cloned() {
                cache.remove(&key);
                debug!("evicted H2 pool entry for {}:{}", key.0, key.1);
            }
        }
        cache.insert((host, port), conn);
    }

    /// Number of cached connections.
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all cached connections.
    pub fn clear(&self) {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// HTTP/2 connection pool (concrete instantiation for `H2Client`).
pub type H2ConnectionPool = ConnectionPool<ut_http::h2::H2Client>;

/// HTTP/2 client wrapper that integrates with the retriever.
///
/// On `Drop`, if the connection is still usable, it is returned to the
/// process-wide pool for reuse by subsequent requests to the same host.
pub struct H2Retriever {
    /// HTTP/2 client for making requests. `None` after the connection has been
    /// returned to the pool or determined to be unusable.
    client: Option<ut_http::h2::H2Client>,
    /// Target host.
    host: String,
    /// Target port.
    port: u16,
    /// Whether the connection is still considered reusable (no error occurred).
    reusable: bool,
}

impl H2Retriever {
    /// Create a new HTTP/2 retriever connection.
    ///
    /// Attempts to reuse a pooled HTTP/2 connection for (host, port) first.
    /// If none is available, establishes a new connection (optionally via a
    /// proxy CONNECT tunnel).
    ///
    /// # Arguments
    ///
    /// * `url` - The target URL.
    /// * `config` - Application configuration.
    ///
    /// # Returns
    ///
    /// An `H2Retriever` if HTTP/2 is supported, or error.
    pub fn connect(url: &ParsedUrl, config: &Config) -> Result<Self, RetrieveError> {
        let host = url.host.clone();
        let port = url.port;

        // Try to reuse a pooled HTTP/2 connection first (multiplexing).
        if let Some(client) = h2_pool().take(&host, port) {
            debug!("reusing pooled HTTP/2 connection to {}:{}", host, port);
            return Ok(H2Retriever {
                client: Some(client),
                host,
                port,
                reusable: true,
            });
        }

        // Reuse the same proxy decision as the HTTP/1.1 path so behavior is
        // consistent (e.g. localhost / no-proxy domains, and only routing via
        // proxy when a proxy URL is actually configured).
        let use_proxy = config.proxy.use_proxy && crate::utils::is_url_proxied(url, config);

        if use_proxy {
            debug!("attempting HTTP/2 connection via proxy to {}:{}", host, port);
            Self::connect_via_proxy(&host, port, config)
        } else {
            debug!("attempting HTTP/2 connection to {}:{}", host, port);
            Self::connect_direct(&host, port, config)
        }
    }

    /// Create a direct HTTP/2 connection (no proxy).
    fn connect_direct(host: &str, port: u16, config: &Config) -> Result<Self, RetrieveError> {
        let mut tls_config = build_h2_tls_config(config)?;
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let client = ut_http::h2::H2Client::connect(host, port, tls_config)
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("HTTP/2 connection failed: {}", e)
            )))?;

        Ok(H2Retriever {
            client: Some(client),
            host: host.to_string(),
            port,
            reusable: true,
        })
    }

    /// Create an HTTP/2 connection through a proxy using CONNECT tunnel.
    ///
    /// This method:
    /// 1. Connects to the proxy server
    /// 2. Sends an HTTP CONNECT request to establish a tunnel
    /// 3. Performs TLS handshake over the tunnel
    /// 4. Performs HTTP/2 handshake
    fn connect_via_proxy(host: &str, port: u16, config: &Config) -> Result<Self, RetrieveError> {
        let proxy = get_proxy_config(config)?;

        debug!("connecting to proxy {}:{}", proxy.host, proxy.port);

        // Connect to proxy
        let mut stream = std::net::TcpStream::connect(format!("{}:{}", proxy.host, proxy.port))
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("failed to connect to proxy: {}", e)
            )))?;

        // Set connection timeout
        if let Some(timeout) = config.connect_timeout {
            stream.set_read_timeout(Some(timeout))
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                    format!("failed to set timeout: {}", e)
                )))?;
        }

        // Send CONNECT request
        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            host, port, host, port
        );
        debug!("CONNECT request: {}", connect_req.trim());
        stream.write_all(connect_req.as_bytes())
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("failed to send CONNECT request: {}", e)
            )))?;
        stream.flush()
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("failed to flush CONNECT request: {}", e)
            )))?;

        // Read CONNECT response
        let mut response = String::new();
        let mut buf = [0u8; 1];
        loop {
            let n = stream.read(&mut buf)
                .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                    format!("failed to read CONNECT response: {}", e)
                )))?;
            if n == 0 {
                return Err(RetrieveError::Protocol(WgetError::Other(
                    "proxy connection closed".into()
                )));
            }
            response.push(buf[0] as char);
            if response.ends_with("\r\n\r\n") {
                break;
            }
        }

        // Check CONNECT response
        let status_line = response.lines().next().unwrap_or("");
        debug!("CONNECT response: {}", status_line);

        if !status_line.contains("200") {
            return Err(RetrieveError::Protocol(WgetError::Other(format!(
                "proxy CONNECT failed: {}",
                status_line
            ))));
        }

        // Convert std TcpStream to tokio TcpStream for async HTTP/2
        stream.set_nonblocking(true)
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("failed to set nonblocking: {}", e)
            )))?;

        let tokio_stream = tokio::net::TcpStream::from_std(stream)
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("failed to convert to tokio stream: {}", e)
            )))?;

        debug!("CONNECT tunnel established, performing TLS handshake");

        // Perform TLS handshake over the tunnel using tokio, reusing the app's
        // TLS settings (no-check-certificate, custom CAs, client certs, ...).
        let mut tls_config = build_h2_tls_config(config)?;
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("invalid server name: {}", e)
            )))?;

        let rt = h2_runtime();

        let tls_stream = rt
            .block_on(tls_connector.connect(server_name, tokio_stream))
            .map_err(|e| RetrieveError::Protocol(WgetError::Tls(
                ut_core::error::TlsError::HandshakeFailed(e.to_string())
            )))?;

        debug!("TLS handshake completed through proxy tunnel");

        // Perform HTTP/2 handshake over TLS using the shared runtime
        let (sender, conn) = rt.block_on(ut_http::h2::client::handshake(tls_stream))
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("HTTP/2 handshake failed: {}", e)
            )))?;

        // Spawn connection driver on the shared runtime so it stays alive
        // for the lifetime of the connection (not dropped with this function).
        rt.spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP/2 connection error: {}", e);
            }
        });

        let client = ut_http::h2::H2Client::from_sender(sender)
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("H2 client creation failed: {}", e))))?;

        Ok(H2Retriever {
            client: Some(client),
            host: host.to_string(),
            port,
            reusable: true,
        })
    }

    /// Send an HTTP/2 request and receive the response.
    ///
    /// The request headers built for HTTP/1.1 cannot be forwarded verbatim:
    /// HTTP/2 forbids uppercase header names and connection-specific headers
    /// (`Connection`, `Transfer-Encoding`, `Keep-Alive`, `Proxy-Connection`,
    /// `Upgrade`, `TE` other than `trailers`), and the `Host` header is
    /// replaced by the `:authority` pseudo-header derived from the URI. This
    /// method performs that conversion, sends the request, and maps the real
    /// response (status, headers, body) back into an `HttpResponse` so the
    /// retriever can handle redirects, auth, decompression, etc. uniformly.
    ///
    /// On error, the connection is marked non-reusable so it will not be
    /// returned to the pool on drop.
    ///
    /// # Arguments
    ///
    /// * `request` - The HTTP request to send.
    ///
    /// # Returns
    ///
    /// The full HTTP response (status, headers, body).
    pub fn send_request(&mut self, request: &HttpRequest) -> Result<HttpResponse, RetrieveError> {
        let client = self.client.as_mut().ok_or_else(|| {
            RetrieveError::Protocol(WgetError::Other("HTTP/2 client not available".into()))
        })?;

        // Convert ut_http request to http crate request
        let method = match request.method {
            ut_http::request::HttpMethod::Get => http::Method::GET,
            ut_http::request::HttpMethod::Post => http::Method::POST,
            ut_http::request::HttpMethod::Head => http::Method::HEAD,
            ut_http::request::HttpMethod::Put => http::Method::PUT,
            ut_http::request::HttpMethod::Delete => http::Method::DELETE,
            _ => http::Method::GET,
        };

        let uri: http::Uri = format!("https://{}:{}{}", self.host, self.port, request.path)
            .parse()
            .map_err(|e| {
                self.reusable = false;
                RetrieveError::Protocol(WgetError::Other(format!("invalid URI: {}", e)))
            })?;

        let builder = http::Request::builder()
            .method(method)
            .uri(uri);

        // Add headers, converting to HTTP/2-compatible form.
        let mut builder = builder;
        for (key, value) in &request.headers {
            let lower = key.to_lowercase();
            if is_h2_forbidden_header(&lower) {
                continue;
            }
            // Header names must be lowercase in HTTP/2; pass the lowercased name.
            builder = builder.header(lower.as_str(), value.as_str());
        }

        let http_request = builder
            .body(())
            .map_err(|e| {
                self.reusable = false;
                RetrieveError::Protocol(WgetError::Other(format!("failed to build request: {}", e)))
            })?;

        // Send request via HTTP/2
        let (response, _send_stream) = client.send_request(http_request)
            .map_err(|e| {
                self.reusable = false;
                RetrieveError::Protocol(WgetError::Other(format!("HTTP/2 request failed: {}", e)))
            })?;

        // Map the real response status and headers.
        let status = response.status().as_u16();
        let reason = response.status().canonical_reason().unwrap_or("").to_string();

        let mut headers = HeaderMap::new();
        for (name, value) in response.headers().iter() {
            if let Ok(vs) = value.to_str() {
                headers.insert(name.as_str().to_string(), vs.to_string());
            }
        }

        // Read response body
        let body = client.read_body(&mut response.into_body())
            .map_err(|e| {
                self.reusable = false;
                RetrieveError::Protocol(WgetError::Other(format!("HTTP/2 body read failed: {}", e)))
            })?;

        let mut resp = HttpResponse::new("2.0".to_string(), status, reason);
        resp.headers = headers;
        resp.body = Some(body.to_vec());
        Ok(resp)
    }

    /// Get the target host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the target port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for H2Retriever {
    /// Return the connection to the pool for reuse if it is still usable.
    fn drop(&mut self) {
        if !self.reusable {
            debug!("dropping non-reusable HTTP/2 connection to {}:{}", self.host, self.port);
            return;
        }
        if let Some(client) = self.client.take() {
            debug!("returning HTTP/2 connection to pool for {}:{}", self.host, self.port);
            h2_pool().put(self.host.clone(), self.port, client);
        }
    }
}

/// Proxy configuration for HTTP/2.
struct ProxyConfig {
    host: String,
    port: u16,
}

/// Get proxy configuration from the main config.
fn get_proxy_config(config: &Config) -> Result<ProxyConfig, RetrieveError> {
    let proxy_url = config.proxy.https_proxy.as_ref()
        .or(config.proxy.http_proxy.as_ref())
        .ok_or_else(|| RetrieveError::Protocol(WgetError::Other(
            "HTTP/2 requires a proxy but no proxy is configured".into()
        )))?;

    // Parse proxy URL (format: host:port or http://host:port)
    let proxy_str = proxy_url.trim_start_matches("http://").trim_start_matches("https://");
    let parts: Vec<&str> = proxy_str.split(':').collect();
    let host = parts[0].to_string();
    let port = if parts.len() > 1 {
        parts[1].parse().unwrap_or(8080)
    } else {
        8080
    };

    Ok(ProxyConfig { host, port })
}

/// Build a rustls `ClientConfig` for HTTP/2 from the application's TLS settings.
///
/// Reuses `RustlsConnector::build_config` so that `--no-check-certificate`,
/// `--ca-certificate`/`--ca-directory`, `--certificate`/`--private-key` and
/// `--secure-protocol` are all honored (the previous implementation hardcoded
/// the webpki root store and always verified, making self-signed / private-CA
/// HTTP/2 servers unreachable). The caller is expected to set ALPN `h2`.
fn build_h2_tls_config(config: &Config) -> Result<rustls::ClientConfig, RetrieveError> {
    let tls_config = ut_net::tls::TlsConfig::from_core(&config.tls);
    ut_net::RustlsConnector::build_config(&tls_config).map_err(|e| {
        RetrieveError::Protocol(WgetError::Tls(ut_core::error::TlsError::HandshakeFailed(
            e.to_string(),
        )))
    })
}

/// Whether a (lowercased) header name must be dropped when forwarding a
/// request over HTTP/2.
///
/// HTTP/2 forbids connection-specific headers and derives `:authority` from
/// the URI, so `host` is also dropped.
pub fn is_h2_forbidden_header(lower_name: &str) -> bool {
    match lower_name {
        "connection" | "transfer-encoding" | "keep-alive" | "proxy-connection"
        | "upgrade" | "host" => true,
        // "te" is allowed only as "trailers"; anything else is forbidden.
        "te" => true,
        _ => false,
    }
}

/// Check if HTTP/2 should be used for a given URL.
///
/// Returns true if:
/// - HTTP/2 is enabled in config
/// - The URL is HTTPS (HTTP/2 requires TLS)
pub fn should_use_http2(url: &ParsedUrl, config: &Config) -> bool {
    if !config.http.force_http2 {
        return false;
    }

    // HTTP/2 requires HTTPS
    if !url.scheme.is_secure() {
        debug!("HTTP/2 requires HTTPS, falling back to HTTP/1.1");
        return false;
    }

    true
}

/// Attempt to download a URL using HTTP/2.
///
/// This function tries to establish an HTTP/2 connection and download the URL.
/// If HTTP/2 fails, it returns an error so the caller can fall back to HTTP/1.1.
///
/// # Arguments
///
/// * `url` - The target URL.
/// * `config` - Application configuration.
///
/// # Returns
///
/// The HTTP response (status, headers, body), or an error.
pub async fn download_with_http2(
    url: &ParsedUrl,
    config: &Config,
) -> Result<HttpResponse, RetrieveError> {
    if !should_use_http2(url, config) {
        return Err(RetrieveError::Protocol(WgetError::Other(
            "HTTP/2 not applicable for this URL".into()
        )));
    }

    let mut retriever = H2Retriever::connect(url, config)?;

    // Build a simple GET request
    let request = HttpRequest::new(
        ut_http::request::HttpMethod::Get,
        url.full_path(),
        url.host.clone(),
    );

    retriever.send_request(&request)
}

