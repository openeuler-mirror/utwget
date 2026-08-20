//! HTTP/2 integration with the retriever.
//!
//! This module provides integration between the HTTP/2 client and the retriever,
//! allowing transparent use of HTTP/2 when available, including over proxies.

use std::io::{Read, Write};
use std::sync::Arc;
use log::debug;

use crate::types::RetrieveError;
use ut_core::{Config, WgetError};
use ut_core::url::ParsedUrl;

/// HTTP/2 client wrapper that integrates with the retriever.
pub struct H2Retriever {
    /// HTTP/2 client for making requests.
    client: ut_http::h2::H2Client,
    /// Target host.
    host: String,
    /// Target port.
    port: u16,
}

impl H2Retriever {
    /// Create a new HTTP/2 retriever connection.
    ///
    /// If a proxy is configured, establishes a CONNECT tunnel through the proxy first.
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

        let use_proxy = config.proxy.use_proxy && is_url_proxied_for_http2(url, config);

        if use_proxy {
            debug!("attempting HTTP/2 connection via proxy to {}:{}", host, port);
            Self::connect_via_proxy(&host, port, config)
        } else {
            debug!("attempting HTTP/2 connection to {}:{}", host, port);
            Self::connect_direct(&host, port)
        }
    }

    /// Create a direct HTTP/2 connection (no proxy).
    fn connect_direct(host: &str, port: u16) -> Result<Self, RetrieveError> {
        let client = ut_http::h2::H2Client::connect(host, port)
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("HTTP/2 connection failed: {}", e)
            )))?;

        Ok(H2Retriever {
            client,
            host: host.to_string(),
            port,
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

        // Perform TLS handshake over the tunnel using tokio
        let tls_config = build_rustls_config()?;
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("invalid server name: {}", e)
            )))?;

        let tls_stream = tokio::runtime::Runtime::new()
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("failed to create tokio runtime: {}", e)
            )))?
            .block_on(tls_connector.connect(server_name, tokio_stream))
            .map_err(|e| RetrieveError::Protocol(WgetError::Tls(
                ut_core::error::TlsError::HandshakeFailed(e.to_string())
            )))?;

        debug!("TLS handshake completed through proxy tunnel");

        // Perform HTTP/2 handshake over TLS
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("failed to create tokio runtime: {}", e)
            )))?;

        let (sender, conn) = rt.block_on(ut_http::h2::client::handshake(tls_stream))
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(
                format!("HTTP/2 handshake failed: {}", e)
            )))?;

        // Spawn connection driver
        rt.spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP/2 connection error: {}", e);
            }
        });

        let client = ut_http::h2::H2Client::from_sender(sender);

        Ok(H2Retriever {
            client,
            host: host.to_string(),
            port,
        })
    }

    /// Send an HTTP/2 request and receive the response.
    ///
    /// # Arguments
    ///
    /// * `request` - The HTTP request to send.
    ///
    /// # Returns
    ///
    /// The HTTP response body as bytes.
    pub fn send_request(&mut self, request: &ut_http::request::HttpRequest) -> Result<Vec<u8>, RetrieveError> {
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
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("invalid URI: {}", e))))?;

        let builder = http::Request::builder()
            .method(method)
            .uri(uri);

        // Add headers
        let mut builder = builder;
        for (key, value) in &request.headers {
            builder = builder.header(key.as_str(), value.as_str());
        }

        let http_request = builder
            .body(())
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("failed to build request: {}", e))))?;

        // Send request via HTTP/2
        let (response, _send_stream) = self.client.send_request(http_request)
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("HTTP/2 request failed: {}", e))))?;

        // Read response body
        let body = self.client.read_body(&mut response.into_body())
            .map_err(|e| RetrieveError::Protocol(WgetError::Other(format!("HTTP/2 body read failed: {}", e))))?;

        Ok(body.to_vec())
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
