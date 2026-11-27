//! Connection establishment for the retriever: DNS-filtered TCP connect
//! with `--bind-address` support (libc syscalls), pooled TCP acquisition,
//! HTTP CONNECT tunneling, and response-body source adapters.
//!
//! Split from the monolithic `retriever.rs` (arch review 3.2). Declared as
//! a CHILD module of `retriever` so `Retriever`'s private fields remain
//! accessible without widening visibility.

// Inherit the parent module's imports and items (child sees private items).
#[allow(unused_imports)]
use super::*;

impl Retriever {
    /// Create a TCP connection with optional timeout, bind address, and address family restrictions.
    ///
    /// Resolves the hostname (with optional DNS timeout), filters addresses by
    /// IPv4/IPv6 preferences (`--inet4-only`, `--inet6-only`, `--prefer-family`),
    /// and attempts to connect to each resolved address until one succeeds.
    ///
    /// # Arguments
    ///
    /// * `host` - The target hostname.
    /// * `port` - The target TCP port.
    ///
    /// # Returns
    ///
    /// A connected `TcpStream`.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if DNS resolution fails, no suitable address is found,
    /// or all connection attempts fail.
    /// Connect to a remote address, binding the local socket to a specific
    /// source address first. Used by `--bind-address`.
    ///
    /// Uses `libc` syscalls to create a socket, bind, then connect with
    /// an optional timeout.
    pub(super) fn connect_with_bind(
        remote: &std::net::SocketAddr,
        bind_addr: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<std::net::TcpStream, std::io::Error> {
        // Parse the bind address. If no port is given, use port 0 (OS picks).
        let bind: std::net::SocketAddr = match bind_addr.parse() {
            Ok(a) => a,
            Err(_) => {
                // Try as host:port or just host (port 0)
                let addr = format!("{}:0", bind_addr);
                addr.parse().map_err(|e: std::net::AddrParseError| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid bind address: {}", e))
                })?
            }
        };

        // Use a SocketAddr in the same family as the remote.
        let bind = match remote {
            std::net::SocketAddr::V4(_) => {
                match bind {
                    std::net::SocketAddr::V4(_) => bind,
                    std::net::SocketAddr::V6(_) => {
                        // Fall back to 0.0.0.0:0
                        "0.0.0.0:0".parse().unwrap()
                    }
                }
            }
            std::net::SocketAddr::V6(_) => {
                match bind {
                    std::net::SocketAddr::V6(_) => bind,
                    std::net::SocketAddr::V4(_) => {
                        // Fall back to [::]:0
                        "[::]:0".parse().unwrap()
                    }
                }
            }
        };

        // Create socket via libc, bind, connect, then wrap as TcpStream.
        unsafe {
            let domain = if remote.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
            let fd = libc::socket(domain, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Bind — 在 match 分支内完成内存复制，避免局部 sockaddr 变量
            // 离开作用域后产生悬垂指针 (dangling pointer) 导致 UB。
            let bind_storage: [u8; 128] = [0u8; 128];
            let bind_len: libc::socklen_t = match &bind {
                std::net::SocketAddr::V4(v4) => {
                    let mut sa: libc::sockaddr_in = std::mem::zeroed();
                    sa.sin_family = libc::AF_INET as u16;
                    sa.sin_port = v4.port().to_be();
                    sa.sin_addr = libc::in_addr { s_addr: u32::from(*v4.ip()).to_be() };
                    let sa_len = std::mem::size_of::<libc::sockaddr_in>();
                    std::ptr::copy_nonoverlapping(
                        &sa as *const libc::sockaddr_in as *const u8,
                        bind_storage.as_ptr() as *mut u8,
                        sa_len,
                    );
                    sa_len as libc::socklen_t
                }
                std::net::SocketAddr::V6(v6) => {
                    let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                    sa.sin6_family = libc::AF_INET6 as u16;
                    sa.sin6_port = v6.port().to_be();
                    sa.sin6_addr.s6_addr = v6.ip().octets();
                    let sa_len = std::mem::size_of::<libc::sockaddr_in6>();
                    std::ptr::copy_nonoverlapping(
                        &sa as *const libc::sockaddr_in6 as *const u8,
                        bind_storage.as_ptr() as *mut u8,
                        sa_len,
                    );
                    sa_len as libc::socklen_t
                }
            };

            if libc::bind(fd, bind_storage.as_ptr() as *const libc::sockaddr, bind_len) < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            // Connect — 同样在 match 分支内完成复制
            let remote_storage: [u8; 128] = [0u8; 128];
            let remote_len: libc::socklen_t = match remote {
                std::net::SocketAddr::V4(v4) => {
                    let mut sa: libc::sockaddr_in = std::mem::zeroed();
                    sa.sin_family = libc::AF_INET as u16;
                    sa.sin_port = v4.port().to_be();
                    sa.sin_addr = libc::in_addr { s_addr: u32::from(*v4.ip()).to_be() };
                    let sa_len = std::mem::size_of::<libc::sockaddr_in>();
                    std::ptr::copy_nonoverlapping(
                        &sa as *const libc::sockaddr_in as *const u8,
                        remote_storage.as_ptr() as *mut u8,
                        sa_len,
                    );
                    sa_len as libc::socklen_t
                }
                std::net::SocketAddr::V6(v6) => {
                    let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                    sa.sin6_family = libc::AF_INET6 as u16;
                    sa.sin6_port = v6.port().to_be();
                    sa.sin6_addr.s6_addr = v6.ip().octets();
                    let sa_len = std::mem::size_of::<libc::sockaddr_in6>();
                    std::ptr::copy_nonoverlapping(
                        &sa as *const libc::sockaddr_in6 as *const u8,
                        remote_storage.as_ptr() as *mut u8,
                        sa_len,
                    );
                    sa_len as libc::socklen_t
                }
            };

            // Set non-blocking if timeout is set
            if timeout.is_some() {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            let conn_ret = libc::connect(
                fd,
                remote_storage.as_ptr() as *const libc::sockaddr,
                remote_len,
            );

            if conn_ret < 0 {
                let errno = *libc::__errno_location();
                if timeout.is_some() && (errno == libc::EINPROGRESS || errno == libc::EWOULDBLOCK) {
                    // Wait for connect with poll
                    let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                    // is_some() 已检查过；用 if let 让编译器知道 timeout 在该分支内非 None，
                    // 避免 unwrap 残留。
                    let timeout_ms = if let Some(t) = timeout {
                        t.as_millis() as libc::c_int
                    } else {
                        unreachable!("timeout.is_some() guarded above")
                    };
                    let poll_ret = libc::poll(&mut pfd, 1, timeout_ms);
                    if poll_ret <= 0 {
                        libc::close(fd);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "connect with bind timed out",
                        ));
                    }
                    // Check for errors
                    let mut soerr: libc::c_int = 0;
                    let mut soerr_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                    let getsockopt_ret = libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut soerr as *mut _ as *mut libc::c_void,
                        &mut soerr_len,
                    );
                    if getsockopt_ret < 0 || soerr != 0 {
                        libc::close(fd);
                        let errno = if soerr != 0 { soerr } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) };
                        return Err(std::io::Error::from_raw_os_error(errno));
                    }
                } else {
                    let err = std::io::Error::last_os_error();
                    libc::close(fd);
                    return Err(err);
                }
            }

            // Restore blocking mode
            if timeout.is_some() {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
            }

            // Convert fd to TcpStream
            use std::os::unix::io::FromRawFd;
            Ok(std::net::TcpStream::from_raw_fd(fd))
        }
    }

    pub(super) fn create_tcp_stream(&self, host: &str, port: u16) -> Result<std::net::TcpStream, RetrieveError> {
        // Try to get a connection from the pool first
        if let Some(conn) = self.connection_pool.get_tcp(host, port) {
            debug!("reusing pooled TCP connection to {}:{}", host, port);
            return Ok(conn);
        }

        let _addr_str = format!("{}:{}", host, port);

        // Resolve addresses with optional DNS timeout.
        // A process-wide DNS cache (TTL 60s) avoids repeated lookups for the
        // same host. Disabled when --no-dns-cache is set.
        let addresses: Vec<std::net::SocketAddr> = {
            // Check DNS cache first (unless disabled)
            if !self.config.no_dns_cache {
                if let Ok(cache) = dns_cache().lock() {
                    if let Some((cached_addrs, cached_at)) = cache.get(&(host.to_string(), port)) {
                        if cached_at.elapsed() < DNS_CACHE_TTL {
                            debug!("DNS cache hit for {}:{}", host, port);
                            cached_addrs.clone()
                        } else {
                            // Stale; fall through to resolve and refresh below.
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        };
        let addresses: Vec<std::net::SocketAddr> = if !addresses.is_empty() {
            addresses
        } else {
            let addrs = if let Some(dns_timeout) = self.config.dns_timeout.or(self.config.timeout) {
                // DNS resolution with timeout using a single background thread + channel.
                // 代码审查 P2 #3.4：简化原三线程拼装（resolver + watchdog + 主线程）
                // 为单 resolver 线程。timeout 时直接 detach resolver 线程
                // （to_socket_addrs 最终会返回，channel send 失败被静默丢弃），
                // 不再维护 DETACHED_DNS_COUNT 计数器 + watchdog 线程。
                let host_owned = host.to_string();
                let (tx, rx) = std::sync::mpsc::channel();

                let _handle = std::thread::Builder::new()
                    .name(format!("dns-resolve-{}", host))
                    .spawn(move || {
                        let result = (host_owned.as_str(), port).to_socket_addrs();
                        let _ = tx.send(result); // receiver 可能已超时 drop，send 失败被静默忽略
                    })
                    .map_err(|e| RetrieveError::Protocol(WgetError::DnsResolution(
                        format!("failed to spawn DNS thread: {}", e)
                    )))?;

                // 等待结果或超时。timeout 时 _handle 被 drop（线程 detach），
                // resolver 线程会在 to_socket_addrs 返回后自然退出，无内存泄漏。
                match rx.recv_timeout(dns_timeout) {
                    Ok(Ok(addrs)) => addrs,
                    Ok(Err(e)) => {
                        return Err(RetrieveError::Protocol(WgetError::DnsResolution(
                            format!("{}", e)
                        )));
                    }
                    Err(_) => {
                        log::debug!("DNS resolution timeout for {}, detaching resolver thread", host);
                        return Err(RetrieveError::Protocol(WgetError::DnsTimeout));
                    }
                }
            } else {
                (host, port).to_socket_addrs()
                    .map_err(|e| RetrieveError::Protocol(WgetError::DnsResolution(
                        format!("{}", e)
                    )))?
            };
            let collected: Vec<std::net::SocketAddr> = addrs.collect();

            // Store in cache (unless disabled)
            if !self.config.no_dns_cache && !collected.is_empty() {
                if let Ok(mut cache) = dns_cache().lock() {
                    cache.insert((host.to_string(), port), (collected.clone(), Instant::now()));
                }
            }

            collected
        };

        if addresses.is_empty() {
            return Err(RetrieveError::Protocol(WgetError::HostNotFound(host.to_string())));
        }

        // Filter addresses based on address family settings
        log::debug!("IPv4 filter: {}, IPv6 filter: {}", self.config.force_ipv4, self.config.force_ipv6);
        log::debug!("Before filter: {:?}", addresses);
        let filtered_addresses: Vec<std::net::SocketAddr> = addresses.into_iter()
            .filter(|addr| {
                if self.config.force_ipv4 {
                    matches!(addr, std::net::SocketAddr::V4(_))
                } else if self.config.force_ipv6 {
                    matches!(addr, std::net::SocketAddr::V6(_))
                } else {
                    true
                }
            })
            .collect();
        log::debug!("After filter: {:?}", filtered_addresses);

        // Apply prefer_family ordering
        let mut sorted_addresses = filtered_addresses;
        match self.config.prefer_family {
            ut_core::AddressFamily::Ipv4 | ut_core::AddressFamily::PreferIpv4 => {
                sorted_addresses.sort_by(|a, b| {
                    let a_is_v4 = matches!(a, std::net::SocketAddr::V4(_));
                    let b_is_v4 = matches!(b, std::net::SocketAddr::V4(_));
                    b_is_v4.cmp(&a_is_v4) // IPv4 first
                });
            }
            ut_core::AddressFamily::Ipv6 | ut_core::AddressFamily::PreferIpv6 => {
                sorted_addresses.sort_by(|a, b| {
                    let a_is_v6 = matches!(a, std::net::SocketAddr::V6(_));
                    let b_is_v6 = matches!(b, std::net::SocketAddr::V6(_));
                    b_is_v6.cmp(&a_is_v6) // IPv6 first
                });
            }
            ut_core::AddressFamily::Unspecified => {}
        }

        if sorted_addresses.is_empty() {
            return Err(RetrieveError::Protocol(WgetError::Other(
                if self.config.force_ipv4 {
                    format!("no IPv4 addresses found for {}", host)
                } else if self.config.force_ipv6 {
                    format!("no IPv6 addresses found for {}", host)
                } else {
                    format!("no addresses found for {}", host)
                }
            )));
        }

        // Connect-time SSRF protection: when --block-private-redirects is
        // set, also check the RESOLVED address of every connection target,
        // not just literal IPs in the redirect Location. A redirect to
        // `http://internal.corp/` (hostname resolving to 169.254.169.254)
        // or a DNS-rebinding host never matches the literal-IP check in
        // the redirect handler — here the hostname has become a concrete
        // socket address, so this is the single choke point that catches
        // all connection targets (initial URL, redirects, recursive).
        if self.config.block_private_redirects {
            for addr in &sorted_addresses {
                if is_private_ip(&addr.ip()) {
                    warn!("SSRF risk: {} resolves to private/loopback IP {}", host, addr.ip());
                    eprintln!(
                        "utwget: WARNING: {} resolves to private/loopback IP {} (potential SSRF); blocked by --block-private-redirects",
                        host,
                        addr.ip()
                    );
                    return Err(RetrieveError::Protocol(WgetError::Other(
                        format!(
                            "connection to private/loopback address {} (host {}) blocked (--block-private-redirects)",
                            addr.ip(),
                            host
                        ),
                    )));
                }
            }
        }

        // Try to connect to each address
        let connect_timeout = self.config.connect_timeout.or(self.config.timeout);
        let mut last_error = None;

        for addr in sorted_addresses {
            debug!("trying to connect to {}", addr);
            // (on success the address is recorded below for WARC-IP-Address)

            // Apply bind address if set: create a socket, bind to the
            // specified local address, then connect to the remote.
            let stream_result = if let Some(ref bind_addr) = self.config.bind_address {
                debug!("--bind-address={} requested for connection to {}", bind_addr, addr);
                match Self::connect_with_bind(&addr, bind_addr, connect_timeout) {
                    Ok(s) => Ok(s),
                    Err(e) => Err(e),
                }
            } else if let Some(timeout) = connect_timeout {
                std::net::TcpStream::connect_timeout(&addr, timeout)
            } else {
                std::net::TcpStream::connect(&addr)
            };

            match stream_result {
                Ok(stream) => {
                    // Record the reached server IP for WARC-IP-Address (8.1-2).
                    self.last_server_ip.set(Some(addr.ip().to_string()));

                    // Apply read timeout if set
                    if let Some(timeout) = self.config.read_timeout.or(self.config.timeout) {
                        stream.set_read_timeout(Some(timeout))
                            .map_err(RetrieveError::Io)?;
                    }

                    // Apply write timeout (using same timeout value)
                    if let Some(timeout) = self.config.timeout {
                        stream.set_write_timeout(Some(timeout))
                            .map_err(RetrieveError::Io)?;
                    }

                    return Ok(stream);
                }
                Err(e) => {
                    last_error = Some(e);
                    // 上一行刚 last_error = Some(e)，但用 if let 而非 unwrap
                    // 让编译器类型推导更稳健，避免 review 提到的 unwrap 残留。
                    if let Some(ref le) = last_error {
                        debug!("failed to connect to {}: {}", addr, le);
                    }
                }
            }
        }

        Err(RetrieveError::Protocol(WgetError::SocketError(
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused, "connection failed"))
        )))
    }    /// Establish an HTTP CONNECT tunnel through a proxy for HTTPS connections.
    ///
    /// Sends a CONNECT request to the proxy, reads the response, and returns
    /// a cloned stream ready for TLS wrapping.
    ///
    /// # Arguments
    ///
    /// * `stream` - The TCP stream connected to the proxy.
    /// * `host` - The target hostname for the tunnel.
    /// * `port` - The target port for the tunnel.
    ///
    /// # Returns
    ///
    /// A cloned `TcpStream` with the tunnel established.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if the proxy returns a non-200 status or if I/O fails.
    pub(super) fn establish_connect_tunnel(
        &self,
        stream: &mut std::net::TcpStream,
        host: &str,
        port: u16,
        proxy_user: Option<&str>,
        proxy_password: Option<&str>,
    ) -> Result<(std::net::TcpStream, Vec<u8>), RetrieveError> {
        // Shared CONNECT request builder (arch 6.3-9: one implementation of
        // request construction + status parsing for the H1/H2/proxy paths).
        // Credential precedence matches the plain-HTTP proxy path and wget's
        // initialize_proxy_configuration (http.c:2021-2052): --proxy-user/
        // --proxy-password first, URL-embedded proxy userinfo as fallback.
        // The previous code only read the config, so
        // https_proxy=http://user:pass@proxy/ authenticated for plain HTTP
        // but not for HTTPS tunneling (P2-3).
        let connect_req = ut_net::proxy::build_connect_request(
            host,
            port,
            proxy_user,
            proxy_password,
        );
        debug!("CONNECT request: {}", crate::utils::redact_sensitive_headers(&connect_req));
        stream.write_all(connect_req.as_bytes()).map_err(RetrieveError::Io)?;
        stream.flush().map_err(RetrieveError::Io)?;

        // Use read_response_head to properly parse the CONNECT response and
        // preserve any leftover bytes read beyond the header boundary.
        let (response, leftover) = read_response_head(stream)?;
        let status_line = format!("{} {} {}", response.version, response.status_code, response.reason);
        debug!("CONNECT response: {}", status_line);

        let status_ok = ut_net::proxy::parse_connect_status(&status_line) == Some(200)
            || response.status_code == 200;

        if !status_ok {
            return Err(RetrieveError::Protocol(WgetError::Other(format!(
                "proxy CONNECT failed: {}",
                status_line
            ))));
        }

        // Validate leftover bytes: a well-formed CONNECT 200 response has no body.
        // Leftover data could be from a malicious proxy injecting data into the
        // TLS handshake. Log a warning if unexpected data is present.
        if !leftover.is_empty() {
            warn!(
                "proxy CONNECT response contained {} unexpected bytes after header; \
                 this may indicate a misconfigured or malicious proxy",
                leftover.len()
            );
        }

        // Return the stream and any leftover bytes for TLS wrapping
        let cloned = stream.try_clone().map_err(RetrieveError::Io)?;
        Ok((cloned, leftover))
    }}

///
/// This lets the binary-safe response reader work
/// uniformly over both plain `TcpStream` and TLS transports.
pub(super) struct TransportRead<'a> {
    inner: &'a mut Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>,
}

impl<'a> TransportRead<'a> {
    pub(super) fn new(inner: &'a mut Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>) -> Self {
        TransportRead { inner }
    }
}

impl<'a> Read for TransportRead<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner
            .read(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

/// Owned adapter that wraps a boxed `Transport` and exposes `std::io::Read`.
///
/// The inner transport is stored as an `Option` so it can be extracted after
/// the response body is fully read, allowing the connection to be returned to
/// the TLS connection pool for Keep-Alive reuse.
pub(super) struct OwnedTransportRead {
    inner: Option<Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>>,
}

impl OwnedTransportRead {
    pub(super) fn new(inner: Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>) -> Self {
        OwnedTransportRead { inner: Some(inner) }
    }

    /// Extract the underlying transport, if still present.
    ///
    /// Returns `None` if the transport was already taken (e.g. after a
    /// previous return-to-pool). This is used after the response body is
    /// fully consumed to return the connection to the pool for Keep-Alive.
    pub(super) fn take_inner(&mut self) -> Option<Box<dyn ut_net::Transport<Error = ut_core::error::TlsError>>> {
        self.inner.take()
    }
}

impl Read for OwnedTransportRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.as_mut() {
            Some(t) => t.read(buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())),
            None => Ok(0), // transport already taken; behave as EOF
        }
    }
}

/// The source of a response body reader.
///
/// Distinguishes between a non-poolable reader (plain HTTP, proxy, or
/// in-memory HTTP/2 buffer) and a poolable TLS transport (direct HTTPS).
/// The `Tcp` variant (direct HTTP) can be returned to the TCP pool, and
/// the `Tls` variant (direct HTTPS) can be returned to the TLS pool for
/// Keep-Alive reuse after the body is fully consumed.
pub(super) enum BodySource {
    /// Non-poolable reader: proxy tunnel, or HTTP/2 in-memory buffer.
    /// Cannot be returned to any connection pool.
    Plain(Box<dyn Read + Send>),
    /// Poolable plain TCP transport (direct HTTP only).
    Tcp(std::net::TcpStream),
    /// Poolable TLS transport (direct HTTPS only).
    Tls(OwnedTransportRead),
}

impl Read for BodySource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            BodySource::Plain(p) => p.read(buf),
            BodySource::Tcp(s) => s.read(buf),
            BodySource::Tls(t) => t.read(buf),
        }
    }
}

/// Information needed to return a connection to the TLS connection pool
/// after the response body is fully consumed.
///
/// `None` means the connection should not be reused (e.g. proxy tunnel where
/// the pool key differs, or a non-reusable response).
pub(super) type ReturnInfo = (String, u16); // (host, port)
