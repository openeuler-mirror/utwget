//! FTP/FTPS download implementation for [`Retriever`].
//!
//! Extracted from the monolithic `retriever.rs` (arch 6.3-12): the FTP
//! paths (plain FTP + FTPS, glob expansion) are self-contained protocol
//! logic using only the Retriever's config/progress/registry surface.
//! Provided as an inherent `impl Retriever` block so call sites are
//! unchanged; `retriever.rs` keeps the HTTP engine.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;
use std::time::Instant;

use log::{debug, info, warn};
use ut_core::types::Scheme;
use ut_core::url::ParsedUrl;
use ut_core::WgetError;

use crate::protocol::apply_rate_limit;
use crate::retriever::{filter_glob_entries, Retriever};
use crate::types::{BodyResult, ProtocolState, RequestOptions, RetrieveError, RetrieveOutcome};
use crate::utils::apply_file_timestamp;

impl Retriever {
    /// Download an FTP directory: write the listing to `.listing`, then
    /// retrieve every entry — files directly, subdirectories recursively
    /// (GNU wget ftp_get_listing + ftp_retrieve_list/ftp_retrieve_dirs).
    ///
    /// Cycle protection: each directory URL is registered as visited (via
    /// the .listing path) before its entries are processed, so symlink
    /// loops terminate. Absolute depth is additionally capped at 128.
    ///
    /// The `.listing` file is removed after processing unless
    /// `--no-remove-listing` is set.
    fn download_ftp_listing(
        &mut self,
        url: &ParsedUrl,
        entries: &[ut_ftp::FtpEntry],
        local_dir: &Path,
    ) -> Result<u64, RetrieveError> {
        let listing_path = local_dir.join(".listing");
        {
            let mut text = String::new();
            for e in entries {
                text.push_str(&format!("{}\n", e.name));
            }
            fs::write(&listing_path, text).map_err(RetrieveError::Io)?;
        }
        // Mark this directory visited BEFORE descending — breaks cycles.
        self.registry().register_download(&url.display(), &listing_path);

        let mut total = 0u64;
        let mut worst: Option<RetrieveError> = None;
        let depth = self.ftp_dir_depth.get();
        for e in entries {
            if e.name == "." || e.name == ".." {
                continue;
            }
            let child_path = if url.path.ends_with('/') {
                format!("{}{}", url.path, e.name)
            } else {
                format!("{}/{}", url.path.trim_end_matches('/'), e.name)
            };
            // Percent-encode the entry name so URL parsing survives spaces
            // and other raw bytes (M15). Directories get a trailing slash
            // so the child retrieval takes the listing path.
            let encoded = ut_core::url::encode_request_target(&child_path);
            let child_url = format!("{}://{}:{}{}{}",
                url.scheme.as_str(), url.host, url.port, encoded,
                if e.is_dir { "/" } else { "" });
            let outcome: Result<u64, RetrieveError> = if e.is_symlink {
                // Symlinks can point anywhere (even outside the tree);
                // wget only follows them with --retr-symlinks.
                debug!("skipping FTP symlink {} (no --retr-symlinks)", e.name);
                Ok(0)
            } else if e.is_dir {
                if depth >= 128 {
                    warn!("FTP directory recursion deeper than 128 levels; stopping at {}", child_url);
                    Ok(0)
                } else {
                    self.retrieve_new_chain_with_retry(&child_url)
                        .map(|o| match o {
                            RetrieveOutcome::Success(b) => b.bytes_read,
                            _ => 0,
                        })
                }
            } else {
                self.retrieve_new_chain_with_retry(&child_url)
                    .map(|o| match o {
                        RetrieveOutcome::Success(b) => b.bytes_read,
                        _ => 0,
                    })
            };
            match outcome {
                Ok(bytes) => total += bytes,
                Err(err) => {
                    warn!("FTP entry '{}' failed: {}", e.name, err);
                    if worst.is_none() {
                        worst = Some(err);
                    }
                }
            }
        }

        // --no-remove-listing keeps the .listing file (wget default removes).
        if self.config.ftp.remove_listing {
            let _ = fs::remove_file(&listing_path);
        }
        match worst {
            Some(e) => Err(e),
            None => Ok(total),
        }
    }

    /// Perform an FTP or FTPS download.
    ///
    /// Handles both plain FTP and FTPS (explicit and implicit) connections,
    /// including login, binary transfer mode, directory navigation, file retrieval,
    /// and post-download processing such as timestamps, extended attributes,
    /// permissions, and cleanup.
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed FTP/FTPS URL.
    /// * `_opts` - Request options (currently unused for FTP).
    /// * `state` - Mutable protocol state.
    /// * `output_path` - Local filesystem path for the downloaded file.
    ///
    /// # Returns
    ///
    /// A `RetrieveOutcome` on success.
    ///
    /// # Errors
    ///
    /// Returns `RetrieveError` if connection, login, transfer, or post-processing fails.
    pub(crate) fn retrieve_ftp(
        &mut self,
        url: &ParsedUrl,
        _opts: &RequestOptions,
        state: &mut ProtocolState,
        output_path: &Path,
    ) -> Result<RetrieveOutcome, RetrieveError> {
        let start = Instant::now();

        let user = url.user.clone()
            .or(self.config.ftp.user.clone())
            .unwrap_or_else(|| "anonymous".to_string());
        let password = url.password.clone()
            .or(self.config.ftp.password.clone())
            .unwrap_or_else(|| "-wget@".to_string());

        // Determine if we should use FTPS
        let use_ftps = url.scheme == Scheme::Ftps || self.config.ftp.ftps_implicit;

        // Determine the port
        let port = if url.scheme == Scheme::Ftps && url.port == 21 {
            // Default FTPS port is 990 for implicit, 21 for explicit
            if self.config.ftp.ftps_implicit { 990 } else { 21 }
        } else {
            url.port
        };

        if use_ftps {
            // Use FTPS client. Propagate --secure-protocol and --no-check-certificate
            // from the TLS config so FTPS honors them like the HTTPS path.
            let verify = self.config.tls.check_certificate != ut_core::types::CheckCertMode::Off;
            if !verify {
                // 代码审查 P1 #2.4：FTPS 路径也打 warning（之前只 HTTPS 路径 build_config 有）
                warn!("FTPS certificate verification is DISABLED (--no-check-certificate). \
                       This makes the FTPS connection vulnerable to MITM attacks.");
            }
            let ftps_cfg = ut_ftp::FtpsConfig {
                verify_certificate: verify,
                ca_cert: self.config.tls.ca_cert.clone(),
                client_cert: self.config.tls.cert_file.clone(),
                client_key: self.config.tls.private_key.clone(),
                require_data_tls: !self.config.ftp.ftps_clear_data,
                secure_protocol: self.config.tls.secure_protocol,
                clear_data_connection: self.config.ftp.ftps_clear_data,
                resume_ssl: self.config.ftp.ftps_resume_ssl,
                active_mode: !self.config.ftp.passive,
                // M20: FTPS now honors the same TLS policy as HTTPS.
                crl_file: self.config.tls.crl_file.clone(),
                pinned_pubkey: self.config.tls.pinned_pubkey.clone(),
                ciphers: self.config.tls.ciphers.clone(),
            };
            let mut ftps_client = ut_ftp::FtpsClient::with_config(ftps_cfg)
                .with_timeout(self.config.read_timeout.or(self.config.timeout).unwrap_or(std::time::Duration::from_secs(60)));

            if self.config.ftp.ftps_implicit {
                // Implicit FTPS: connect with TLS from the start
                ftps_client.connect_implicit(&url.host, port)
                    .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTPS connect error: {}", e))))?;
            } else {
                // Explicit FTPS: connect plain, then upgrade with AUTH TLS
                ftps_client.connect_explicit(&url.host, port)
                    .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTPS connect error: {}", e))))?;
            }

            ftps_client.login(&user, &password)
                .map_err(|_| RetrieveError::Protocol(WgetError::FtpLoginRefused))?;
            ftps_client.type_binary()
                .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTP type error: {}", e))))?;

            // Percent-escapes must be decoded before FTP commands: wget uses
            // the decoded u->dir/u->file for CWD/RETR (url.c); ParsedUrl keeps
            // the encoded form for HTTP, so `my%20file.txt` must become
            // `my file.txt` or servers return 550. Decoded control characters
            // are still rejected by the FTP client's command-injection guard.
            let path_segments: Vec<String> = url.path.trim_start_matches('/')
                .split('/').filter(|s| !s.is_empty())
                .map(ut_core::url::decode_iri)
                .collect();
            if path_segments.len() > 1 {
                for dir in &path_segments[..path_segments.len() - 1] {
                    if let Err(e) = ftps_client.cwd(dir) {
                        // Directory navigation failure is fatal (GNU wget
                        // ftp.c:880-940 tries CWD then per-component CWD and
                        // bails on error): continuing would run RETR in the
                        // login directory and silently download a WRONG file
                        // that happens to share the name.
                        return Err(RetrieveError::Ftp(e));
                    }
                }
            }

            let filename = path_segments.last().map(|s| s.as_str()).unwrap_or("index.html");

            // Directory URL (trailing slash / empty file part): LIST it,
            // save `.listing`, and download all entries (GNU wget
            // ftp_retrieve_list) — not a bare RETR, which servers answer
            // with 550. CWD into the FINAL segment too: the earlier loop
            // only navigated to the parent.
            if url.file.is_empty() || url.path.ends_with('/') {
                if let Some(last) = path_segments.last() {
                    ftps_client.cwd(last).map_err(RetrieveError::Ftp)?;
                }
                let entries = ftps_client
                    .list(None)
                    .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTP LIST error: {}", e))))?;
                let _ = ftps_client.quit();
                let local_dir = output_path
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                fs::create_dir_all(&local_dir).map_err(RetrieveError::Io)?;
                self.ftp_dir_depth.set(self.ftp_dir_depth.get() + 1);
                let result = self.download_ftp_listing(url, &entries, &local_dir);
                self.ftp_dir_depth.set(self.ftp_dir_depth.get() - 1);
                let total = result?;
                return Ok(RetrieveOutcome::Success(BodyResult {
                    bytes_read: total,
                    elapsed: start.elapsed(),
                    local_file: None,
                    content_type: None,
                }));
            }

            let file_size = ftps_client.size(filename).ok().flatten();

            // Handle directory creation
            if let Some(parent) = output_path.parent() {
                if !parent.as_os_str().is_empty() {
                    if self.config.no_directories {
                        if !parent.exists() {
                            return Err(RetrieveError::Io(io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("directory {} does not exist (--no-directories)", parent.display())
                            )));
                        }
                    } else {
                        fs::create_dir_all(parent).map_err(RetrieveError::Io)?;
                    }
                }
            }

            // Remove existing file if --unlink is set
            if self.config.unlink && output_path.exists() {
                fs::remove_file(output_path).map_err(RetrieveError::Io)?;
            }

        let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(state.resume_position == 0)
                .append(state.resume_position > 0)
                .open(output_path)
                .map_err(RetrieveError::Io)?;

            self.progress.begin(&url.display(), file_size, Some(state.resume_position));
            self.progress.reset();

            let mut rate_writer = apply_rate_limit(file, self.config.limit_rate);
            // GNU wget sends REST only when resuming (restval > 0, ftp.c);
            // "REST 0" is a wasted round trip and some servers reject it (M13).
            let resume_arg = if state.resume_position > 0 { Some(state.resume_position) } else { None };
            let total_bytes = ftps_client.retr(filename, &mut rate_writer, resume_arg)
                .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTPS transfer error: {}", e))))?;

            // Apply server timestamp (MDTM) before closing the connection
            if let Some(mdtm) = ftps_client.mdtm(filename).ok().flatten() {
                apply_file_timestamp(output_path, mdtm);
            }

            ftps_client.quit()
                .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTPS quit error: {}", e))))?;

            let elapsed = start.elapsed();
            self.progress.finish(ut_progress::FinishStatus::Success {
                downloaded: total_bytes,
                elapsed,
            });

            self.total_downloaded += total_bytes;
            if self.total_downloaded > self.config.quota.unwrap_or(u64::MAX) {
                log::warn!("quota exceeded ({} bytes downloaded, quota {})",
                    self.total_downloaded, self.config.quota.unwrap_or(0));
            }

            self.registry().register_download(&url.display(), output_path);

            let result = BodyResult {
                bytes_read: total_bytes,
                elapsed,
                local_file: Some(output_path.to_path_buf()),
                content_type: None,
            };

            return Ok(RetrieveOutcome::Success(result));
        }

        // Regular FTP
        log::debug!("FTP passive mode: {}", self.config.ftp.passive);
        let ftp_timeout = self.config.read_timeout
            .or(self.config.timeout)
            .unwrap_or(std::time::Duration::from_secs(30));
        let mut ftp_client = ut_ftp::FtpClient::new()
            .with_passive(self.config.ftp.passive)
            .with_timeout(ftp_timeout);
        ftp_client.connect(&url.host, url.port)
            .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTP connect error: {}", e))))?;
        ftp_client.login(&user, &password)
            .map_err(RetrieveError::Ftp)?;
        ftp_client.type_binary()
            .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTP type error: {}", e))))?;

        // Percent-escapes decoded before FTP commands (see the FTPS branch
        // above; wget uses decoded u->dir/u->file for CWD/RETR).
        let path_segments: Vec<String> = url.path.trim_start_matches('/')
            .split('/').filter(|s| !s.is_empty())
            .map(ut_core::url::decode_iri)
            .collect();
        if path_segments.len() > 1 {
            for dir in &path_segments[..path_segments.len() - 1] {
                if let Err(e) = ftp_client.cwd(dir) {
                    // Directory navigation failure is fatal (GNU wget
                    // ftp.c:880-940): continuing would run RETR in the login
                    // directory and silently download a WRONG file that
                    // happens to share the name.
                    return Err(RetrieveError::Ftp(e));
                }
            }
        }

        let filename = path_segments.last().map(|s| s.as_str()).unwrap_or("index.html");

        // Directory URL: LIST + .listing + download entries (see the FTPS
        // branch above; GNU wget ftp_retrieve_list). CWD into the FINAL
        // segment too — the earlier loop only navigated to the parent.
        if url.file.is_empty() || url.path.ends_with('/') {
            if let Some(last) = path_segments.last() {
                ftp_client.cwd(last).map_err(RetrieveError::Ftp)?;
            }
            let entries = ftp_client
                .list(None)
                .map_err(|e| RetrieveError::Ftp(e))?;
            let _ = ftp_client.quit();
            let local_dir = output_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            fs::create_dir_all(&local_dir).map_err(RetrieveError::Io)?;
            self.ftp_dir_depth.set(self.ftp_dir_depth.get() + 1);
            let result = self.download_ftp_listing(url, &entries, &local_dir);
            self.ftp_dir_depth.set(self.ftp_dir_depth.get() - 1);
            let total = result?;
            return Ok(RetrieveOutcome::Success(BodyResult {
                bytes_read: total,
                elapsed: start.elapsed(),
                local_file: None,
                content_type: None,
            }));
        }

        let file_size = ftp_client.size(filename).ok().flatten();

        // Handle directory creation based on --no-directories / --force-directories
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                if self.config.no_directories {
                    if !parent.exists() {
                        return Err(RetrieveError::Io(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("directory {} does not exist (--no-directories)", parent.display())
                        )));
                    }
                } else {
                    fs::create_dir_all(parent).map_err(RetrieveError::Io)?;
                }
            }
        }

        // Remove existing file if --unlink is set
        if self.config.unlink && output_path.exists() {
            fs::remove_file(output_path).map_err(RetrieveError::Io)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(state.resume_position == 0)
            .append(state.resume_position > 0)
            .open(output_path)
            .map_err(RetrieveError::Io)?;

        self.progress.begin(&url.display(), file_size, Some(state.resume_position));
        self.progress.reset();

        let mut rate_writer = apply_rate_limit(file, self.config.limit_rate);
        let resume_arg = if state.resume_position > 0 { Some(state.resume_position) } else { None };
        // From<FtpError> preserves FileNotFound/CommandFailed/ServerError
        // variants (arch 6.3-10) instead of collapsing into FtpIo("...").
        let total_bytes = ftp_client.retr(filename, &mut rate_writer, resume_arg)
            .map_err(RetrieveError::Ftp)?;

        // Get server timestamp before closing connection
        let mdtm = ftp_client.mdtm(filename).ok().flatten();

        ftp_client.quit()
            .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTP quit error: {}", e))))?;

        let elapsed = start.elapsed();
        self.progress.finish(ut_progress::FinishStatus::Success {
            downloaded: total_bytes,
            elapsed,
        });

        self.total_downloaded += total_bytes;
        if self.total_downloaded > self.config.quota.unwrap_or(u64::MAX) {
            log::warn!("quota exceeded ({} bytes downloaded, quota {})",
                self.total_downloaded, self.config.quota.unwrap_or(0));
        }

        if let Some(mdtm) = mdtm {
            apply_file_timestamp(output_path, mdtm);
        }

        self.registry().register_download(&url.display(), output_path);

        // Set extended attributes if enabled
        if self.config.xattr {
            let metadata = crate::xattr::FileMetadata {
                url: url.display(),
                content_type: None, // FTP doesn't provide content-type
                last_modified: None,
                etag: None,
            };
            if let Err(e) = crate::xattr::set_xattr(output_path, &metadata) {
                log::warn!("failed to set xattr on {}: {}", output_path.display(), e);
            }
        }

        // Preserve permissions if enabled
        if self.config.preserve_permissions {
            // For FTP, we could potentially get permissions from LIST output
            // For now, use default permissions
            let perms = crate::xattr::RemotePermissions::default();
            if let Err(e) = crate::xattr::apply_permissions(output_path, &perms) {
                log::warn!("failed to set permissions on {}: {}", output_path.display(), e);
            }
        }

        // Delete file after download if --delete-after is set
        if self.config.delete_after {
            if let Err(e) = fs::remove_file(output_path) {
                warn!("failed to delete file after download: {}", e);
            }
        }

        let result = BodyResult {
            bytes_read: total_bytes,
            elapsed,
            local_file: if self.config.delete_after { None } else { Some(output_path.to_path_buf()) },
            content_type: None,
        };

        Ok(RetrieveOutcome::Success(result))
    }

    /// Download every file matching an FTP glob pattern.
    ///
    /// Connects (optionally via FTPS), CWDs to the directory portion of the
    /// URL, lists it, and downloads each entry whose name matches the glob
    /// pattern in the URL's filename component. `--no-glob` disables this.
    pub(crate) fn retrieve_ftp_glob(
        &mut self,
        url: &ParsedUrl,
        _referer: Option<&str>,
    ) -> Result<RetrieveOutcome, RetrieveError> {
        let user = url.user.clone()
            .or(self.config.ftp.user.clone())
            .unwrap_or_else(|| "anonymous".to_string());
        let password = url.password.clone()
            .or(self.config.ftp.password.clone())
            .unwrap_or_else(|| "-wget@".to_string());

        let use_ftps = url.scheme == Scheme::Ftps || self.config.ftp.ftps_implicit;
        let port = if url.scheme == Scheme::Ftps && url.port == 21 {
            if self.config.ftp.ftps_implicit { 990 } else { 21 }
        } else {
            url.port
        };

        // Directory components (everything except the last segment, which is
        // the glob pattern). CWD into each in turn. Percent-escapes decoded
        // before commands (wget semantics) and so the decoded pattern can
        // match raw NLST entry names.
        let path_segments: Vec<String> = url.path.trim_start_matches('/')
            .split('/').filter(|s| !s.is_empty())
            .map(ut_core::url::decode_iri)
            .collect();
        let glob_pattern = path_segments.last().map(|s| s.as_str()).unwrap_or("*");

        // Collect matching filenames via a directory listing.
        let matches: Vec<ut_ftp::FtpEntry> = if use_ftps {
            let ftps_cfg = ut_ftp::FtpsConfig {
                verify_certificate: self.config.tls.check_certificate != ut_core::types::CheckCertMode::Off,
                ca_cert: self.config.tls.ca_cert.clone(),
                client_cert: self.config.tls.cert_file.clone(),
                client_key: self.config.tls.private_key.clone(),
                require_data_tls: !self.config.ftp.ftps_clear_data,
                secure_protocol: self.config.tls.secure_protocol,
                clear_data_connection: self.config.ftp.ftps_clear_data,
                resume_ssl: self.config.ftp.ftps_resume_ssl,
                active_mode: !self.config.ftp.passive,
                // M20: FTPS now honors the same TLS policy as HTTPS.
                crl_file: self.config.tls.crl_file.clone(),
                pinned_pubkey: self.config.tls.pinned_pubkey.clone(),
                ciphers: self.config.tls.ciphers.clone(),
            };
            let mut ftps = ut_ftp::FtpsClient::with_config(ftps_cfg)
                .with_timeout(self.config.read_timeout.or(self.config.timeout).unwrap_or(std::time::Duration::from_secs(60)));
            if self.config.ftp.ftps_implicit {
                ftps.connect_implicit(&url.host, port)
                    .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTPS connect error: {}", e))))?;
            } else {
                ftps.connect_explicit(&url.host, port)
                    .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTPS connect error: {}", e))))?;
            }
            ftps.login(&user, &password)
                .map_err(|_| RetrieveError::Protocol(WgetError::FtpLoginRefused))?;
            ftps.type_binary()
                .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTP type error: {}", e))))?;
            for dir in &path_segments[..path_segments.len().saturating_sub(1)] {
                ftps.cwd(dir).map_err(RetrieveError::Ftp)?;
            }
            // LIST (not NLST) so entry types are known: directories can be
            // descended into and symlinks skipped (wget ftp_retrieve_glob).
            let listing = ftps.list(None)
                .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTP LIST error: {}", e))))?;
            let _ = ftps.quit();
            filter_glob_entries(&listing, glob_pattern, self.config.ignore_case)
        } else {
            let mut ftp = ut_ftp::FtpClient::new().with_passive(self.config.ftp.passive);
            ftp.connect(&url.host, url.port)
                .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTP connect error: {}", e))))?;
            ftp.login(&user, &password)
                .map_err(|_| RetrieveError::Protocol(WgetError::FtpLoginRefused))?;
            ftp.type_binary()
                .map_err(|e| RetrieveError::Protocol(WgetError::FtpIo(format!("FTP type error: {}", e))))?;
            for dir in &path_segments[..path_segments.len().saturating_sub(1)] {
                ftp.cwd(dir).map_err(RetrieveError::Ftp)?;
            }
            let listing = ftp.list(None)
                .map_err(|e| RetrieveError::Ftp(e))?;
            let _ = ftp.quit();
            filter_glob_entries(&listing, glob_pattern, self.config.ignore_case)
        };

        if matches.is_empty() {
            warn!("no files matched FTP glob pattern '{}'", glob_pattern);
            return Ok(RetrieveOutcome::SpiderOnly);
        }

        info!("FTP glob '{}' matched {} file(s)", glob_pattern, matches.len());

        // Download each matched file by re-running the single-file retrieval
        // path with a concrete URL (no glob characters). Matched
        // directories descend through the directory-listing path (trailing
        // slash) when recursion is enabled.
        // dir_part keeps its trailing slash: "/pub/docs" + "report.txt"
        // would otherwise concatenate into "/pub/docsreport.txt".
        let dir_part = if path_segments.len() > 1 {
            format!("/{}/", path_segments[..path_segments.len() - 1].join("/"))
        } else {
            String::new()
        };
        let mut worst: Option<RetrieveError> = None;
        let mut last_outcome = RetrieveOutcome::SpiderOnly;
        for entry in matches {
            if entry.is_symlink {
                // Symlink targets are untrustworthy; wget follows only with
                // --retr-symlinks.
                debug!("skipping FTP symlink {} (no --retr-symlinks)", entry.name);
                continue;
            }
            if entry.is_dir && !self.config.recursive.enabled {
                debug!("skipping FTP directory {} (not recursive)", entry.name);
                continue;
            }
            // Percent-encode the expanded filename: LIST entries may contain
            // spaces or other characters that would break URL parsing
            // (M15: previously a file "a b.txt" failed ParsedUrl::parse and
            // was silently skipped). encode_request_target escapes
            // control/space/high bytes while keeping '/' and '?' intact.
            let encoded_name = ut_core::url::encode_request_target(&entry.name);
            let concrete = format!("{}://{}:{}{}{}{}",
                url.scheme.as_str(), url.host, url.port, dir_part, encoded_name,
                if entry.is_dir { "/" } else { "" });
            match self.retrieve_new_chain_with_retry(&concrete) {
                Ok(o) => last_outcome = o,
                Err(e) => {
                    warn!("failed to download '{}': {}", entry.name, e);
                    worst = worst.or(Some(e));
                }
            }
        }
        match worst {
            Some(e) => Err(e),
            None => Ok(last_outcome),
        }
    }
}
