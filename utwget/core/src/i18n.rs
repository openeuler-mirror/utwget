use std::sync::OnceLock;

static CURRENT_LOCALE: OnceLock<String> = OnceLock::new();
const DEFAULT_LOCALE: &str = "en";
pub const SUPPORTED_LOCALES: &[&str] = &["en", "zh-CN"];

pub fn init_locale() {
    if let Ok(lang) = std::env::var("LANGUAGE") {
        if let Some(first) = lang.split(':').next() {
            let normalized = first.replace('_', "-");
            if SUPPORTED_LOCALES.contains(&normalized.as_str()) {
                let _ = CURRENT_LOCALE.set(normalized);
                return;
            }
            if let Some(lang_part) = normalized.split('-').next() {
                if SUPPORTED_LOCALES.contains(&lang_part) {
                    let _ = CURRENT_LOCALE.set(lang_part.to_string());
                    return;
                }
            }
        }
    }
    if let Ok(lang) = std::env::var("LANG") {
        let lang = lang.split('.').next().unwrap_or("en");
        let normalized = lang.replace('_', "-");
        if SUPPORTED_LOCALES.contains(&normalized.as_str()) {
            let _ = CURRENT_LOCALE.set(normalized);
            return;
        }
        if let Some(lang_part) = normalized.split('-').next() {
            if SUPPORTED_LOCALES.contains(&lang_part) {
                let _ = CURRENT_LOCALE.set(lang_part.to_string());
                return;
            }
        }
    }
    let _ = CURRENT_LOCALE.set(DEFAULT_LOCALE.to_string());
}

pub fn set_locale(locale: &str) {
    let locale = if SUPPORTED_LOCALES.contains(&locale) {
        locale.to_string()
    } else {
        let normalized = locale.replace('_', "-");
        if SUPPORTED_LOCALES.contains(&normalized.as_str()) {
            normalized
        } else {
            DEFAULT_LOCALE.to_string()
        }
    };
    let _ = CURRENT_LOCALE.set(locale);
}

pub fn current_locale() -> &'static str {
    CURRENT_LOCALE.get().map(|s| s.as_str()).unwrap_or_else(|| {
        if let Ok(lang) = std::env::var("LANG") {
            let lang = lang.split('.').next().unwrap_or("en");
            let normalized = lang.replace('_', "-");
            if SUPPORTED_LOCALES.contains(&normalized.as_str()) {
                return CURRENT_LOCALE.get_or_init(|| normalized);
            }
            if let Some(lang_part) = normalized.split('-').next() {
                if SUPPORTED_LOCALES.contains(&lang_part) {
                    return CURRENT_LOCALE.get_or_init(|| lang_part.to_string());
                }
            }
        }
        if let Ok(lang) = std::env::var("LANGUAGE") {
            if let Some(first) = lang.split(':').next() {
                let normalized = first.replace('_', "-");
                if SUPPORTED_LOCALES.contains(&normalized.as_str()) {
                    return CURRENT_LOCALE.get_or_init(|| normalized);
                }
            }
        }
        DEFAULT_LOCALE
    })
}

pub fn translate(key: &str) -> String {
    let locale = current_locale();
    get_translation(locale, key).unwrap_or(key).to_string()
}

pub fn translate_with_args(key: &str, args: &[(&str, String)]) -> String {
    let template = translate(key);
    let mut result = template;
    for (name, value) in args {
        result = result.replace(&format!("%{{{}}}", name), value);
    }
    result
}

fn get_translation(locale: &str, key: &str) -> Option<&'static str> {
    const TRANSLATIONS: &[(&str, &str, &str)] = &[
        // ===================
        // English
        // ===================
        ("en", "utwget.version", "GNU Wget 1.21.4 built on linux-gnu."),
        ("en", "utwget.help_usage", "Usage: utwget [OPTION]... [URL]..."),
        ("en", "utwget.help_mandatory", "Mandatory arguments to long options are mandatory for short options too."),
        ("en", "utwget.error_no_url", "No URLs specified"),
        ("en", "utwget.error_file_not_found", "File not found: %{file}"),
        ("en", "utwget.error_connection_refused", "Connection refused"),
        ("en", "utwget.error_timeout", "Connection timed out"),
        ("en", "utwget.error_dns_failure", "DNS resolution failed: %{host}"),
        ("en", "utwget.error_invalid_url", "Invalid URL: %{url}"),
        ("en", "utwget.error_write_failed", "Write failed: %{reason}"),
        ("en", "utwget.error_read_failed", "Read failed: %{reason}"),
        ("en", "utwget.error_network", "Network error: %{reason}"),
        ("en", "utwget.error_ssl", "SSL error: %{reason}"),
        ("en", "utwget.error_auth_failed", "Authentication failed"),
        ("en", "utwget.warning_config_error", "warning: error applying %{path}: %{error}"),
        ("en", "utwget.warning_config_read_error", "warning: error reading %{path}: %{error}"),
        ("en", "utwget.warning_failed_set_xattr", "failed to set xattr on %{path}: %{error}"),
        ("en", "utwget.warning_failed_permissions", "failed to set permissions on %{path}: %{error}"),
        ("en", "utwget.warning_partial_download", "warning: partial download completed"),
        ("en", "utwget.status_saved", "saved [%{url}] (%{size} bytes) in %{duration} (%{speed})"),
        ("en", "utwget.status_saved_to", "Saved to: %{path}"),
        ("en", "utwget.status_download_complete", "Download complete"),
        ("en", "utwget.status_downloading", "Downloading"),
        ("en", "utwget.status_connecting", "Connecting to %{host}:%{port}"),
        ("en", "utwget.status_resolving", "Resolving %{host}..."),
        ("en", "utwget.status_redirect", "Redirected to %{url}"),
        ("en", "utwget.status_not_modified", "Server file not modified"),
        ("en", "utwget.status_skipping", "Skipping %{url}: %{reason}"),
        ("en", "utwget.status_already_exists", "File already exists; not retrieving."),
        ("en", "utwget.status_fully_retrieved", "The file is already fully retrieved; nothing to do."),
        ("en", "utwget.status_redirected_to", "Redirected to: %{url}"),
        ("en", "utwget.progress_finished", "FINISHED --"),
        ("en", "utwget.progress_downloaded", "Downloaded: %{bytes} bytes in %{files} files"),
        ("en", "utwget.progress_time", "Total wall clock time: %{duration}"),
        ("en", "utwget.progress_speed", "Speed: %{speed}"),
        ("en", "utwget.auth_password_prompt", "Password for %{user}: "),
        ("en", "utwget.auth_password_prompt_default", "Password: "),
        ("en", "utwget.auth_username_prompt", "Username: "),
        ("en", "utwget.recursive_entering", "Entering directory %{dir}"),
        ("en", "utwget.recursive_leaving", "Leaving directory %{dir}"),
        ("en", "utwget.recursive_depth", "Depth: %{depth}"),
        ("en", "utwget.recursive_following", "Following links in %{url}"),
        ("en", "utwget.proxy_connecting", "Connecting to proxy %{host}:%{port}"),
        ("en", "utwget.proxy_tunnel", "Establishing tunnel to %{host}:%{port}"),
        ("en", "utwget.resume_partial", "Partial download detected, resuming from byte %{pos}"),
        ("en", "utwget.resume_complete", "Download already complete"),
        ("en", "utwget.signal_interrupted", "Interrupted. Saving current download state..."),
        ("en", "utwget.signal_graceful", "Received termination signal, shutting down gracefully..."),
        ("en", "utwget.error", "ERROR: %{reason}"),
        ("en", "utwget.downloading_to", "Downloading %{url} to %{path}"),
        ("en", "utwget.downloaded_info", "Downloaded: %{url} (%{size} bytes, checksum: %{checksum})"),
        ("en", "utwget.error_downloading", "utwget: error downloading %{url}: %{error}"),
        ("en", "utwget.response_saved", "Server response saved to %{path}"),
        ("en", "utwget.request_sent", "Sent request, waiting for response..."),
        ("en", "utwget.config_reloaded", "Configuration reloaded"),

        // ===================
        // Help text
        // ===================
        ("en", "utwget.help_startup", "Startup"),
        ("en", "utwget.help_version", "print this version"),
        ("en", "utwget.help_help", "print this help"),
        ("en", "utwget.help_background", "go to background just after startup"),
        ("en", "utwget.help_execute", "execute a \".wgetrc\" command"),
        ("en", "utwget.help_logging", "Logging and input file"),
        ("en", "utwget.help_output_file", "log messages to FILE"),
        ("en", "utwget.help_append_output", "append messages to FILE"),
        ("en", "utwget.help_debug", "print lots of debugging information"),
        ("en", "utwget.help_quiet", "quiet (no output)"),
        ("en", "utwget.help_verbose", "be verbose (this is the default)"),
        ("en", "utwget.help_no_verbose", "turn off verboseness, but not quiet"),
        ("en", "utwget.help_report_speed", "output speed as either TYPE or TOTAL AVG"),
        ("en", "utwget.help_input_file", "read URLs from FILE"),
        ("en", "utwget.help_force_html", "treat input file as HTML"),
        ("en", "utwget.help_base", "base URL resolves <base> tags in HTML"),
        ("en", "utwget.help_config", "specify custom config file"),
        ("en", "utwget.help_no_config", "disable loading of config file"),
        ("en", "utwget.help_rejected_log", "log where URLs are rejected before download"),
        ("en", "utwget.help_download", "Download"),
        ("en", "utwget.help_tries", "set number of retries to NUMBER"),
        ("en", "utwget.help_retry_connrefused", "retry even if connection is refused"),
        ("en", "utwget.help_retry_on_host_error", "retry on host error"),
        ("en", "utwget.help_retry_on_http_error", "retry on server error matching ERRORS"),
        ("en", "utwget.help_output_document", "save all documents to FILE"),
        ("en", "utwget.help_no_clobber", "skip downloads that appear download already done"),
        ("en", "utwget.help_no_netrc", "disable parsing of .netrc"),
        ("en", "utwget.help_continue", "resume getting a partially-downloaded file"),
        ("en", "utwget.help_start_pos", "start getting from OFFSET bytes into file"),
        ("en", "utwget.help_progress", "select progress gauge type"),
        ("en", "utwget.help_show_progress", "display progress bar in any verbosity mode"),
        ("en", "utwget.help_timestamping", "don't re-retrieve files unless newer than local"),
        ("en", "utwget.help_server_response", "print server response"),
        ("en", "utwget.help_spider", "don't download anything"),
        ("en", "utwget.help_timeout", "set all timeout values to SECONDS"),
        ("en", "utwget.help_wait", "wait SECONDS between retrievals"),
        ("en", "utwget.help_concurrency", "number of concurrent downloads (utwget extension)"),
        ("en", "utwget.help_no_proxy", "use the proxy directly"),
        ("en", "utwget.help_quota", "set retrieval quota to NUMBER"),
        ("en", "utwget.help_limit_rate", "limit download rate to RATE"),
        ("en", "utwget.help_connect_timeout", "set the connect timeout to SECS"),
        ("en", "utwget.help_read_timeout", "set the read timeout to SECS"),
        ("en", "utwget.help_dns_timeout", "set the DNS timeout to SECS"),
        ("en", "utwget.help_waitretry", "wait SECONDS between retries"),
        ("en", "utwget.help_random_wait", "wait from 0..2*WAIT seconds between retrievals"),
        ("en", "utwget.help_delete_after", "delete file after download"),
        ("en", "utwget.help_content_disposition", "use Content-Disposition to determine filename"),
        ("en", "utwget.help_auth_no_challenge", "use Basic auth without challenge"),
        ("en", "utwget.help_ask_password", "ask for password interactively"),
        ("en", "utwget.help_use_askpass", "use PROGRAM for password prompts"),
        ("en", "utwget.help_trust_server_names", "trust server names when redirecting"),
        ("en", "utwget.help_unlink", "remove file before writing"),
        ("en", "utwget.help_xattr", "set extended attributes"),
        ("en", "utwget.help_preserve_permissions", "preserve file permissions"),
        ("en", "utwget.help_directories", "Directories"),
        ("en", "utwget.help_no_directories", "don't create directories"),
        ("en", "utwget.help_force_directories", "force creation of directories"),
        ("en", "utwget.help_no_host_directories", "don't create host directories"),
        ("en", "utwget.help_protocol_directories", "use protocol name in directories"),
        ("en", "utwget.help_directory_prefix", "save files to PREFIX/.."),
        ("en", "utwget.help_cut_dirs", "ignore NUMBER remote directory components"),
        ("en", "utwget.help_http_options", "HTTP options"),
        ("en", "utwget.help_http_user", "set http user to USER"),
        ("en", "utwget.help_http_password", "set http password to PASS"),
        ("en", "utwget.help_no_cache", "disallow server-cached data"),
        ("en", "utwget.help_adjust_extension", "save HTML/CSS documents with proper extensions"),
        ("en", "utwget.help_header", "insert STRING among the headers"),
        ("en", "utwget.help_compression", "choose compression, one of auto, gzip and none"),
        ("en", "utwget.help_user_agent", "identify as AGENT instead of Wget/VERSION"),
        ("en", "utwget.help_no_cookies", "don't use cookies"),
        ("en", "utwget.help_load_cookies", "load cookies from FILE before session"),
        ("en", "utwget.help_save_cookies", "save cookies to FILE after session"),
        ("en", "utwget.help_post_data", "use the POST method; send STRING as the data"),
        ("en", "utwget.help_post_file", "use the POST method; send contents of FILE"),
        ("en", "utwget.help_https_options", "HTTPS (SSL/TLS) options"),
        ("en", "utwget.help_secure_protocol", "choose secure protocol, one of auto, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3 and PFS"),
        ("en", "utwget.help_https_only", "only follow secure HTTPS links"),
        ("en", "utwget.help_no_check_certificate", "don't validate the server's certificate"),
        ("en", "utwget.help_certificate", "client certificate file"),
        ("en", "utwget.help_ca_certificate", "file with the bundle of CAs"),
        ("en", "utwget.help_ciphers", "Set the priority string (GnuTLS) or cipher list string (OpenSSL) directly."),
        ("en", "utwget.help_ca_directory", "CA certificate directory"),
        ("en", "utwget.help_crl_file", "certificate revocation list file"),
        ("en", "utwget.help_pinnedpubkey", "SHA256 hash of public key certificate"),
        ("en", "utwget.help_ftp_options", "FTP options"),
        ("en", "utwget.help_ftp_user", "set ftp user to USER"),
        ("en", "utwget.help_ftp_password", "set ftp password to PASS"),
        ("en", "utwget.help_no_remove_listing", "don't remove the temporary .listing files"),
        ("en", "utwget.help_no_glob", "turn off FTP file name globbing"),
        ("en", "utwget.help_no_passive_ftp", "disable the \"passive\" transfer mode"),
        ("en", "utwget.help_retr_symlinks", "traverse symlinks and retrieve pointed-to files"),
        ("en", "utwget.help_ftps_implicit", "use implicit FTPS"),
        ("en", "utwget.help_ftps_resume_ssl", "resume TLS session"),
        ("en", "utwget.help_ftps_clear_data_connection", "clear data connection"),
        ("en", "utwget.help_ftps_fallback_to_ftp", "fallback to FTP if FTPS fails"),
        ("en", "utwget.help_recursive_download", "Recursive download"),
        ("en", "utwget.help_recursive", "specify recursive download"),
        ("en", "utwget.help_level", "maximum recursion depth (inf or 0 for infinite)"),
        ("en", "utwget.help_convert_links", "make links in downloaded HTML or CSS point to local files"),
        ("en", "utwget.help_backup_converted", "before converting file X, back up as X.orig"),
        ("en", "utwget.help_mirror", "turn on options suitable for mirroring"),
        ("en", "utwget.help_page_requisites", "get all images, etc. needed to display HTML page"),
        ("en", "utwget.help_strict_comments", "turn on strict (SGML) handling of HTML comments"),
        ("en", "utwget.help_convert_file_only", "only convert file name part of links"),
        ("en", "utwget.help_reject_tags", "comma-separated list of tags to not follow"),
        ("en", "utwget.help_recursive_accept", "Recursive accept/reject"),
        ("en", "utwget.help_accept", "comma-separated list of accepted extensions"),
        ("en", "utwget.help_reject", "comma-separated list of rejected extensions"),
        ("en", "utwget.help_accept_regex", "regex matching accepted extensions"),
        ("en", "utwget.help_reject_regex", "regex matching rejected extensions"),
        ("en", "utwget.help_domains", "comma-separated list of accepted domains"),
        ("en", "utwget.help_exclude_domains", "comma-separated list of rejected domains"),
        ("en", "utwget.help_follow_ftp", "follow FTP links from HTML documents"),
        ("en", "utwget.help_span_hosts", "go to foreign hosts when recursive"),
        ("en", "utwget.help_relative", "follow relative links only"),
        ("en", "utwget.help_include_directories", "list of allowed directories"),
        ("en", "utwget.help_exclude_directories", "list of excluded directories"),
        ("en", "utwget.help_no_parent", "don't ascend to the parent directory"),
        ("en", "utwget.help_robots", "use robots.txt"),
        ("en", "utwget.help_regex_type", "regular expression type"),
        ("en", "utwget.help_ignore_case", "ignore case when matching"),
        ("en", "utwget.help_keep_session_cookies", "keep session cookies"),
        ("en", "utwget.help_referer", "set Referer header"),
        ("en", "utwget.help_local_encoding", "set local encoding"),
        ("en", "utwget.help_remote_encoding", "set remote encoding"),
        ("en", "utwget.help_no_iri", "disable IRI support"),
        ("en", "utwget.help_http2", "force HTTP/2 usage (utwget extension)"),
        ("en", "utwget.help_http1_1", "force HTTP/1.1 usage (disable HTTP/2)"),
        ("en", "utwget.help_backups", "number of backups to keep"),
        ("en", "utwget.help_bind_address", "bind address for outgoing connections"),
        ("en", "utwget.help_no_dns_cache", "disable DNS cache"),
        ("en", "utwget.help_restrict_file_names", "restrict file names"),
        ("en", "utwget.help_prefer_family", "prefer address family"),
        ("en", "utwget.help_private_key", "private key file"),
        ("en", "utwget.help_private_key_type", "private key type"),
        ("en", "utwget.help_certificate_type", "certificate type"),
        ("en", "utwget.help_metalink_options", "Metalink options"),
        ("en", "utwget.help_metalink_over_http", "use Metalink from HTTP response headers"),
        ("en", "utwget.help_input_metalink", "read Metalink from FILE"),
        ("en", "utwget.help_warc_options", "WARC options"),
        ("en", "utwget.help_warc_file", "save WARC to FILENAME"),
        ("en", "utwget.help_warc_maxsize", "set maximum WARC file size to NUMBER"),
        ("en", "utwget.help_warc_cdx", "write CDX index file"),
        ("en", "utwget.help_warc_dedup", "do not store records matching URL"),
        ("en", "utwget.help_warc_compression", "enable WARC compression"),
        ("en", "utwget.help_warc_digests", "enable WARC digests"),
        ("en", "utwget.help_warc_keep_log", "keep log file in WARC"),
        ("en", "utwget.help_warc_temp_dir", "temporary directory for WARC files"),
        ("en", "utwget.help_warc_header", "add custom WARC header"),
        ("en", "utwget.help_email", "Email bug reports, questions and discussions to <bug-wget@gnu.org>."),

        // ===================
        // Chinese (Simplified)
        // ===================
        ("zh-CN", "utwget.version", "GNU Wget 1.21.4 在 linux-gnu 上编译。"),
        ("zh-CN", "utwget.help_usage", "用法： wget [选项]... [URL]..."),
        ("zh-CN", "utwget.help_mandatory", "长选项所必须的参数在使用短选项时也是必须的。"),
        ("zh-CN", "utwget.error_no_url", "未指定 URL"),
        ("zh-CN", "utwget.error_file_not_found", "文件未找到: %{file}"),
        ("zh-CN", "utwget.error_connection_refused", "连接被拒绝"),
        ("zh-CN", "utwget.error_timeout", "连接超时"),
        ("zh-CN", "utwget.error_dns_failure", "DNS 解析失败: %{host}"),
        ("zh-CN", "utwget.error_invalid_url", "无效的 URL: %{url}"),
        ("zh-CN", "utwget.error_write_failed", "写入失败: %{reason}"),
        ("zh-CN", "utwget.error_read_failed", "读取失败: %{reason}"),
        ("zh-CN", "utwget.error_network", "网络错误: %{reason}"),
        ("zh-CN", "utwget.error_ssl", "SSL 错误: %{reason}"),
        ("zh-CN", "utwget.error_auth_failed", "认证失败"),
        ("zh-CN", "utwget.warning_config_error", "警告: 应用 %{path} 时出错: %{error}"),
        ("zh-CN", "utwget.warning_config_read_error", "警告: 读取 %{path} 时出错: %{error}"),
        ("zh-CN", "utwget.warning_failed_set_xattr", "无法设置 %{path} 的扩展属性: %{error}"),
        ("zh-CN", "utwget.warning_failed_permissions", "无法设置 %{path} 的权限: %{error}"),
        ("zh-CN", "utwget.warning_partial_download", "警告: 部分下载已完成"),
        ("zh-CN", "utwget.status_saved", "已保存 [%{url}]（%{size} 字节）用时 %{duration}（%{speed}）"),
        ("zh-CN", "utwget.status_saved_to", "已保存到: %{path}"),
        ("zh-CN", "utwget.status_download_complete", "下载完成"),
        ("zh-CN", "utwget.status_downloading", "正在下载"),
        ("zh-CN", "utwget.status_connecting", "正在连接 %{host}:%{port}"),
        ("zh-CN", "utwget.status_resolving", "正在解析 %{host}..."),
        ("zh-CN", "utwget.status_redirect", "重定向到 %{url}"),
        ("zh-CN", "utwget.status_not_modified", "服务器文件未修改"),
        ("zh-CN", "utwget.status_skipping", "跳过 %{url}: %{reason}"),
        ("zh-CN", "utwget.status_already_exists", "文件已存在；不再获取。"),
        ("zh-CN", "utwget.status_fully_retrieved", "文件已完整获取；无需操作。"),
        ("zh-CN", "utwget.status_redirected_to", "重定向到: %{url}"),
        ("zh-CN", "utwget.progress_finished", "完成 --"),
        ("zh-CN", "utwget.progress_downloaded", "已下载: %{bytes} 字节，共 %{files} 个文件"),
        ("zh-CN", "utwget.progress_time", "总用时: %{duration}"),
        ("zh-CN", "utwget.progress_speed", "速度: %{speed}"),
        ("zh-CN", "utwget.auth_password_prompt", "%{user} 的密码: "),
        ("zh-CN", "utwget.auth_password_prompt_default", "密码: "),
        ("zh-CN", "utwget.auth_username_prompt", "用户名: "),
        ("zh-CN", "utwget.recursive_entering", "进入目录 %{dir}"),
        ("zh-CN", "utwget.recursive_leaving", "离开目录 %{dir}"),
        ("zh-CN", "utwget.recursive_depth", "深度: %{depth}"),
        ("zh-CN", "utwget.recursive_following", "跟随 %{url} 中的链接"),
        ("zh-CN", "utwget.proxy_connecting", "正在连接代理 %{host}:%{port}"),
        ("zh-CN", "utwget.proxy_tunnel", "正在建立到 %{host}:%{port} 的隧道"),
        ("zh-CN", "utwget.resume_partial", "检测到部分下载，从字节 %{pos} 继续"),
        ("zh-CN", "utwget.resume_complete", "下载已完成"),
        ("zh-CN", "utwget.signal_interrupted", "已中断。正在保存当前下载状态..."),
        ("zh-CN", "utwget.config_reloaded", "配置已重新加载"),
        ("zh-CN", "utwget.signal_graceful", "收到终止信号，正在优雅关闭..."),
        ("zh-CN", "utwget.error", "错误: %{reason}"),
        ("zh-CN", "utwget.downloading_to", "正在将 %{url} 下载到 %{path}"),
        ("zh-CN", "utwget.downloaded_info", "已下载: %{url}（%{size} 字节，校验和: %{checksum}）"),
        ("zh-CN", "utwget.error_downloading", "utwget: 下载 %{url} 时出错: %{error}"),
        ("zh-CN", "utwget.response_saved", "服务器响应已保存到 %{path}"),
        ("zh-CN", "utwget.request_sent", "已发送请求，等待响应..."),

        ("zh-CN", "utwget.help_startup", "启动"),
        ("zh-CN", "utwget.help_version", "显示此版本"),
        ("zh-CN", "utwget.help_help", "显示此帮助信息"),
        ("zh-CN", "utwget.help_background", "启动后立即转入后台运行"),
        ("zh-CN", "utwget.help_execute", "执行 \".wgetrc\" 命令"),
        ("zh-CN", "utwget.help_logging", "日志记录和输入文件"),
        ("zh-CN", "utwget.help_output_file", "将消息记录到 FILE"),
        ("zh-CN", "utwget.help_append_output", "将消息追加到 FILE"),
        ("zh-CN", "utwget.help_debug", "输出大量调试信息"),
        ("zh-CN", "utwget.help_quiet", "安静模式（无输出）"),
        ("zh-CN", "utwget.help_verbose", "详细输出（默认）"),
        ("zh-CN", "utwget.help_no_verbose", "关闭详细输出，但不安静"),
        ("zh-CN", "utwget.help_report_speed", "以 TYPE 或 TOTAL AVG 输出速度"),
        ("zh-CN", "utwget.help_input_file", "从 FILE 读取 URL"),
        ("zh-CN", "utwget.help_force_html", "将输入文件视为 HTML"),
        ("zh-CN", "utwget.help_base", "基础 URL 解析 HTML 中的 <base> 标签"),
        ("zh-CN", "utwget.help_config", "指定自定义配置文件"),
        ("zh-CN", "utwget.help_no_config", "禁用配置文件加载"),
        ("zh-CN", "utwget.help_rejected_log", "记录下载前被拒绝的 URL"),
        ("zh-CN", "utwget.help_download", "下载"),
        ("zh-CN", "utwget.help_tries", "设置重试次数为 NUMBER"),
        ("zh-CN", "utwget.help_retry_connrefused", "即使连接被拒绝也重试"),
        ("zh-CN", "utwget.help_retry_on_host_error", "主机错误时重试"),
        ("zh-CN", "utwget.help_retry_on_http_error", "匹配 ERRORS 的服务器错误时重试"),
        ("zh-CN", "utwget.help_output_document", "将所有文档保存到 FILE"),
        ("zh-CN", "utwget.help_no_clobber", "跳过已下载完成的文件"),
        ("zh-CN", "utwget.help_no_netrc", "禁用 .netrc 解析"),
        ("zh-CN", "utwget.help_continue", "继续下载部分下载的文件"),
        ("zh-CN", "utwget.help_start_pos", "从文件的 OFFSET 字节处开始下载"),
        ("zh-CN", "utwget.help_progress", "选择进度条类型"),
        ("zh-CN", "utwget.help_show_progress", "在任何详细模式下显示进度条"),
        ("zh-CN", "utwget.help_timestamping", "仅在本地文件较新时不重新获取"),
        ("zh-CN", "utwget.help_server_response", "打印服务器响应"),
        ("zh-CN", "utwget.help_spider", "不下载任何内容"),
        ("zh-CN", "utwget.help_timeout", "将所有超时值设为 SECONDS"),
        ("zh-CN", "utwget.help_wait", "每次获取间隔等待 SECONDS"),
        ("zh-CN", "utwget.help_concurrency", "并发下载数量（utwget 扩展）"),
        ("zh-CN", "utwget.help_no_proxy", "直接使用代理"),
        ("zh-CN", "utwget.help_quota", "设置获取配额为 NUMBER"),
        ("zh-CN", "utwget.help_limit_rate", "限制下载速度为 RATE"),
        ("zh-CN", "utwget.help_connect_timeout", "设置连接超时为 SECS"),
        ("zh-CN", "utwget.help_read_timeout", "设置读取超时为 SECS"),
        ("zh-CN", "utwget.help_dns_timeout", "设置 DNS 超时为 SECS"),
        ("zh-CN", "utwget.help_waitretry", "重试间隔等待 SECONDS"),
        ("zh-CN", "utwget.help_random_wait", "每次获取间隔随机等待 0..2*WAIT 秒"),
        ("zh-CN", "utwget.help_delete_after", "下载后删除文件"),
        ("zh-CN", "utwget.help_content_disposition", "使用 Content-Disposition 确定文件名"),
        ("zh-CN", "utwget.help_auth_no_challenge", "使用 Basic 认证无需质询"),
        ("zh-CN", "utwget.help_ask_password", "交互式询问密码"),
        ("zh-CN", "utwget.help_use_askpass", "使用 PROGRAM 询问密码"),
        ("zh-CN", "utwget.help_trust_server_names", "重定向时信任服务器名称"),
        ("zh-CN", "utwget.help_unlink", "写入前删除文件"),
        ("zh-CN", "utwget.help_xattr", "设置扩展属性"),
        ("zh-CN", "utwget.help_preserve_permissions", "保留文件权限"),
        ("zh-CN", "utwget.help_directories", "目录"),
        ("zh-CN", "utwget.help_no_directories", "不创建目录"),
        ("zh-CN", "utwget.help_force_directories", "强制创建目录"),
        ("zh-CN", "utwget.help_no_host_directories", "不创建主机目录"),
        ("zh-CN", "utwget.help_protocol_directories", "在目录中使用协议名"),
        ("zh-CN", "utwget.help_directory_prefix", "将文件保存到 PREFIX/.."),
        ("zh-CN", "utwget.help_cut_dirs", "忽略 NUMBER 个远程目录组件"),
        ("zh-CN", "utwget.help_http_options", "HTTP 选项"),
        ("zh-CN", "utwget.help_http_user", "设置 HTTP 用户为 USER"),
        ("zh-CN", "utwget.help_http_password", "设置 HTTP 密码为 PASS"),
        ("zh-CN", "utwget.help_no_cache", "禁止使用服务器缓存数据"),
        ("zh-CN", "utwget.help_adjust_extension", "以正确的扩展名保存 HTML/CSS 文档"),
        ("zh-CN", "utwget.help_header", "在头部插入 STRING"),
        ("zh-CN", "utwget.help_compression", "选择压缩方式，可选 auto、gzip 或 none"),
        ("zh-CN", "utwget.help_user_agent", "标识为 AGENT 而非 Wget/VERSION"),
        ("zh-CN", "utwget.help_no_cookies", "不使用 cookies"),
        ("zh-CN", "utwget.help_load_cookies", "会话前从 FILE 加载 cookies"),
        ("zh-CN", "utwget.help_save_cookies", "会话后将 cookies 保存到 FILE"),
        ("zh-CN", "utwget.help_post_data", "使用 POST 方法；发送 STRING 作为数据"),
        ("zh-CN", "utwget.help_post_file", "使用 POST 方法；发送 FILE 的内容"),
        ("zh-CN", "utwget.help_https_options", "HTTPS (SSL/TLS) 选项"),
        ("zh-CN", "utwget.help_secure_protocol", "选择安全协议，可选 auto、SSLv2、SSLv3、TLSv1、TLSv1_1、TLSv1_2、TLSv1_3 和 PFS"),
        ("zh-CN", "utwget.help_https_only", "仅跟踪安全的 HTTPS 链接"),
        ("zh-CN", "utwget.help_no_check_certificate", "不验证服务器证书"),
        ("zh-CN", "utwget.help_certificate", "客户端证书文件"),
        ("zh-CN", "utwget.help_ca_certificate", "CA 证书包文件"),
        ("zh-CN", "utwget.help_ciphers", "直接设置优先级字符串（GnuTLS）或密码列表字符串（OpenSSL）。"),
        ("zh-CN", "utwget.help_ca_directory", "CA 证书目录"),
        ("zh-CN", "utwget.help_crl_file", "证书吊销列表文件"),
        ("zh-CN", "utwget.help_pinnedpubkey", "公钥证书的 SHA256 哈希"),
        ("zh-CN", "utwget.help_ftp_options", "FTP 选项"),
        ("zh-CN", "utwget.help_ftp_user", "设置 FTP 用户为 USER"),
        ("zh-CN", "utwget.help_ftp_password", "设置 FTP 密码为 PASS"),
        ("zh-CN", "utwget.help_no_remove_listing", "不删除临时 .listing 文件"),
        ("zh-CN", "utwget.help_no_glob", "关闭 FTP 文件名通配"),
        ("zh-CN", "utwget.help_no_passive_ftp", "禁用 \"被动\" 传输模式"),
        ("zh-CN", "utwget.help_retr_symlinks", "遍历符号链接并获取指向的文件"),
        ("zh-CN", "utwget.help_ftps_implicit", "使用隐式 FTPS"),
        ("zh-CN", "utwget.help_ftps_resume_ssl", "恢复 TLS 会话"),
        ("zh-CN", "utwget.help_ftps_clear_data_connection", "清除数据连接"),
        ("zh-CN", "utwget.help_ftps_fallback_to_ftp", "FTPS 失败时回退到 FTP"),
        ("zh-CN", "utwget.help_recursive_download", "递归下载"),
        ("zh-CN", "utwget.help_recursive", "指定递归下载"),
        ("zh-CN", "utwget.help_level", "最大递归深度（inf 或 0 表示无限）"),
        ("zh-CN", "utwget.help_convert_links", "使下载的 HTML 或 CSS 中的链接指向本地文件"),
        ("zh-CN", "utwget.help_backup_converted", "转换文件 X 前，备份为 X.orig"),
        ("zh-CN", "utwget.help_mirror", "启用适合镜像的选项"),
        ("zh-CN", "utwget.help_page_requisites", "获取显示 HTML 页面所需的所有图片等"),
        ("zh-CN", "utwget.help_strict_comments", "启用严格的（SGML）HTML 注释处理"),
        ("zh-CN", "utwget.help_convert_file_only", "只转换链接的文件名部分"),
        ("zh-CN", "utwget.help_reject_tags", "逗号分隔的不跟踪标签列表"),
        ("zh-CN", "utwget.help_recursive_accept", "递归接受/拒绝"),
        ("zh-CN", "utwget.help_accept", "逗号分隔的接受扩展名列表"),
        ("zh-CN", "utwget.help_reject", "逗号分隔的拒绝扩展名列表"),
        ("zh-CN", "utwget.help_accept_regex", "匹配接受扩展名的正则表达式"),
        ("zh-CN", "utwget.help_reject_regex", "匹配拒绝扩展名的正则表达式"),
        ("zh-CN", "utwget.help_domains", "逗号分隔的接受域名列表"),
        ("zh-CN", "utwget.help_exclude_domains", "逗号分隔的拒绝域名列表"),
        ("zh-CN", "utwget.help_follow_ftp", "跟踪 HTML 文档中的 FTP 链接"),
        ("zh-CN", "utwget.help_span_hosts", "递归时访问外部主机"),
        ("zh-CN", "utwget.help_relative", "仅跟踪相对链接"),
        ("zh-CN", "utwget.help_include_directories", "允许的目录列表"),
        ("zh-CN", "utwget.help_exclude_directories", "排除的目录列表"),
        ("zh-CN", "utwget.help_no_parent", "不上升到父目录"),
        ("zh-CN", "utwget.help_robots", "使用 robots.txt"),
        ("zh-CN", "utwget.help_regex_type", "正则表达式类型"),
        ("zh-CN", "utwget.help_ignore_case", "匹配时忽略大小写"),
        ("zh-CN", "utwget.help_keep_session_cookies", "保持会话 cookies"),
        ("zh-CN", "utwget.help_referer", "设置 Referer 头"),
        ("zh-CN", "utwget.help_local_encoding", "设置本地编码"),
        ("zh-CN", "utwget.help_remote_encoding", "设置远程编码"),
        ("zh-CN", "utwget.help_no_iri", "禁用 IRI 支持"),
        ("zh-CN", "utwget.help_http2", "强制使用 HTTP/2（utwget 扩展）"),
        ("zh-CN", "utwget.help_http1_1", "强制使用 HTTP/1.1（禁用 HTTP/2）"),
        ("zh-CN", "utwget.help_backups", "保留的备份数量"),
        ("zh-CN", "utwget.help_bind_address", "出站连接的绑定地址"),
        ("zh-CN", "utwget.help_no_dns_cache", "禁用 DNS 缓存"),
        ("zh-CN", "utwget.help_restrict_file_names", "限制文件名"),
        ("zh-CN", "utwget.help_prefer_family", "首选地址族"),
        ("zh-CN", "utwget.help_private_key", "私钥文件"),
        ("zh-CN", "utwget.help_private_key_type", "私钥类型"),
        ("zh-CN", "utwget.help_certificate_type", "证书类型"),
        ("zh-CN", "utwget.help_metalink_options", "Metalink 选项"),
        ("zh-CN", "utwget.help_metalink_over_http", "使用 HTTP 响应头中的 Metalink"),
        ("zh-CN", "utwget.help_input_metalink", "从 FILE 读取 Metalink"),
        ("zh-CN", "utwget.help_warc_options", "WARC 选项"),
        ("zh-CN", "utwget.help_warc_file", "将 WARC 保存到 FILENAME"),
        ("zh-CN", "utwget.help_warc_maxsize", "设置最大 WARC 文件大小为 NUMBER"),
        ("zh-CN", "utwget.help_warc_cdx", "写入 CDX 索引文件"),
        ("zh-CN", "utwget.help_warc_dedup", "不存储与 URL 匹配的记录"),
        ("zh-CN", "utwget.help_warc_compression", "启用 WARC 压缩"),
        ("zh-CN", "utwget.help_warc_digests", "启用 WARC 摘要"),
        ("zh-CN", "utwget.help_warc_keep_log", "在 WARC 中保留日志文件"),
        ("zh-CN", "utwget.help_warc_temp_dir", "WARC 文件的临时目录"),
        ("zh-CN", "utwget.help_warc_header", "添加自定义 WARC 头"),
        ("zh-CN", "utwget.help_email", "将 bug 报告、问题和讨论发送到 <bug-wget@gnu.org>。"),
    ];

    for &(loc, k, trans) in TRANSLATIONS {
        if loc == locale && k == key {
            return Some(trans);
        }
    }
    if locale != DEFAULT_LOCALE {
        for &(loc, k, trans) in TRANSLATIONS {
            if loc == DEFAULT_LOCALE && k == key {
                return Some(trans);
            }
        }
    }
    None
}

pub fn is_locale_supported(locale: &str) -> bool {
    SUPPORTED_LOCALES.contains(&locale)
}

pub fn get_supported_locales() -> &'static [&'static str] {
    SUPPORTED_LOCALES
}
