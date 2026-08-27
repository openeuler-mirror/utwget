//! utwget CLI entry point.
//!
//! This module contains the main entry point for the utwget command-line utility.
//! It handles argument parsing, configuration loading, and orchestrates the download
//! process by delegating to the `app` module.
//!
//! # Workflow
//!
//! 1. Rearrange command-line arguments to handle wget-style option placement
//! 2. Parse arguments into an `Args` structure
//! 3. Load configuration from wgetrc files
//! 4. Apply any `--execute` commands
//! 5. Run the download application

mod args;
mod app;
mod wgetrc;
mod i18n;
mod signal;
mod config_reload;

use std::process::ExitCode;

use clap::Parser;
use args::Args;

/// Rearrange command-line arguments to put options before URLs.
///
/// GNU wget allows options to appear anywhere on the command line, including after URLs.
/// This function reorders arguments so that all options come before all URLs, which
/// simplifies parsing with clap.
///
/// # Returns
///
/// A new `Vec<String>` containing the rearranged arguments, with the program name
/// first, followed by all options, then all URLs.
///
/// # Example
///
/// If the original command line is:
/// ```text
/// utwget http://example.com -O output.txt http://example.org
/// ```
///
/// The rearranged arguments will be:
/// ```text
/// utwget -O output.txt http://example.com http://example.org
/// ```
fn rearrange_args() -> Vec<String> {
    let original_args: Vec<String> = std::env::args().collect();

    // Expand compound short options to long forms
    // e.g., -nc -> --no-clobber, -nd -> --no-directories, -nv -> --no-verbose, etc.
    //
    // GNU wget's -n<char> combinator (main.c:1524-1555) iterates each
    // character after -n and applies "no-" semantics:
    //   v → --no-verbose,  H → --no-host-directories,
    //   d → --no-directories,  c → --no-clobber,  p → --no-parent
    //
    // We handle the common two-char forms here. Multi-char forms like
    // -nHcp are split into individual flags.
    let n_char_map: std::collections::HashMap<char, &str> = [
        ('v', "no-verbose"),
        ('H', "no-host-directories"),
        ('d', "no-directories"),
        ('c', "no-clobber"),
        ('p', "no-parent"),
    ].iter().copied().collect();

    // Also keep the old-style compound map for backward compat (e.g. -x)
    let compound_short_opts: std::collections::HashMap<&str, &str> = [
        ("x", "force-directories"),
    ].iter().copied().collect();

    let mut args: Vec<String> = Vec::new();
    for arg in &original_args {
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
            let short = &arg[1..];
            // Check the old-style compound map first (e.g. -x)
            if let Some(long_opt) = compound_short_opts.get(short) {
                args.push(format!("--{}", long_opt));
                continue;
            }
            // GNU wget -n<char> combinator: expand -nv, -nH, -nd, -nc, -np,
            // and multi-char forms like -nHcp into individual --no-XXX flags.
            if short.starts_with('n') && short.len() > 1 {
                let mut expanded = Vec::new();
                let mut all_known = true;
                for ch in short[1..].chars() {
                    if let Some(long_opt) = n_char_map.get(&ch) {
                        expanded.push(format!("--{}", long_opt));
                    } else {
                        all_known = false;
                        break;
                    }
                }
                if all_known {
                    args.extend(expanded);
                    continue;
                }
            }
        }
        args.push(arg.clone());
    }

    // Known short options that take a value
    let short_opts_with_value = [
        'e', 'o', 'a', 'i', 'B', 'l', 'O', 'P', 'Q', 'w', 't', 'T',
        'A', 'R', 'D', 'I', 'X', 'U', // Add more as needed
    ];

    // Known long options that take a value
    let long_opts_with_value = [
        "execute", "output-file", "append-output", "input-file", "base",
        "level", "output-document", "directory-prefix", "cut-dirs", "quota",
        "limit-rate", "wait", "waitretry", "tries", "timeout", "connect-timeout",
        "read-timeout", "dns-timeout", "start-pos", "progress", "report-speed",
        "config", "rejected-log", "retry-on-http-error", "accept", "reject",
        "domains", "exclude-domains", "include-directories", "exclude-directories",
        "follow-tags", "ignore-tags", "accept-regex", "reject-regex", "user-agent",
        "header", "post-data", "post-file", "method", "body-data", "body-file",
        "http-user", "http-password", "user", "password", "proxy-user", "proxy-password",
        "http-proxy", "https-proxy", "ftp-proxy", "no-proxy", "bind-address",
        "certificate", "private-key", "ca-certificate", "ca-directory", "crl-file",
        "pinnedpubkey", "secure-protocol", "ciphers", "ftp-user", "ftp-password",
        "load-cookies", "save-cookies", "hsts-file", "warc-file", "warc-max-size",
        "warc-cdx", "warc-dedup", "warc-tempdir", "warc-header", "referer",
        "local-encoding", "remote-encoding", "metalink", "default-page",
        "certificate-type", "private-key-type", "regex-type", "restrict-file-names",
        "use-askpass",
    ];

    let mut options: Vec<String> = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    let mut i = 1; // Skip program name

    while i < args.len() {
        let arg = &args[i];

        if arg.starts_with("--") {
            // Long option
            let opt_name = arg[2..].split('=').next().unwrap_or("");
            options.push(arg.clone());

            // Check if this option takes a value and wasn't provided with =
            if !arg.contains('=') && long_opts_with_value.contains(&opt_name) && i + 1 < args.len() {
                i += 1;
                options.push(args[i].clone());
            }
        } else if arg.starts_with('-') && arg.len() > 1 {
            // Short option
            // Safe because we checked arg.len() > 1
            let opt_char = arg.chars().nth(1).unwrap_or('-');
            options.push(arg.clone());

            // Check if this option takes a value
            if short_opts_with_value.contains(&opt_char) && i + 1 < args.len() && !args[i + 1].starts_with('-') {
                i += 1;
                options.push(args[i].clone());
            }
        } else {
            // URL
            urls.push(arg.clone());
        }

        i += 1;
    }

    // Combine: program name, then options, then URLs
    let mut result = vec![args[0].clone()];
    result.extend(options);
    result.extend(urls);

    // GNU wget auto-generates --no-FOO for every boolean option (main.c:540-548).
    // clap only accepts the --no-FOO forms we explicitly declared in args.rs.
    // For all other boolean options, preprocess --no-FOO → a hidden
    // --_no-foo flag that apply_args recognizes and converts to config.foo=false.
    // This avoids having to declare 35+ separate clap fields.
    let boolean_opts_needing_no: &[&str] = &[
        "recursive", "quiet", "debug", "background", "mirror", "timestamping",
        "continue", "page-requisites", "convert-links", "backup-converted",
        "convert-file-only", "delete-after", "content-disposition",
        "auth-no-challenge", "content-on-error", "save-headers",
        "https-only", "span-hosts", "relative", "protocol-directories",
        "force-directories", "retr-symlinks", "retry-connrefused",
        "retry-on-host-error", "spider", "strict-comments",
        "trust-server-names", "unlink", "xattr", "preserve-permissions",
        "backups", "follow-ftp", "show-progress", "keep-session-cookies",
        "parent", "clobber", "directories", "host-directories",
        "remove-listing", "glob", "passive-ftp", "check-certificate",
        "iri", "netrc", "cache", "use-server-timestamps",
        "if-modified-since", "cookies", "hsts", "dns-cache",
        "http-keep-alive", "compression",
    ];

    // --no-FOO already declared in args.rs (don't interfere with them)
    let existing_no_opts: std::collections::HashSet<&str> = [
        "no-cache", "no-check-certificate", "no-clobber", "no-compression",
        "no-config", "no-cookies", "no-directories", "no-dns-cache",
        "no-glob", "no-host-directories", "no-hsts", "no-http-keep-alive",
        "no-if-modified-since", "no-iri", "no-netrc", "no-parent",
        "no-passive-ftp", "no-proxy", "no-remove-listing",
        "no-use-server-timestamps", "no-verbose", "no-warc-compression",
        "no-warc-digests", "no-warc-keep-log",
    ].iter().copied().collect();

    let result: Vec<String> = result
        .iter()
        .map(|arg| {
            if let Some(rest) = arg.strip_prefix("--no-") {
                let opt_name = rest.split('=').next().unwrap_or("");
                // If this --no-FOO is already declared in args.rs, leave it.
                if existing_no_opts.contains(opt_name) {
                    return arg.clone();
                }
                // If --FOO is a known boolean option, convert to hidden flag
                if boolean_opts_needing_no.contains(&opt_name) {
                    return format!("--_no-{}", opt_name);
                }
            }
            arg.clone()
        })
        .collect();

    result
}

/// Main entry point for the utwget command-line utility.
///
/// This function orchestrates the entire download process:
///
/// 1. Creates debug files for troubleshooting
/// 2. Rearranges command-line arguments to handle wget-style option placement
/// 3. Initializes the logger
/// 4. Parses command-line arguments
/// 5. Handles `--version` and `--help` flags
/// 6. Loads configuration from wgetrc files
/// 7. Applies `--execute` commands
/// 8. Creates and runs the download application
///
/// # Returns
///
/// An `ExitCode` indicating success (0) or failure (1).
///
/// # Exit Codes
///
/// * `0` - All downloads completed successfully
/// * `1` - One or more downloads failed, or a configuration/parsing error occurred
fn main() -> ExitCode {
    // Initialize locale based on system language
    crate::i18n::init_locale();

    // Install signal handlers (SIGINT, SIGTERM, SIGHUP, SIGUSR1, SIGPIPE)
    // SAFETY: Signal handlers only set atomic flags, which is async-signal-safe.
    unsafe { crate::signal::install_signal_handlers(); }

    // Rearrange args to handle wget-style command line
    let rearranged = rearrange_args();

    // Initialize logger
    env_logger::init();

    let args = match Args::try_parse_from(&rearranged) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::from(2); // PARSE_ERROR
        }
    };

    if args.version {
        println!("utwget {}", env!("CARGO_PKG_VERSION"));
        println!("Rust 重构版 GNU Wget 1.21.4");
        println!();
        println!("特性支持:");
        println!("    +http +https +ftp +ftps");
        println!("    +cookies +auth-basic +auth-digest");

        // 动态显示可选特性
        let mut optional_features = Vec::new();
        #[cfg(feature = "hsts")]
        optional_features.push("+hsts");
        #[cfg(feature = "compression")]
        optional_features.push("+compression");
        #[cfg(feature = "metalink")]
        optional_features.push("+metalink");
        #[cfg(feature = "http2")]
        optional_features.push("+http2");
        #[cfg(feature = "auth-ntlm")]
        optional_features.push("+auth-ntlm");
        #[cfg(feature = "async")]
        optional_features.push("+async");

        if !optional_features.is_empty() {
            println!("    {}", optional_features.join(" "));
        }

        // WARC 总是可用
        println!("    +warc +iri +ipv6");
        println!();
        println!("编译信息:");
        println!("    rustc {} (target: {})", env!("RUSTC_VERSION"), env!("TARGET"));
        return ExitCode::SUCCESS;
    }

    if args.help || args.help_short {
        print_wget_help();
        return ExitCode::SUCCESS;
    }

    // First, load wgetrc files to get defaults
    let mut config = ut_core::Config::default();
    let config_paths = load_wgetrc_paths(&args);
    for path in &config_paths {
        if path.exists() {
            match wgetrc::WgetrcParser::parse(path) {
                Ok(commands) => {
                    if let Err(e) = wgetrc::WgetrcParser::apply(&commands, &mut config) {
                        eprintln!("utwget: warning: error applying {}: {}", path.display(), e);
                    }
                }
                Err(e) => {
                    eprintln!("utwget: warning: error reading {}: {}", path.display(), e);
                }
            }
        }
    }

    // Then apply command-line arguments (they override wgetrc)
    app::apply_args(&mut config, &args);

    // Redirect diagnostic output to -o/-a log file as early as possible so
    // every subsequent message (including those from apply_args/askpass) goes
    // to the log. CLI flags override wgetrc values, matching GNU wget.
    let log_target = args.output_file.clone()
        .or(args.append_output.clone())
        .or(config.output_file.clone())
        .or(config.append_output.clone());
    let log_append = args.append_output.is_some() || config.append_output.is_some();
    if let Some(ref target) = log_target {
        if let Err(e) = redirect_log_output(target, log_append) {
            eprintln!("utwget: {}", e);
            return ExitCode::from(1);
        }
    }

    if !args.execute.is_empty() {
        app::apply_execute_commands(&mut config, &args.execute);
    }

    // Daemonize if --background is set
    if config.background {
        // GNU wget validates URLs before backgrounding so that errors like
        // "no URLs specified" are visible on the terminal, not swallowed by
        // the daemon's /dev/null.
        if args.urls.is_empty()
            && config.input_filename.is_none()
            && args.input_file.is_none()
        {
            eprintln!("utwget: 缺少 URL");
            return ExitCode::from(1);
        }

        // If -o/-a redirected stderr to a log file, keep that redirection in
        // the daemon.  Otherwise, create a default "wget-log" file (GNU wget
        // behavior) and redirect output there.
        let keep_log = config.output_file.is_some() || config.append_output.is_some();
        if !keep_log {
            // GNU wget defaults to "wget-log" in the current directory.
            let default_log = std::path::PathBuf::from("wget-log");
            if let Err(e) = redirect_log_output(&default_log, false) {
                eprintln!("utwget: {}", e);
                return ExitCode::from(1);
            }
        }

        // Print background message to the *original* stderr before forking.
        // After fork+setsid the child loses the terminal, so this must happen
        // in the parent before the fork returns.
        // (The actual message is printed by the parent below.)
        match daemonize(false) {
            Ok(child_pid) if child_pid > 0 => {
                // Parent process: child has been forked off.
                eprintln!("Continuing in background, pid {}.", child_pid);
                if !keep_log {
                    eprintln!("Output will be written to 'wget-log'.");
                }
                return ExitCode::SUCCESS;
            }
            Ok(_) => {
                // Child (daemon) process — continue with the download.
                // Signal handlers were already reinstalled inside daemonize().
            }
            Err(e) => {
                eprintln!("utwget: unable to daemonize: {}", e);
                return ExitCode::from(1);
            }
        }
    }

    match app::App::new(config) {
        Ok(mut app) => {
            let result = app.run(&args.urls);
            // Persist cookies and HSTS regardless of whether the run succeeded.
            app.save_state();
            match result {
                Ok(status) => ExitCode::from(status.to_exit_code()),
                Err(e) => {
                    eprintln!("utwget: {}", e);
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("utwget: {}", e);
            ExitCode::from(1)
        }
    }
}

/// Determine the paths to wgetrc configuration files.
///
/// Returns a prioritized list of configuration file paths to load. The order is:
///
/// 1. `$SYSTEMRC` or `/etc/wgetrc` - system-wide configuration
/// 2. `$WGETRC` or `~/.wgetrc` - user-specific configuration
/// 3. Custom config file specified via `--config` argument
///
/// `$WGETRC` overrides `~/.wgetrc` (GNU wget init.c:575-590). If `$WGETRC`
/// points to a non-existent file, GNU wget prints an error and exits.
///
/// # Arguments
///
/// * `args` - The parsed command-line arguments
///
/// # Returns
///
/// A vector of `PathBuf` objects representing the configuration file paths.
/// Not all paths may exist; the caller should check for existence before reading.
fn load_wgetrc_paths(args: &Args) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    // --no-config: skip all configuration files (matches GNU wget behavior)
    if args.no_config {
        return paths;
    }

    // System wgetrc: $SYSTEMRC env var overrides the default /etc/wgetrc
    // (GNU wget init.c:754)
    let system_rc = std::env::var_os("SYSTEMRC")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/wgetrc"));
    paths.push(system_rc);

    // User wgetrc: $WGETRC overrides ~/.wgetrc (GNU wget init.c:575-590)
    if let Some(wgetrc) = std::env::var_os("WGETRC") {
        let path = std::path::PathBuf::from(wgetrc);
        if !path.exists() {
            eprintln!("utwget: WGETRC points to {:?} which does not exist", path);
            std::process::exit(1);
        }
        paths.push(path);
    } else if let Some(home) = std::env::var_os("HOME") {
        paths.push(std::path::PathBuf::from(home).join(".wgetrc"));
    }

    if let Some(ref config_file) = args.config_file {
        paths.push(config_file.clone());
    }

    paths
}

/// Print help message in wget-compatible format.
///
/// Outputs a comprehensive help message that matches the format and content of
/// GNU wget 1.21.4's `--help` output. This ensures script compatibility and
/// familiar user experience for users migrating from GNU wget.
///
/// The help text is organized into the following sections:
///
/// * Startup - version, help, background, execute
/// * Logging and input file - output redirection, verbosity, input sources
/// * Download - retry, timeout, quota, rate limiting
/// * Directories - directory creation and naming
/// * HTTP options - authentication, headers, cookies
/// * HTTPS (SSL/TLS) options - certificates, protocols, ciphers
/// * HSTS options - HTTP Strict Transport Security
/// * FTP options - authentication, transfer mode
/// * FTPS options - FTP over SSL/TLS
/// * WARC options - Web ARChive format
/// * Recursive download - crawling, depth, conversion
/// * Recursive accept/reject - filtering patterns
/// * Metalink options - Metalink download support
fn print_wget_help() {
    let t = |key: &str| crate::i18n::translate(key);

    println!("{}", t("utwget.version"));
    println!("{}", t("utwget.help_usage"));
    println!();
    println!("{}", t("utwget.help_mandatory"));
    println!();

    println!("{}:", t("utwget.help_startup"));
    println!("  -V,  --version                   {}", t("utwget.help_version"));
    println!("  -h,  --help                      {}", t("utwget.help_help"));
    println!("  -b,  --background                {}", t("utwget.help_background"));
    println!("  -e,  --execute=COMMAND           {}", t("utwget.help_execute"));
    println!();

    println!("{}:", t("utwget.help_logging"));
    println!("  -o,  --output-file=FILE          {}", t("utwget.help_output_file"));
    println!("  -a,  --append-output=FILE        {}", t("utwget.help_append_output"));
    println!("  -d,  --debug                     {}", t("utwget.help_debug"));
    println!("  -q,  --quiet                     {}", t("utwget.help_quiet"));
    println!("  -v,  --verbose                   {}", t("utwget.help_verbose"));
    println!("  -nv, --no-verbose                {}", t("utwget.help_no_verbose"));
    println!("       --report-speed=TYPE         {}", t("utwget.help_report_speed"));
    println!("  -i,  --input-file=FILE           {}", t("utwget.help_input_file"));
    println!("  -F,  --force-html                {}", t("utwget.help_force_html"));
    println!("  -B,  --base=URL                  {}", t("utwget.help_base"));
    println!("       --config=FILE               {}", t("utwget.help_config"));
    println!("       --no-config                 {}", t("utwget.help_no_config"));
    println!("       --rejected-log=FILE         {}", t("utwget.help_rejected_log"));
    println!();

    println!("{}:", t("utwget.help_download"));
    println!("  -t,  --tries=NUMBER              {}", t("utwget.help_tries"));
    println!("       --retry-connrefused         {}", t("utwget.help_retry_connrefused"));
    println!("       --retry-on-host-error       {}", t("utwget.help_retry_on_host_error"));
    println!("       --retry-on-http-error=ERRORS    {}", t("utwget.help_retry_on_http_error"));
    println!("  -O,  --output-document=FILE      {}", t("utwget.help_output_document"));
    println!("  -nc, --no-clobber                {}", t("utwget.help_no_clobber"));
    println!("       --no-netrc                  {}", t("utwget.help_no_netrc"));
    println!("  -c,  --continue                  {}", t("utwget.help_continue"));
    println!("       --start-pos=OFFSET          {}", t("utwget.help_start_pos"));
    println!("       --progress=TYPE             {}", t("utwget.help_progress"));
    println!("       --show-progress             {}", t("utwget.help_show_progress"));
    println!("  -N,  --timestamping              {}", t("utwget.help_timestamping"));
    println!("  -S,  --server-response           {}", t("utwget.help_server_response"));
    println!("       --spider                    {}", t("utwget.help_spider"));
    println!("  -T,  --timeout=SECONDS           {}", t("utwget.help_timeout"));
    println!("       --connect-timeout=SECS      {}", t("utwget.help_connect_timeout"));
    println!("       --read-timeout=SECS         {}", t("utwget.help_read_timeout"));
    println!("       --dns-timeout=SECS          {}", t("utwget.help_dns_timeout"));
    println!("  -w,  --wait=SECONDS              {}", t("utwget.help_wait"));
    println!("       --waitretry=SECONDS         {}", t("utwget.help_waitretry"));
    println!("       --random-wait               {}", t("utwget.help_random_wait"));
    println!("       --no-proxy                  {}", t("utwget.help_no_proxy"));
    println!("  -4,  --inet4-only                {}", t("utwget.help_inet4_only"));
    println!("  -6,  --inet6-only                {}", t("utwget.help_inet6_only"));
    println!("       --proxy-user=USER           {}", t("utwget.help_proxy_user"));
    println!("       --proxy-password=PASS       {}", t("utwget.help_proxy_password"));
    println!("  -Q,  --quota=NUMBER              {}", t("utwget.help_quota"));
    println!("       --limit-rate=RATE           {}", t("utwget.help_limit_rate"));
    println!("       --delete-after              {}", t("utwget.help_delete_after"));
    println!("       --content-disposition       {}", t("utwget.help_content_disposition"));
    println!("       --auth-no-challenge          {}", t("utwget.help_auth_no_challenge"));
    println!("       --ask-password              {}", t("utwget.help_ask_password"));
    println!("       --use-askpass=PROGRAM       {}", t("utwget.help_use_askpass"));
    println!("       --trust-server-names         {}", t("utwget.help_trust_server_names"));
    println!("       --unlink                    {}", t("utwget.help_unlink"));
    println!("       --xattr                     {}", t("utwget.help_xattr"));
    println!("       --preserve-permissions      {}", t("utwget.help_preserve_permissions"));
    println!("       --backups                   {}", t("utwget.help_backups"));
    println!("       --bind-address=ADDRESS      {}", t("utwget.help_bind_address"));
    println!("       --no-dns-cache              {}", t("utwget.help_no_dns_cache"));
    println!("       --restrict-file-names=MODES {}", t("utwget.help_restrict_file_names"));
    println!("       --prefer-family=ADDRESS     {}", t("utwget.help_prefer_family"));
    println!();
    println!("{}:", t("utwget.help_directories"));
    println!("  -nd, --no-directories            {}", t("utwget.help_no_directories"));
    println!("  -x,  --force-directories         {}", t("utwget.help_force_directories"));
    println!("  -nH, --no-host-directories       {}", t("utwget.help_no_host_directories"));
    println!("       --protocol-directories      {}", t("utwget.help_protocol_directories"));
    println!("  -P,  --directory-prefix=PREFIX   {}", t("utwget.help_directory_prefix"));
    println!("       --cut-dirs=NUMBER           {}", t("utwget.help_cut_dirs"));
    println!();

    println!("{}:", t("utwget.help_http_options"));
    println!("       --user=USER                  {}", t("utwget.help_user"));
    println!("       --password=PASS              {}", t("utwget.help_password"));
    println!("       --http-user=USER            {}", t("utwget.help_http_user"));
    println!("       --http-password=PASS        {}", t("utwget.help_http_password"));
    println!("       --no-cache                  {}", t("utwget.help_no_cache"));
    println!("  -E,  --adjust-extension          {}", t("utwget.help_adjust_extension"));
    println!("       --header=STRING             {}", t("utwget.help_header"));
    println!("       --compression=TYPE          {}", t("utwget.help_compression"));
    println!("  -U,  --user-agent=AGENT          {}", t("utwget.help_user_agent"));
    println!("       --no-cookies                {}", t("utwget.help_no_cookies"));
    println!("       --load-cookies=FILE         {}", t("utwget.help_load_cookies"));
    println!("       --save-cookies=FILE         {}", t("utwget.help_save_cookies"));
    println!("       --keep-session-cookies      {}", t("utwget.help_keep_session_cookies"));
    println!("       --post-data=STRING          {}", t("utwget.help_post_data"));
    println!("       --post-file=FILE            {}", t("utwget.help_post_file"));
    println!("       --method=METHOD             {}", t("utwget.help_method"));
    println!("       --body-data=STRING          {}", t("utwget.help_body_data"));
    println!("       --body-file=FILE            {}", t("utwget.help_body_file"));
    println!("       --content-on-error          {}", t("utwget.help_content_on_error"));
    println!("       --save-headers              {}", t("utwget.help_save_headers"));
    println!("       --ignore-length             {}", t("utwget.help_ignore_length"));
    println!("       --max-redirect=NUM          {}", t("utwget.help_max_redirect"));
    println!("       --follow-tags=LIST          {}", t("utwget.help_follow_tags"));
    println!("       --ignore-tags=LIST          {}", t("utwget.help_ignore_tags"));
    println!("       --default-page=NAME         {}", t("utwget.help_default_page"));
    println!("       --no-http-keep-alive        {}", t("utwget.help_no_http_keep_alive"));
    println!("       --no-if-modified-since      {}", t("utwget.help_no_if_modified_since"));
    println!("       --no-use-server-timestamps  {}", t("utwget.help_no_use_server_timestamps"));
    println!("       --referer=URL               {}", t("utwget.help_referer"));
    println!("       --local-encoding=ENC        {}", t("utwget.help_local_encoding"));
    println!("       --remote-encoding=ENC       {}", t("utwget.help_remote_encoding"));
    println!("       --no-iri                    {}", t("utwget.help_no_iri"));
    println!();

    println!("{}:", t("utwget.help_https_options"));
    println!("       --secure-protocol=PR        {}", t("utwget.help_secure_protocol"));
    println!("       --https-only                {}", t("utwget.help_https_only"));
    println!("       --no-check-certificate      {}", t("utwget.help_no_check_certificate"));
    println!("       --certificate=FILE          {}", t("utwget.help_certificate"));
    println!("       --ca-certificate=FILE       {}", t("utwget.help_ca_certificate"));
    println!("       --ca-directory=DIR          {}", t("utwget.help_ca_directory"));
    println!("       --crl-file=FILE             {}", t("utwget.help_crl_file"));
    println!("       --ciphers=STR               {}", t("utwget.help_ciphers"));
    println!("       --pinnedpubkey=FILE         {}", t("utwget.help_pinnedpubkey"));
    println!("       --private-key=FILE          {}", t("utwget.help_private_key"));
    println!("       --private-key-type=TYPE     {}", t("utwget.help_private_key_type"));
    println!("       --certificate-type=TYPE     {}", t("utwget.help_certificate_type"));
    println!();

    println!("{}:", t("utwget.help_hsts_options"));
    println!("       --no-hsts                   {}", t("utwget.help_no_hsts"));
    println!("       --hsts-file=FILE            {}", t("utwget.help_hsts_file"));
    println!();

    println!("{}:", t("utwget.help_ftp_options"));
    println!("       --ftp-user=USER             {}", t("utwget.help_ftp_user"));
    println!("       --ftp-password=PASS         {}", t("utwget.help_ftp_password"));
    println!("       --no-remove-listing         {}", t("utwget.help_no_remove_listing"));
    println!("       --no-glob                   {}", t("utwget.help_no_glob"));
    println!("       --no-passive-ftp            {}", t("utwget.help_no_passive_ftp"));
    println!("       --retr-symlinks             {}", t("utwget.help_retr_symlinks"));
    println!("       --ftps-implicit             {}", t("utwget.help_ftps_implicit"));
    println!("       --ftps-resume-ssl           {}", t("utwget.help_ftps_resume_ssl"));
    println!("       --ftps-clear-data-connection {}", t("utwget.help_ftps_clear_data_connection"));
    println!("       --ftps-fallback-to-ftp      {}", t("utwget.help_ftps_fallback_to_ftp"));
    println!();

    println!("{}:", t("utwget.help_recursive_download"));
    println!("  -r,  --recursive                 {}", t("utwget.help_recursive"));
    println!("  -l,  --level=NUMBER              {}", t("utwget.help_level"));
    println!("  -k,  --convert-links             {}", t("utwget.help_convert_links"));
    println!("  -K,  --backup-converted          {}", t("utwget.help_backup_converted"));
    println!("  -m,  --mirror                    {}", t("utwget.help_mirror"));
    println!("  -p,  --page-requisites           {}", t("utwget.help_page_requisites"));
    println!("       --strict-comments           {}", t("utwget.help_strict_comments"));
    println!("       --convert-file-only         {}", t("utwget.help_convert_file_only"));
    println!();

    println!("{}:", t("utwget.help_recursive_accept"));
    println!("  -A,  --accept=LIST               {}", t("utwget.help_accept"));
    println!("  -R,  --reject=LIST               {}", t("utwget.help_reject"));
    println!("       --accept-regex=REGEX        {}", t("utwget.help_accept_regex"));
    println!("       --reject-regex=REGEX        {}", t("utwget.help_reject_regex"));
    println!("  -D,  --domains=LIST              {}", t("utwget.help_domains"));
    println!("       --exclude-domains=LIST      {}", t("utwget.help_exclude_domains"));
    println!("       --follow-ftp                {}", t("utwget.help_follow_ftp"));
    println!("  -H,  --span-hosts                {}", t("utwget.help_span_hosts"));
    println!("  -L,  --relative                  {}", t("utwget.help_relative"));
    println!("  -I,  --include-directories=LIST  {}", t("utwget.help_include_directories"));
    println!("  -X,  --exclude-directories=LIST  {}", t("utwget.help_exclude_directories"));
    println!("  -np, --no-parent                 {}", t("utwget.help_no_parent"));
    println!("       --robots                    {}", t("utwget.help_robots"));
    println!("       --regex-type=TYPE           {}", t("utwget.help_regex_type"));
    println!("       --ignore-case               {}", t("utwget.help_ignore_case"));
    println!();

    println!("{}:", t("utwget.help_metalink_options"));
    println!("       --metalink-over-http        {}", t("utwget.help_metalink_over_http"));
    println!("       --input-metalink=FILE       {}", t("utwget.help_input_metalink"));
    println!();

    println!("{}:", t("utwget.help_warc_options"));
    println!("       --warc-file=FILENAME        {}", t("utwget.help_warc_file"));
    println!("       --warc-max-size=NUMBER      {}", t("utwget.help_warc_maxsize"));
    println!("       --warc-cdx                  {}", t("utwget.help_warc_cdx"));
    println!("       --warc-dedup=URL            {}", t("utwget.help_warc_dedup"));
    println!("       --warc-compression          {}", t("utwget.help_warc_compression"));
    println!("       --warc-digests              {}", t("utwget.help_warc_digests"));
    println!("       --warc-keep-log             {}", t("utwget.help_warc_keep_log"));
    println!("       --warc-tempdir=DIR          {}", t("utwget.help_warc_temp_dir"));
    println!("       --warc-header=STRING        {}", t("utwget.help_warc_header"));
    println!();

    println!("{}", t("utwget.help_email"));
}

/// Redirect process logging to a file specified by `-o`/`-a`.
///
/// GNU wget routes all diagnostic output through a single log file pointer.
/// We achieve the same effect by redirecting the process's stderr file
/// descriptor to the target file with `dup2`, so that every `eprintln!`
/// and `log` message flows into it automatically — no call-site changes
/// are required.
///
/// * `-o FILE`  — truncate FILE and write logs there.
/// * `-a FILE`  — append logs to FILE.
/// * `-o -`     — write logs to stdout (matching GNU wget).
///
/// When neither is set, stderr is left untouched. This must run before
/// `daemonize()` so the daemon inherits the redirected descriptor.
fn redirect_log_output(file: &std::path::Path, append: bool) -> Result<(), Box<dyn std::error::Error>> {
    // `-o -` (or `-a -`) routes logs to stdout.
    if file == std::path::Path::new("-") {
        // dup2(stdout, stderr) so eprintln!/log go to stdout.
        unsafe {
            if libc::dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO) < 0 {
                return Err("failed to redirect stderr to stdout".into());
            }
        }
        return Ok(());
    }

    let flags = libc::O_WRONLY | libc::O_CREAT | if append { libc::O_APPEND } else { libc::O_TRUNC };
    let fd = unsafe {
        let c_path = std::ffi::CString::new(file.as_os_str().as_encoded_bytes())
            .map_err(|e| format!("invalid log path: {e}"))?;
        libc::open(c_path.as_ptr(), flags, 0o600)
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("cannot open log file {}: {}", file.display(), err).into());
    }

    // Redirect stderr to the log file. If stdout is not already the log
    // file, leave it untouched (downloaded content via `-O -` uses stdout).
    unsafe {
        if libc::dup2(fd, libc::STDERR_FILENO) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("failed to redirect stderr to {}: {}", file.display(), err).into());
        }
        if fd > libc::STDERR_FILENO {
            libc::close(fd);
        }
    }
    Ok(())
}

/// Daemonize the process by forking and creating a new session.
///
/// Returns `Ok(child_pid)` in the parent process (should exit after
/// printing the background message), or `Err` on failure.  The child
/// process never returns from this function — it continues execution
/// as the daemon after the double-fork completes.
///
/// This follows the classic Unix double-fork pattern:
/// 1. Fork first time - parent returns with child PID, child continues
/// 2. Call setsid() to create new session
/// 3. Fork second time - first child exits, grandchild continues
/// 4. Redirect stdin/stdout/stderr to /dev/null
///
/// `redirect_stderr_to_null` controls whether stderr is sent to /dev/null.
/// When `-o`/`-a` or the default `wget-log` has already redirected stderr
/// to a log file, pass `false` to preserve that redirection.
fn daemonize(redirect_stderr_to_null: bool) -> Result<i32, Box<dyn std::error::Error>> {
    // First fork
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("fork failed".into());
    }
    if pid > 0 {
        // Parent process - return child PID so caller can print message.
        return Ok(pid as i32);
    }

    // Child process - create new session
    let sid = unsafe { libc::setsid() };
    if sid < 0 {
        return Err("setsid failed".into());
    }

    // Second fork (prevent the daemon from acquiring a controlling terminal)
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("second fork failed".into());
    }
    if pid > 0 {
        // First child - exit
        unsafe { libc::_exit(0); }
    }

    // Grandchild (daemon) process — redirect stdin/stdout/stderr to /dev/null
    unsafe {
        let devnull = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::dup2(devnull, libc::STDOUT_FILENO);
            // Only redirect stderr to /dev/null when no log file (-o/-a)
            // was set up; otherwise keep the log-file redirection.
            if redirect_stderr_to_null {
                libc::dup2(devnull, libc::STDERR_FILENO);
            }
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }

    // Reinstall signal handlers in the daemon process.
    unsafe { crate::signal::install_signal_handlers(); }

    // Return a sentinel PID (0) — the child never actually reaches this
    // return because the parent already returned above.  This is just to
    // satisfy the type system; the function effectively "diverges" here.
    // In practice, the child continues execution from the caller's match.
    Ok(0)
}
