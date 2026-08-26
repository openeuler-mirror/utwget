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

    // Known short options that take a value
    let short_opts_with_value = [
        'e', 'o', 'a', 'i', 'B', 'l', 'O', 'P', 'Q', 'w', 't', 'T',
        'A', 'R', 'D', 'I', 'X', 'U', 'S', // Add more as needed
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
        "load-cookies", "save-cookies", "hsts-file", "warc-file", "warc-maxsize",
        "warc-cdx", "warc-dedup", "warc-temp-dir", "warc-header", "referer",
        "local-encoding", "remote-encoding", "metalink", "default-page",
        "certificate-type", "private-key-type", "regex-type", "restrict-file-names",
        "use-askpass",
    ];

    let mut options: Vec<String> = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    let mut i = 1; // Skip program name

    while i < original_args.len() {
        let arg = &original_args[i];

        if arg.starts_with("--") {
            // Long option
            let opt_name = arg[2..].split('=').next().unwrap_or("");
            options.push(arg.clone());

            // Check if this option takes a value and wasn't provided with =
            if !arg.contains('=') && long_opts_with_value.contains(&opt_name) && i + 1 < original_args.len() {
                i += 1;
                options.push(original_args[i].clone());
            }
        } else if arg.starts_with('-') && arg.len() > 1 {
            // Short option
            let opt_char = arg.chars().nth(1).unwrap();
            options.push(arg.clone());

            // Check if this option takes a value
            if short_opts_with_value.contains(&opt_char) && i + 1 < original_args.len() && !original_args[i + 1].starts_with('-') {
                i += 1;
                options.push(original_args[i].clone());
            }
        } else {
            // URL
            urls.push(arg.clone());
        }

        i += 1;
    }

    // Combine: program name, then options, then URLs
    let mut result = vec![original_args[0].clone()];
    result.extend(options);
    result.extend(urls);
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
        println!("GNU Wget 1.21.4 built on linux-gnu.\n");
        println!("+cares +digest +gpgme +https +ipv6 +iri +large-file +metalink +nls\n+ntlm +opie +psl +ssl/openssl");
        println!();
        println!("Wgetrc:\n    /etc/wgetrc (system)\n");
        println!("Locale:\n    /usr/share/locale\n");
        println!("Compile:\n    gcc -DHAVE_CONFIG_H -DSYSTEM_WGETRC=\\\"/etc/wgetrc\\\"\n    -DLOCALEDIR=\\\"/usr/share/locale\\\" -I. -I../lib -I../lib\n    -DHAVE_LIBSSL -DNDEBUG -g -O2\n");
        println!("Link:\n    gcc -g -O2 -o wget ftp.o css.o html-parse.o ...\n    -lssl -lcrypto -lz -lidn2 -lpsl\n    -lnghttp2 -lssh2 -lmetalink -lexpat\n");
        return ExitCode::SUCCESS;
    }

    if args.help || args.help_short {
        print_wget_help();
        return ExitCode::SUCCESS;
    }

    let mut config = app::build_config(&args);

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

    if !args.execute.is_empty() {
        app::apply_execute_commands(&mut config, &args.execute);
    }

    // Daemonize if --background is set
    if config.background {
        match daemonize() {
            Ok(true) => {
                // Parent process after successful fork - exit immediately
                return ExitCode::SUCCESS;
            }
            Ok(false) => {
                // Child process - continue with download
                // Reinstall signal handlers in child process
                unsafe { crate::signal::install_signal_handlers(); }
            }
            Err(e) => {
                eprintln!("utwget: unable to daemonize: {}", e);
                return ExitCode::from(1);
            }
        }
    }

    match app::App::new(config) {
        Ok(mut app) => match app.run(&args.urls) {
            Ok(status) => ExitCode::from(status.to_exit_code()),
            Err(e) => {
                eprintln!("utwget: {}", e);
                ExitCode::from(1)
            }
        },
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
/// 1. `/etc/wgetrc` - system-wide configuration
/// 2. `~/.wgetrc` - user-specific configuration (if `HOME` environment variable is set)
/// 3. Custom config file specified via `--config` argument
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

    paths.push(std::path::PathBuf::from("/etc/wgetrc"));

    if let Some(home) = std::env::var_os("HOME") {
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
    println!("  -j,  --concurrency=NUMBER        {}", t("utwget.help_concurrency"));
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
    println!("       --http2                     {}", t("utwget.help_http2"));
    println!("       --http1.1                   {}", t("utwget.help_http1_1"));
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
    println!("       --reject-tags=LIST          {}", t("utwget.help_reject_tags"));
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
    println!("       --warc-maxsize=NUMBER       {}", t("utwget.help_warc_maxsize"));
    println!("       --warc-cdx                  {}", t("utwget.help_warc_cdx"));
    println!("       --warc-dedup=URL            {}", t("utwget.help_warc_dedup"));
    println!("       --warc-compression          {}", t("utwget.help_warc_compression"));
    println!("       --warc-digests              {}", t("utwget.help_warc_digests"));
    println!("       --warc-keep-log             {}", t("utwget.help_warc_keep_log"));
    println!("       --warc-temp-dir=DIR         {}", t("utwget.help_warc_temp_dir"));
    println!("       --warc-header=STRING        {}", t("utwget.help_warc_header"));
    println!();

    println!("{}", t("utwget.help_email"));
}
