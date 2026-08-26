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
