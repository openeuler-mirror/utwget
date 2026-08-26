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
