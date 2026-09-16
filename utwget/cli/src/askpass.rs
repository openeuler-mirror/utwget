//! Password acquisition: interactive prompt and --use-askpass helpers.
//!
//! Extracted from the monolithic `app.rs` (arch review 3.2): self-contained
//! credential-input helpers with no App dependencies.

/// Prompt for password interactively from terminal.
///
/// Disables terminal echo on Unix platforms so the password is not displayed
/// as it is typed. Falls back to normal (echoing) input if terminal attributes
/// cannot be changed.
///
/// # Arguments
/// * `prompt` — The prompt string to display (e.g. "Password for user: ").
///
/// # Returns
/// The entered password, or `None` if input could not be read.
pub(crate) fn prompt_password(prompt: &str) -> Option<String> {
    use std::io::Write;

    // Write prompt to stderr
    let _ = std::io::stderr().write_all(prompt.as_bytes());
    let _ = std::io::stderr().flush();

    // Read password from stdin (without echo if possible)
    #[cfg(unix)]
    {
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        // Get current terminal attributes
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut term) } == 0 {
            // Disable echo
            let original_lflag = term.c_lflag;
            term.c_lflag &= !libc::ECHO;
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term) };

            let mut password = String::new();
            let result = std::io::stdin().read_line(&mut password);

            // Re-enable echo
            term.c_lflag = original_lflag;
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term) };

            // Print newline since echo was disabled
            let _ = std::io::stderr().write_all(b"\n");

            if result.is_ok() {
                return Some(password.trim().to_string());
            }
        }
    }

    // Fallback: read normally (echo will be visible)
    let mut password = String::new();
    if std::io::stdin().read_line(&mut password).is_ok() {
        Some(password.trim().to_string())
    } else {
        None
    }
}

/// Run external askpass program to get password.
///
/// Executes the askpass program and captures its stdout as the password.
/// The prompt string is passed as the first argument, matching GNU wget's
/// behavior (`argv[1] = question`).
///
/// # Arguments
/// * `program` — Path or name of the askpass executable.
/// * `prompt` — The prompt/question string passed to the program.
///
/// # Returns
/// The password text returned by the program, or `None` if the program could
/// not be run or returned a non-zero exit code.
pub(crate) fn run_askpass(program: &str, prompt: &str) -> Option<String> {
    use std::process::Command;

    let result = Command::new(program)
        .arg(prompt)
        .output()
        .ok()?;

    if result.status.success() {
        let password = String::from_utf8_lossy(&result.stdout);
        Some(password.trim().to_string())
    } else {
        None
    }
}

/// Resolve the askpass program and prompt string.
///
/// Implements GNU wget's `--use-askpass` resolution order:
/// 1. If `--use-askpass=COMMAND` was given an explicit value, use it.
/// 2. Otherwise, fall back to the `WGET_ASKPASS` environment variable.
/// 3. Then fall back to the `SSH_ASKPASS` environment variable.
///
/// Returns `Some(program)` if a program was resolved, or `None` (after
/// printing an error) if none of the sources yielded a value.
pub(crate) fn resolve_askpass(explicit: Option<&str>) -> Option<String> {
    if let Some(cmd) = explicit {
        if !cmd.is_empty() {
            return Some(cmd.to_string());
        }
    }
    if let Some(cmd) = std::env::var_os("WGET_ASKPASS") {
        if !cmd.is_empty() {
            return cmd.to_string_lossy().into_owned().into();
        }
    }
    if let Some(cmd) = std::env::var_os("SSH_ASKPASS") {
        if !cmd.is_empty() {
            return cmd.to_string_lossy().into_owned().into();
        }
    }
    eprintln!("use-askpass requires a string or either environment variable WGET_ASKPASS or SSH_ASKPASS to be set.");
    None
}
