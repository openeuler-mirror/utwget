use std::process::Command;
use std::path::PathBuf;

fn utwget_bin() -> PathBuf {
    let release = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/release/utwget");
    if release.exists() {
        release
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug/utwget")
    }
}

#[test]
fn output_file_captures_stderr() {
    // A connection to a port with no listener produces diagnostic output
    // (resolve/connect messages). With -o, these must land in the log file,
    // not the terminal. We use --tries=1 --timeout=1 to keep it quick.
    let tmp = std::env::temp_dir().join("utwget_log_test_out.txt");
    let _ = std::fs::remove_file(&tmp);

    let _ = Command::new(utwget_bin())
        .args(["--tries=1", "--timeout=2", "-o"])
        .arg(&tmp)
        .arg("http://127.0.0.1:1/nope")
        .output()
        .expect("failed to run utwget");

    let log_content = std::fs::read_to_string(&tmp).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    // The resolve/connect messages should be in the log file.
    assert!(!log_content.is_empty(), "log file should not be empty");
    assert!(log_content.contains("127.0.0.1") || log_content.contains("连接"),
        "log should contain connection info: got {log_content}");
}

#[test]
fn append_output_preserves_existing() {
    let tmp = std::env::temp_dir().join("utwget_log_test_append.txt");
    let _ = std::fs::remove_file(&tmp);
    std::fs::write(&tmp, "PREEXISTING\n").unwrap();

    let _ = Command::new(utwget_bin())
        .args(["--tries=1", "--timeout=2", "-a"])
        .arg(&tmp)
        .arg("http://127.0.0.1:1/nope")
        .output()
        .expect("failed to run utwget");

    let content = std::fs::read_to_string(&tmp).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    // Pre-existing content must survive (append, not truncate).
    assert!(content.starts_with("PREEXISTING"),
        "append should preserve existing content: got {content}");
}

#[test]
fn no_log_flag_leaves_stderr_alone() {
    // Without -o/-a, behavior is unchanged; we just ensure it doesn't crash.
    let output = Command::new(utwget_bin())
        .args(["--help"])
        .output()
        .expect("failed to run utwget");
    assert!(output.status.success());
    assert!(!output.stdout.is_empty(), "help should print to stdout");
}
