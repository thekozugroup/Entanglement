//! CLI integration tests for the `entangle compute` subcommand.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    cmd
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `entangle compute dispatch --help` must list all expected flags.
#[test]
fn compute_dispatch_help_lists_all_flags() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["compute", "dispatch", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("integrity"))
        .stdout(predicate::str::contains("replicas"))
        .stdout(predicate::str::contains("allow"))
        .stdout(predicate::str::contains("timeout-ms"))
        .stdout(predicate::str::contains("cpu-cores"))
        .stdout(predicate::str::contains("memory-bytes"))
        .stdout(predicate::str::contains("gpu"))
        .stdout(predicate::str::contains("--raw"))
        .stdout(predicate::str::contains("--output-file"));
}

/// Without a daemon running (and without --allow-local), `compute dispatch`
/// must fail with a clear error message.
#[test]
fn compute_dispatch_with_no_daemon_errors_clearly() {
    let tmp = TempDir::new().unwrap();
    // Point the socket at a path that will never exist.
    entangle(&tmp)
        .args(["compute", "dispatch", "pub/nonexistent@0.1.0"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("daemon not running")
                .or(predicate::str::contains("not running")),
        );
}

/// The `compute` subcommand itself should require a subcommand.
#[test]
fn compute_subcommand_required() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp).arg("compute").assert().failure();
}

/// `entangle compute --help` should mention dispatch.
#[test]
fn compute_help_mentions_dispatch() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["compute", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dispatch"));
}

#[test]
fn invalid_resource_requests_are_rejected_before_submission() {
    let home = TempDir::new().unwrap();
    for (flag, value, message) in [
        ("--cpu-cores", "NaN", "must be finite"),
        (
            "--gpu-vram-min-mib",
            "18446744073709551615",
            "exceeds the supported byte range",
        ),
    ] {
        entangle(&home)
            .args(["compute", "dispatch", "pub/name@1.0.0", flag, value])
            .assert()
            .failure()
            .stderr(predicate::str::contains(message));
    }
}

#[test]
fn dispatch_writes_unmodified_binary_output_and_reports_the_worker_on_stderr() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    let home = TempDir::new().unwrap();
    let state = home.path().join(".entangle");
    std::fs::create_dir(&state).unwrap();
    let server = UnixListener::bind(state.join("sock")).unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["method"], "compute/dispatch");
        let response = serde_json::json!({"jsonrpc":"2.0", "id": request["id"], "result":{
            "chosen_peer":"worker-id", "score":1.0, "reason":"selected", "output":[255,0,10]
        }});
        writeln!(stream, "{response}").unwrap();
    });
    entangle(&home)
        .args(["compute", "dispatch", "pub/name@1.0.0", "--raw"])
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(vec![255, 0, 10])
        .stderr(predicate::str::contains("Chosen: worker-id"));
    worker.join().unwrap();
}
