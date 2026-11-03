//! `entangle agent` — uses a fake agent (a shell script) via `--bin`.
#![cfg(unix)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::TempDir;

fn entangle() -> Command {
    Command::cargo_bin("entangle").unwrap()
}

const FAKE_AGENT: &str = r#"#!/bin/sh
[ -n "$ENTANGLE_SESSION_ID" ] || exit 11
[ -n "$ENTANGLE_SESSION_TOKEN" ] || exit 12
[ "$1" = "--mcp-config" ] || exit 13
cfg="$2"
[ -f "$cfg" ] || exit 14
grep -q '127.0.0.1:[0-9]*/mcp/fs' "$cfg" || exit 15
grep -q 'ENTANGLE_SESSION_TOKEN' "$cfg" || exit 16
if grep -q "$ENTANGLE_SESSION_TOKEN" "$cfg"; then exit 17; fi
if grep -q 'npx' "$cfg"; then exit 18; fi
[ "$3" = "--strict-mcp-config" ] || exit 19
[ "$4" = "--model" ] && [ "$5" = "x" ] || exit 20
echo "$cfg" > "$RECORD"
exit 7
"#;

#[test]
fn agent_run_wires_session_propagates_exit_code_and_cleans_up() {
    let dir = TempDir::new().unwrap();
    let cfg = dir.path().join("mcp.json");
    let original = r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","fs"]}}}"#;
    fs::write(&cfg, original).unwrap();
    let agent = dir.path().join("fake-agent.sh");
    fs::write(&agent, FAKE_AGENT).unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    let record = dir.path().join("record");
    let sessions = dir.path().join("sessions");

    entangle()
        .env("ENTANGLE_SESSIONS_DIR", &sessions)
        .env("RECORD", &record)
        .args(["agent", "run", "claude-code", "--config"])
        .arg(&cfg)
        .arg("--bin")
        .arg(&agent)
        .args(["--", "--model", "x"])
        .assert()
        .code(7);

    let session_cfg = fs::read_to_string(&record).expect("agent saw the session config");
    let session_cfg = session_cfg.trim();
    assert!(
        session_cfg.starts_with(sessions.to_str().unwrap()),
        "{session_cfg}"
    );
    assert!(
        !std::path::Path::new(session_cfg).exists(),
        "session config removed on exit"
    );
    assert_eq!(
        fs::read_dir(&sessions).unwrap().count(),
        0,
        "session dir removed"
    );
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        original,
        "user config untouched"
    );
}

#[test]
fn agent_run_unknown_agent_lists_known_agents() {
    entangle()
        .args(["agent", "run", "emacs-gpt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown agent 'emacs-gpt'"))
        .stderr(predicate::str::contains("claude-code"))
        .stderr(predicate::str::contains("codex"))
        .stderr(predicate::str::contains("opencode"));
}

#[test]
fn agent_run_missing_binary_is_actionable_and_cleans_up() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions");
    entangle()
        .env("ENTANGLE_SESSIONS_DIR", &sessions)
        .args(["agent", "run", "claude-code", "--config"])
        .arg(dir.path().join("none.json"))
        .arg("--bin")
        .arg(dir.path().join("does-not-exist"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("launching"));
    assert_eq!(fs::read_dir(&sessions).map(|d| d.count()).unwrap_or(0), 0);
}

#[test]
fn agent_run_failed_session_setup_leaves_no_session_dir() {
    // A config whose root is not an object reads as "no servers" but cannot
    // be rewritten, so activating the session fails after the gateway is up.
    let dir = TempDir::new().unwrap();
    let cfg = dir.path().join("mcp.json");
    fs::write(&cfg, "[]").unwrap();
    let sessions = dir.path().join("sessions");
    entangle()
        .env("ENTANGLE_SESSIONS_DIR", &sessions)
        .args(["agent", "run", "claude-code", "--config"])
        .arg(&cfg)
        .arg("--bin")
        .arg(dir.path().join("never-launched"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("writing session config"));
    let left: Vec<_> = fs::read_dir(&sessions)
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "session dirs left behind: {left:?}");
}

#[test]
fn agent_list_shows_adapters() {
    entangle()
        .args(["agent", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("claude-code"))
        .stdout(predicate::str::contains("codex"))
        .stdout(predicate::str::contains("opencode"));
}
