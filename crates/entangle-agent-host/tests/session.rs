//! Integration test for `AgentSession` start + restore round-trip.
//!
//! These tests use the claude-code adapter (project-local `.mcp.json`).
//! Because `config_path()` returns a relative path that resolves against the
//! process working directory, each test creates a tempdir, changes into it,
//! runs the assertions, then restores the original working directory.
//!
//! Tests are tagged `#[serial]` via the `serial_test` crate so that
//! parallel execution cannot corrupt each other's CWD changes.
//! (Cargo.toml dev-dep: serial_test = "3".)

use entangle_agent_host::AgentSession;
use std::fs;
use tempfile::TempDir;

const GW: &str = "http://127.0.0.1:9000/mcp";
const SRV: &str = "strata";

/// Helper: change CWD into `dir`, run `f`, restore CWD even if `f` panics.
fn with_cwd<F: FnOnce()>(dir: &TempDir, f: F) {
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::env::set_current_dir(&original).unwrap();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// Start a session, verify the gateway URL is injected, restore, verify
/// original content is back.
#[test]
#[ignore = "mutates current_dir; run with: cargo test -p entangle-agent-host --test session -- --ignored --test-threads=1"]
fn session_start_and_restore_round_trips() {
    let dir = TempDir::new().unwrap();
    let original = r#"{"mcpServers":{"user-tool":{"type":"http","url":"http://user"}}}"#;
    fs::write(dir.path().join(".mcp.json"), original).unwrap();

    with_cwd(&dir, || {
        let session =
            AgentSession::start("claude-code", GW, SRV).expect("session start should succeed");

        let patched = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(v["mcpServers"][SRV]["url"], GW, "gateway URL not injected");
        assert!(
            v["mcpServers"]["user-tool"].is_object(),
            "original server lost"
        );

        session.restore().expect("restore should succeed");

        let restored = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        assert_eq!(
            restored, original,
            "restore did not reproduce original content"
        );
    });
}

/// When no `.mcp.json` exists, restore should delete the generated file.
#[test]
#[ignore = "mutates current_dir; run with: cargo test -p entangle-agent-host --test session -- --ignored --test-threads=1"]
fn session_start_no_prior_config_restore_removes_file() {
    let dir = TempDir::new().unwrap();
    let mcp_path = dir.path().join(".mcp.json");
    assert!(!mcp_path.exists());

    with_cwd(&dir, || {
        let session = AgentSession::start("claude-code", GW, SRV)
            .expect("session start should succeed even with no prior file");
        assert!(mcp_path.exists(), "gateway config should have been created");

        session.restore().expect("restore should succeed");
        assert!(
            !mcp_path.exists(),
            "file should be removed after restore when none existed originally"
        );
    });
}
