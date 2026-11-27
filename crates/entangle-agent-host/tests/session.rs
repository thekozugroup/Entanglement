//! Exercise the default Claude Code adapter in a private working directory for each case.

use entangle_agent_host::AgentSession;
use std::{fs, path::Path, process::Command};

const GW: &str = "http://127.0.0.1:9000/mcp";
const SRV: &str = "strata";

fn with_fixture(test: &str, exercise: impl FnOnce(&Path)) {
    const CHILD_DIR: &str = "ENTANGLE_AGENT_SESSION_TEST_DIR";
    const COMPLETE: &str = "session-test-complete";
    const PREFIX: &str = "entangle-agent-session-test-";

    if let Some(path) = std::env::var_os(CHILD_DIR) {
        assert!(
            std::env::args_os().skip(1).eq(["--exact", test]),
            "child process must select only {test}"
        );
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(cwd, Path::new(&path));
        assert!(cwd
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(PREFIX));
        assert!(
            fs::read_dir(&cwd).unwrap().next().is_none(),
            "child working directory must be empty"
        );
        exercise(&cwd);
        fs::File::create_new(cwd.join(COMPLETE)).unwrap();
        return;
    }

    let dir = tempfile::Builder::new().prefix(PREFIX).tempdir().unwrap();
    let child_dir = dir.path().canonicalize().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test])
        .current_dir(&child_dir)
        .env(CHILD_DIR, &child_dir)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "child test {test} failed:\n{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        child_dir.join(COMPLETE).is_file(),
        "child test {test} finished without exercising the fixture"
    );
}

/// Start a session, verify the gateway URL is injected, restore, verify
/// original content is back.
#[test]
fn session_start_and_restore_round_trips() {
    with_fixture("session_start_and_restore_round_trips", |dir| {
        let path = dir.join(".mcp.json");
        let original = r#"{"mcpServers":{"user-tool":{"type":"http","url":"http://user"}}}"#;
        fs::write(&path, original).unwrap();

        let session =
            AgentSession::start("claude-code", GW, SRV).expect("session start should succeed");

        let patched = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(v["mcpServers"][SRV]["url"], GW, "gateway URL not injected");
        assert!(
            v["mcpServers"]["user-tool"].is_object(),
            "original server lost"
        );

        session.restore().expect("restore should succeed");

        let restored = fs::read_to_string(path).unwrap();
        assert_eq!(
            restored, original,
            "restore did not reproduce original content"
        );
    });
}

/// When no `.mcp.json` exists, restore should delete the generated file.
#[test]
fn session_start_no_prior_config_restore_removes_file() {
    with_fixture(
        "session_start_no_prior_config_restore_removes_file",
        |dir| {
            let mcp_path = dir.join(".mcp.json");
            assert!(!mcp_path.exists());
            let session = AgentSession::start("claude-code", GW, SRV)
                .expect("session start should succeed even with no prior file");
            assert!(mcp_path.exists(), "gateway config should have been created");

            session.restore().expect("restore should succeed");
            assert!(
                !mcp_path.exists(),
                "file should be removed after restore when none existed originally"
            );
        },
    );
}
