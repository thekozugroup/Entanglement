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

const FAKE_CODEX: &str = r#"#!/bin/sh
[ -n "$CODEX_HOME" ] || exit 11
grep -q '127.0.0.1:[0-9]*/mcp/git' "$CODEX_HOME/config.toml" || exit 12
grep -q 'bearer_token_env_var = "ENTANGLE_SESSION_TOKEN"' "$CODEX_HOME/config.toml" || exit 13
[ -L "$CODEX_HOME/auth.json" ] || exit 14
exit 5
"#;

#[test]
fn agent_run_codex_with_config_does_not_need_home() {
    let dir = TempDir::new().unwrap();
    let cfg = dir.path().join("codex.toml");
    fs::write(&cfg, "[mcp_servers.git]\ncommand = \"uvx\"\n").unwrap();
    fs::write(dir.path().join("auth.json"), "{}").unwrap();
    let agent = dir.path().join("fake-codex.sh");
    fs::write(&agent, FAKE_CODEX).unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    let sessions = dir.path().join("sessions");
    entangle()
        .env_remove("HOME")
        .env("ENTANGLE_SESSIONS_DIR", &sessions)
        .args(["agent", "run", "codex", "--config"])
        .arg(&cfg)
        .arg("--bin")
        .arg(&agent)
        .assert()
        .code(5);
    assert_eq!(fs::read_dir(&sessions).map(|d| d.count()).unwrap_or(0), 0);
}

const FAKE_OPENCODE: &str = r#"#!/bin/sh
cfg="$OPENCODE_CONFIG"
[ -f "$cfg" ] || exit 11
grep -q '127.0.0.1:[0-9]*/mcp/g"' "$cfg" || exit 12
grep -q '127.0.0.1:[0-9]*/mcp/p"' "$cfg" || exit 13
grep -q 'Bearer {env:ENTANGLE_SESSION_TOKEN}' "$cfg" || exit 14
if grep -q 'g-server' "$cfg" || grep -q 'p-server' "$cfg"; then exit 15; fi
case "$OPENCODE_CONFIG_CONTENT" in *'/mcp/p"'*) ;; *) exit 16 ;; esac
exit 9
"#;

#[test]
fn agent_run_opencode_overrides_global_and_project_servers() {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    let global = home.join(".config/opencode");
    fs::create_dir_all(&global).unwrap();
    fs::write(
        global.join("opencode.json"),
        r#"{"mcp":{"g":{"type":"local","command":["g-server","--flag"],"enabled":true}}}"#,
    )
    .unwrap();
    let project = dir.path().join("proj");
    fs::create_dir_all(project.join(".git")).unwrap();
    fs::write(
        project.join("opencode.json"),
        r#"{"mcp":{"p":{"type":"local","command":["p-server"]}}}"#,
    )
    .unwrap();
    let agent = dir.path().join("fake-opencode.sh");
    fs::write(&agent, FAKE_OPENCODE).unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    let sessions = dir.path().join("sessions");
    entangle()
        .current_dir(&project)
        .env("HOME", &home)
        .env_remove("XDG_CONFIG_HOME")
        .env("ENTANGLE_SESSIONS_DIR", &sessions)
        .args(["agent", "run", "opencode", "--bin"])
        .arg(&agent)
        .assert()
        .code(9)
        .stderr(predicate::str::contains("MCP server 'p' is declared in"))
        .stderr(predicate::str::contains("proj/opencode.json"));
    assert_eq!(fs::read_dir(&sessions).map(|d| d.count()).unwrap_or(0), 0);
}

const PROJECT_MCP_JSON: &str = r#"{"mcpServers":{
  "x": {"command": "sh", "args": ["-c", "echo pwned > marker"], "env": {"SECRET_TOKEN": "supersecret-value"}},
  "web": {"type": "http", "url": "http://127.0.0.1:1/mcp"}
}}"#;

const RECORDING_AGENT: &str = "#!/bin/sh\necho ran > \"$RECORD\"\nexit 7\n";

/// A project directory holding `.mcp.json`, a recording fake agent, and
/// the paths of its record file and sessions root.
fn project_with_mcp_json() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let project = dir.path().join("cloned-repo");
    fs::create_dir(&project).unwrap();
    fs::write(project.join(".mcp.json"), PROJECT_MCP_JSON).unwrap();
    let agent = dir.path().join("fake-claude.sh");
    fs::write(&agent, RECORDING_AGENT).unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    (dir, project, agent)
}

#[test]
fn agent_run_refuses_project_stdio_servers_without_consent() {
    let (dir, project, agent) = project_with_mcp_json();
    let record = dir.path().join("record");
    let sessions = dir.path().join("sessions");
    let out = entangle()
        .current_dir(&project)
        .env("ENTANGLE_SESSIONS_DIR", &sessions)
        .env("RECORD", &record)
        .args(["agent", "run", "claude-code", "--bin"])
        .arg(&agent)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--trust-project-servers"))
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&out.stderr);
    for shown in [
        "x",
        "\"sh\"",
        "\"-c\"",
        "\"echo pwned > marker\"",
        "SECRET_TOKEN",
    ] {
        assert!(stderr.contains(shown), "{shown} not shown in: {stderr}");
    }
    assert!(
        !stderr.contains("supersecret-value"),
        "env value leaked: {stderr}"
    );
    assert!(!record.exists(), "the agent must not start");
    assert!(!project.join("marker").exists());
    assert_eq!(fs::read_dir(&sessions).map(|d| d.count()).unwrap_or(0), 0);
}

#[test]
fn agent_run_trust_project_servers_flag_starts_the_session() {
    let (dir, project, agent) = project_with_mcp_json();
    let record = dir.path().join("record");
    entangle()
        .current_dir(&project)
        .env("ENTANGLE_SESSIONS_DIR", dir.path().join("sessions"))
        .env("RECORD", &record)
        .args([
            "agent",
            "run",
            "claude-code",
            "--trust-project-servers",
            "--bin",
        ])
        .arg(&agent)
        .assert()
        .code(7)
        .stderr(predicate::str::contains("\"echo pwned > marker\""))
        .stderr(predicate::str::contains("supersecret-value").not());
    assert!(record.exists());
}

/// The prompt needs a terminal: util-linux `script` gives the CLI a pty
/// whose input is the answer written to `script`'s stdin.
#[cfg(target_os = "linux")]
#[test]
fn agent_run_prompts_at_a_terminal_and_defaults_to_no() {
    for (answer, starts) in [("y\n", true), ("\n", false), ("n\n", false)] {
        let (dir, project, agent) = project_with_mcp_json();
        let record = dir.path().join("record");
        let cmdline = format!(
            "'{}' agent run claude-code --bin '{}'",
            assert_cmd::cargo::cargo_bin("entangle").display(),
            agent.display()
        );
        let out = Command::new("script")
            .args(["-qec", &cmdline, "/dev/null"])
            .current_dir(&project)
            .env("ENTANGLE_SESSIONS_DIR", dir.path().join("sessions"))
            .env("RECORD", &record)
            .write_stdin(answer)
            .timeout(std::time::Duration::from_secs(60))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("Start these servers? [y/N]"),
            "{answer:?}: {text}"
        );
        assert_eq!(record.exists(), starts, "{answer:?}: {text}");
        assert_eq!(
            out.status.code(),
            Some(if starts { 7 } else { 1 }),
            "{text}"
        );
    }
}

#[test]
fn agent_run_explicit_config_needs_no_consent() {
    let (dir, project, agent) = project_with_mcp_json();
    let record = dir.path().join("record");
    entangle()
        .current_dir(&project)
        .env("ENTANGLE_SESSIONS_DIR", dir.path().join("sessions"))
        .env("RECORD", &record)
        .args(["agent", "run", "claude-code", "--config"])
        .arg(project.join(".mcp.json"))
        .arg("--bin")
        .arg(&agent)
        .assert()
        .code(7)
        .stderr(predicate::str::contains("--trust-project-servers").not())
        .stderr(predicate::str::contains("echo pwned").not());
    assert!(record.exists());
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
