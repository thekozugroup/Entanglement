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
if grep -rqF "$ENTANGLE_SESSION_TOKEN" "$(dirname "$cfg")"; then exit 17; fi
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

/// The original config changes while the session runs and the agent fails
/// to launch: both must be reported. The config is a FIFO whose first
/// reader (the session's snapshot) gets `{}`; before that read ends, a
/// regular file with other content is renamed over the FIFO, so the
/// end-of-session check reads different bytes.
#[test]
fn agent_run_launch_failure_still_reports_a_modified_original() {
    use std::io::Write;
    let dir = TempDir::new().unwrap();
    let cfg = dir.path().join("mcp.json");
    let status = std::process::Command::new("mkfifo")
        .arg(&cfg)
        .status()
        .unwrap();
    assert!(status.success());
    let replacement = dir.path().join("replacement.json");
    fs::write(&replacement, r#"{"mcpServers":{}}"#).unwrap();
    let writer = {
        let (cfg, replacement) = (cfg.clone(), replacement.clone());
        std::thread::spawn(move || {
            // Blocks until the snapshot opens the FIFO for reading.
            let mut w = fs::OpenOptions::new().write(true).open(&cfg).unwrap();
            w.write_all(b"{}").unwrap();
            // The reader is still waiting for EOF while this end is open.
            fs::rename(&replacement, &cfg).unwrap();
        })
    };
    let sessions = dir.path().join("sessions");
    let out = entangle()
        .env("ENTANGLE_SESSIONS_DIR", &sessions)
        .args(["agent", "run", "claude-code", "--config"])
        .arg(&cfg)
        .arg("--bin")
        .arg(dir.path().join("does-not-exist"))
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .get_output()
        .clone();
    if !writer.is_finished() {
        // The CLI never opened the FIFO: unblock the writer.
        let _ = fs::read(&cfg);
    }
    writer.join().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("launching"), "{stderr}");
    assert!(
        stderr.contains("ENTANGLE-E0660"),
        "the modified original must be reported even when launch fails: {stderr}"
    );
}

/// Fake agent that publishes its PID, then waits until `$SIG` arrives,
/// records it in `$MARK` and exits with `$CODE`.
const TRAPPING_AGENT: &str = r#"#!/bin/sh
trap 'kill "$child" 2>/dev/null; echo got > "$MARK"; exit "$CODE"' "$SIG"
sleep 60 >/dev/null 2>&1 &
child=$!
echo $$ > "$READY.tmp" && mv "$READY.tmp" "$READY"
wait "$child"
exit 0
"#;

/// Fake agent that ignores SIGTERM.
const STUBBORN_AGENT: &str = r#"#!/bin/sh
trap '' TERM
echo $$ > "$READY.tmp" && mv "$READY.tmp" "$READY"
exec sleep 60
"#;

/// Run `entangle agent run` with `script` as the agent, send `sig` to the
/// CLI once the agent is up, and return the CLI's exit status and the
/// directory holding `mark` and `sessions`.
fn signal_cli(
    script: &str,
    sig: &str,
    envs: &[(&str, &str)],
) -> (std::process::ExitStatus, TempDir) {
    use std::time::{Duration, Instant};
    let dir = TempDir::new().unwrap();
    let agent = dir.path().join("agent.sh");
    fs::write(&agent, script).unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    let ready = dir.path().join("ready");
    let mut cli = std::process::Command::new(assert_cmd::cargo::cargo_bin("entangle"))
        .args(["agent", "run", "claude-code", "--config"])
        .arg(dir.path().join("none.json"))
        .arg("--bin")
        .arg(&agent)
        .env("ENTANGLE_SESSIONS_DIR", dir.path().join("sessions"))
        .env("READY", &ready)
        .env("MARK", dir.path().join("mark"))
        .envs(envs.iter().copied())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "agent never started");
        std::thread::sleep(Duration::from_millis(50));
    }
    let agent_pid = fs::read_to_string(&ready).unwrap().trim().to_string();
    let sent = std::process::Command::new("kill")
        .args([format!("-{sig}"), cli.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(st) = cli.try_wait().unwrap() {
            break st;
        }
        if Instant::now() > deadline {
            let _ = cli.kill();
            panic!("entangle did not exit after SIG{sig}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Never leave the fake agent behind, whatever the CLI did.
    let _ = std::process::Command::new("kill")
        .args(["-KILL", &agent_pid])
        .stderr(std::process::Stdio::null())
        .status();
    (status, dir)
}

fn sessions_left(dir: &TempDir) -> usize {
    fs::read_dir(dir.path().join("sessions"))
        .map(|d| d.count())
        .unwrap_or(0)
}

#[test]
fn agent_run_sigterm_is_passed_on_to_the_agent() {
    let (status, dir) = signal_cli(TRAPPING_AGENT, "TERM", &[("SIG", "TERM"), ("CODE", "3")]);
    assert!(
        dir.path().join("mark").exists(),
        "the agent gets SIGTERM and can shut down cleanly"
    );
    assert_eq!(status.code(), Some(3), "the agent's own exit status");
    assert_eq!(sessions_left(&dir), 0, "session dir removed");
}

#[test]
fn agent_run_sighup_cleans_up_and_is_passed_on() {
    let (status, dir) = signal_cli(TRAPPING_AGENT, "HUP", &[("SIG", "HUP"), ("CODE", "4")]);
    assert!(dir.path().join("mark").exists(), "the agent gets SIGHUP");
    assert_eq!(status.code(), Some(4), "{status:?}");
    assert_eq!(sessions_left(&dir), 0, "session dir removed");
}

/// Fake agent that treats SIGINT the way interactive agents do — "interrupt
/// the current turn" — and keeps running for longer than the CLI's stop
/// grace period before it exits on its own with status 5.
const INTERRUPTIBLE_AGENT: &str = r#"#!/bin/sh
trap 'echo got > "$MARK"' INT
echo $$ > "$READY.tmp" && mv "$READY.tmp" "$READY"
i=0
while [ ! -f "$MARK" ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done
sleep 6
exit 5
"#;

#[test]
fn agent_run_sigint_is_passed_on_and_does_not_end_the_session() {
    // stdin is not a terminal here, so the SIGINT reached the CLI alone: it
    // must be passed on, and the agent decides what it means. The session
    // lasts until the agent exits by itself — even past the stop grace
    // period that applies to SIGTERM/SIGHUP.
    let (status, dir) = signal_cli(INTERRUPTIBLE_AGENT, "INT", &[]);
    assert!(
        dir.path().join("mark").exists(),
        "the agent gets the SIGINT"
    );
    assert_eq!(
        status.code(),
        Some(5),
        "the agent's own exit status, not a kill: {status:?}"
    );
    assert_eq!(sessions_left(&dir), 0, "session dir removed");
}

#[test]
fn agent_run_sigterm_kills_an_agent_that_ignores_it_and_exits_143() {
    let (status, dir) = signal_cli(STUBBORN_AGENT, "TERM", &[]);
    assert_eq!(status.code(), Some(143), "{status:?}");
    assert_eq!(sessions_left(&dir), 0, "session dir removed");
}

/// Fake stdio MCP server: answers `initialize` and `tools/call`, and logs
/// every `tools/call` line it receives to `$CALLS`.
const FAKE_SERVER: &str = r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  [ -n "$id" ] || continue
  case "$line" in
    *'"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"f","version":"1"}}}\n' "$id" ;;
    *'"tools/call"'*) echo "$line" >> "$CALLS"; printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[]}}\n' "$id" ;;
  esac
done
"#;

/// Fake agent that calls two tools through the gateway with its session
/// token, and records the replies and the session directory's mode.
const GATEWAY_AGENT: &str = r#"#!/bin/sh
cfg="$2"
url=$(sed -n 's/.*"url": *"\([^"]*\)".*/\1/p' "$cfg" | head -n 1)
call() {
  curl -s -m 20 -H "Authorization: Bearer $ENTANGLE_SESSION_TOKEN" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{}}}" "$url"
}
{ call 1 secret; echo; call 2 fine; echo; } > "$OUT"
stat -c %a "$(dirname "$cfg")" > "$MODE"
exit 0
"#;

#[test]
fn agent_run_policy_flags_reach_the_gateway_end_to_end() {
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("curl not available; skipping");
        return;
    }
    let dir = TempDir::new().unwrap();
    let server = dir.path().join("server.sh");
    fs::write(&server, FAKE_SERVER).unwrap();
    fs::set_permissions(&server, fs::Permissions::from_mode(0o755)).unwrap();
    let agent = dir.path().join("agent.sh");
    fs::write(&agent, GATEWAY_AGENT).unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    let calls = dir.path().join("calls");
    let cfg = dir.path().join("mcp.json");
    fs::write(
        &cfg,
        serde_json::json!({"mcpServers":{"fs":{
            "command": server, "env": {"CALLS": calls}
        }}})
        .to_string(),
    )
    .unwrap();
    let out = dir.path().join("out");
    let mode = dir.path().join("mode");
    entangle()
        .env("ENTANGLE_SESSIONS_DIR", dir.path().join("sessions"))
        .env("OUT", &out)
        .env("MODE", &mode)
        .args([
            "agent",
            "run",
            "claude-code",
            "--deny",
            "fs/secret",
            "--config",
        ])
        .arg(&cfg)
        .arg("--bin")
        .arg(&agent)
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .success();
    let replies = fs::read_to_string(&out).unwrap();
    let mut lines = replies.lines();
    let denied = lines.next().unwrap_or_default();
    let allowed = lines.next().unwrap_or_default();
    assert!(
        denied.contains("ENTANGLE-E0661") && denied.contains("denied"),
        "--deny must reach the gateway: {replies}"
    );
    assert!(
        allowed.contains("\"result\"") && !allowed.contains("ENTANGLE-"),
        "an allowed call must reach the downstream: {replies}"
    );
    let seen = fs::read_to_string(&calls).unwrap();
    assert!(
        seen.contains("\"fine\"") && !seen.contains("secret"),
        "the denied call must never reach the server: {seen}"
    );
    assert_eq!(
        fs::read_to_string(&mode).unwrap().trim(),
        "700",
        "session dir is private"
    );
}

#[test]
fn agent_run_warns_about_remote_http_servers() {
    let dir = TempDir::new().unwrap();
    let cfg = dir.path().join("mcp.json");
    fs::write(
        &cfg,
        r#"{"mcpServers":{"remote":{"type":"http","url":"https://mcp.example.com/x"}}}"#,
    )
    .unwrap();
    let agent = dir.path().join("agent.sh");
    fs::write(&agent, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    entangle()
        .env("ENTANGLE_SESSIONS_DIR", dir.path().join("sessions"))
        .args(["agent", "run", "claude-code", "--config"])
        .arg(&cfg)
        .arg("--bin")
        .arg(&agent)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("remote").and(predicate::str::contains("mcp.example.com/x")),
        );
}

#[test]
fn agent_run_reports_an_original_modified_during_a_normal_run() {
    let dir = TempDir::new().unwrap();
    let cfg = dir.path().join("mcp.json");
    fs::write(&cfg, r#"{"mcpServers":{}}"#).unwrap();
    let agent = dir.path().join("agent.sh");
    fs::write(&agent, "#!/bin/sh\necho '{}' > \"$ORIG\"\nexit 3\n").unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    entangle()
        .env("ENTANGLE_SESSIONS_DIR", dir.path().join("sessions"))
        .env("ORIG", &cfg)
        .args(["agent", "run", "claude-code", "--config"])
        .arg(&cfg)
        .arg("--bin")
        .arg(&agent)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("ENTANGLE-E0660"));
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
