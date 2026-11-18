//! `entangle agent run` starts the agent inside the OS sandbox (spec §8.2):
//! a fake agent (a shell script via `--bin`) tries to write inside and
//! outside the project directory.
//!
//! Directories live under `CARGO_TARGET_TMPDIR`, not the system temporary
//! directory: `/tmp` is on the agent's allowlist, so a file there would not
//! be "outside".
#![cfg(target_os = "linux")]

use assert_cmd::Command;
use std::path::{Path, PathBuf};
use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::TempDir;

fn entangle() -> Command {
    Command::cargo_bin("entangle").unwrap()
}

fn dir() -> TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

/// Writes `inside` (relative to the project, its working directory) and
/// then tries `$OUTSIDE`. Exit 0: both written. Exit 40: the outside write
/// was refused. Exit 41: the inside write failed.
const FAKE_AGENT: &str = r#"#!/bin/sh
echo started > started || exit 41
mkdir -p sub && echo inside > sub/inside.txt || exit 41
if (echo escaped > "$OUTSIDE/escape.txt") 2>/dev/null; then exit 0; fi
exit 40
"#;

struct Fixture {
    project: TempDir,
    outside: TempDir,
    sessions: TempDir,
    agent: PathBuf,
}

fn fixture() -> Fixture {
    let project = dir();
    // Its own repository root: the project directory of a session is the
    // enclosing git work tree, which would otherwise be this checkout (and
    // contain the "outside" directories).
    fs::create_dir(project.path().join(".git")).unwrap();
    let agent = project.path().join("fake-agent.sh");
    fs::write(&agent, FAKE_AGENT).unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    Fixture {
        project,
        outside: dir(),
        sessions: dir(),
        agent,
    }
}

impl Fixture {
    fn run(&self, extra: &[&str]) -> Command {
        let mut cmd = entangle();
        cmd.current_dir(self.project.path())
            .env("ENTANGLE_SESSIONS_DIR", self.sessions.path().join("s"))
            .env("OUTSIDE", self.outside.path())
            .env_remove("ENTANGLE_AGENT_SANDBOX_PROBE")
            .args(["agent", "run", "claude-code", "--config"])
            .arg(self.project.path().join("none.json"))
            .arg("--bin")
            .arg(&self.agent)
            .args(extra);
        cmd
    }
    fn escaped(&self) -> bool {
        self.outside.path().join("escape.txt").exists()
    }
    fn inside(&self) -> bool {
        self.project.path().join("sub/inside.txt").exists()
    }
}

fn landlock() -> bool {
    let has = entangle_sandbox::probe().landlock_abi.is_some();
    if !has {
        eprintln!("skipping: this kernel has no Landlock");
    }
    has
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn sandboxed_agent_writes_in_the_project_and_not_outside_the_allowlist() {
    if !landlock() {
        return;
    }
    let f = fixture();
    let out = f.run(&[]).output().unwrap();
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(40), "outside write refused: {err}");
    assert!(f.inside(), "the project directory is writable");
    assert!(!f.escaped(), "nothing was written outside the allowlist");
    // The session start reports the sandbox, and never claims a network
    // restriction.
    assert!(err.contains("sandbox: Landlock ABI"), "{err}");
    assert!(err.contains("network egress NOT restricted"), "{err}");
    let project = fs::canonicalize(f.project.path()).unwrap();
    assert!(
        err.contains(&format!("writable: {}", project.display())),
        "{err}"
    );
}

#[test]
fn sandbox_write_flag_extends_the_allowlist() {
    if !landlock() {
        return;
    }
    let f = fixture();
    let out = f
        .run(&["--sandbox-write", f.outside.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(f.escaped(), "a --sandbox-write path is writable");

    // A path that does not exist is refused before the agent starts.
    let f = fixture();
    let out = f.run(&["--sandbox-read", "/no/such/dir"]).output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("ENTANGLE-E0682"), "{}", stderr(&out));
    assert!(!f.project.path().join("started").exists());
}

#[test]
fn no_sandbox_runs_unconfined_with_a_loud_warning() {
    let f = fixture();
    let out = f.run(&["--no-sandbox"]).output().unwrap();
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(f.inside() && f.escaped(), "nothing is confined");
    assert!(err.contains("warning: --no-sandbox"), "{err}");
    assert!(err.contains("WITHOUT the OS sandbox"), "{err}");
    assert!(!err.contains("sandbox: Landlock"), "{err}");
}

#[test]
fn landlock_unavailable_degrades_with_a_clear_message() {
    let f = fixture();
    let out = f
        .run(&[])
        .env("ENTANGLE_AGENT_SANDBOX_PROBE", "no-landlock")
        .output()
        .unwrap();
    let err = stderr(&out);
    // The agent still starts; its filesystem access is not confined, and
    // the warning says so and why.
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(f.escaped());
    assert!(err.contains("warning:"), "{err}");
    assert!(err.contains("NOT confined"), "{err}");
    assert!(err.contains("Landlock is not available"), "{err}");
    assert!(err.contains("--require-sandbox"), "{err}");
}

#[test]
fn require_sandbox_refuses_to_start_without_landlock() {
    let f = fixture();
    let out = f
        .run(&["--require-sandbox"])
        .env("ENTANGLE_AGENT_SANDBOX_PROBE", "no-landlock")
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(!out.status.success());
    assert!(err.contains("ENTANGLE-E0680"), "{err}");
    assert!(
        !f.project.path().join("started").exists(),
        "the agent must not have been started"
    );
    // The session directory is cleaned up all the same.
    let left = fs::read_dir(f.sessions.path().join("s"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(left, 0);

    // --no-sandbox and --require-sandbox contradict each other.
    let out = fixture()
        .run(&["--require-sandbox", "--no-sandbox"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cannot be used with"));
}

#[test]
fn require_sandbox_starts_where_landlock_works() {
    if !landlock() {
        return;
    }
    let f = fixture();
    let out = f.run(&["--require-sandbox"]).output().unwrap();
    assert_eq!(out.status.code(), Some(40), "{}", stderr(&out));
}

/// The session config directory is readable inside the sandbox (the agent
/// must load its gateway-routed MCP config) but not writable for an agent
/// that does not keep state there.
#[test]
fn session_config_is_readable_and_not_writable() {
    if !landlock() {
        return;
    }
    let f = fixture();
    // `$2` is the --mcp-config path.
    let script = "#!/bin/sh\ncat \"$2\" > /dev/null || exit 50\n\
                  if (echo x >> \"$2\") 2>/dev/null; then exit 51; fi\nexit 0\n";
    fs::write(&f.agent, script).unwrap();
    let out = f.run(&[]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

fn doctor(home: &Path) -> Command {
    let mut cmd = entangle();
    cmd.arg("doctor").env("HOME", home);
    cmd
}

#[test]
fn doctor_reports_the_agent_sandbox() {
    let home = tempfile::tempdir().unwrap();
    let out = doctor(home.path())
        .env_remove("ENTANGLE_AGENT_SANDBOX_PROBE")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = stdout
        .lines()
        .find(|l| l.contains("agent sandbox"))
        .unwrap_or_else(|| panic!("no agent sandbox line:\n{stdout}"));
    assert!(line.contains("network egress NOT restricted"), "{line}");
    if entangle_sandbox::probe().landlock_abi.is_some() {
        assert!(line.contains("Landlock ABI"), "{line}");
    }

    let out = doctor(home.path())
        .env("ENTANGLE_AGENT_SANDBOX_PROBE", "no-landlock")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = stdout
        .lines()
        .find(|l| l.contains("agent sandbox"))
        .unwrap_or_else(|| panic!("no agent sandbox line:\n{stdout}"));
    assert!(line.contains("[warn]"), "{line}");
    assert!(
        line.contains("can read and write every file you can"),
        "{line}"
    );
    assert!(line.contains("NO filesystem allowlist"), "{line}");
}

/// Spec §8.3 wrapper item 3: the informational shell-history note. Counts
/// only — the commands themselves never appear in the output.
#[test]
fn doctor_shell_history_note_counts_without_printing_commands() {
    let home = tempfile::tempdir().unwrap();
    fs::write(
        home.path().join(".bash_history"),
        "ls\nclaude --resume SECRET-SESSION-NAME\nentangle agent run claude-code\n\
         codex exec 'private prompt text'\nclaude\n",
    )
    .unwrap();
    let line_of = |out: &std::process::Output| {
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let line = stdout
            .lines()
            .find(|l| l.contains("shell history"))
            .unwrap_or_else(|| panic!("no shell history line:\n{stdout}"))
            .to_owned();
        (stdout, line)
    };
    let out = doctor(home.path())
        .env_remove("HISTFILE")
        .env_remove("ENTANGLE_DOCTOR_NO_HISTORY")
        .output()
        .unwrap();
    let (stdout, line) = line_of(&out);
    assert!(
        line.contains("[ok]"),
        "informational, not a warning: {line}"
    );
    assert!(line.contains("3 of the last 5 history entries"), "{line}");
    assert!(
        line.contains("claude: 2") && line.contains("codex: 1"),
        "{line}"
    );
    assert!(line.contains("ENTANGLE_DOCTOR_NO_HISTORY"), "{line}");
    let all = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(!all.contains("SECRET-SESSION-NAME") && !all.contains("private prompt"));

    // Opt-out: the file is not read.
    let out = doctor(home.path())
        .env_remove("HISTFILE")
        .env("ENTANGLE_DOCTOR_NO_HISTORY", "1")
        .output()
        .unwrap();
    let (_, line) = line_of(&out);
    assert!(
        line.contains("[skip]") && line.contains("not read"),
        "{line}"
    );

    // No history file at all.
    let empty = tempfile::tempdir().unwrap();
    let out = doctor(empty.path())
        .env_remove("HISTFILE")
        .env_remove("ENTANGLE_DOCTOR_NO_HISTORY")
        .output()
        .unwrap();
    let (_, line) = line_of(&out);
    assert!(line.contains("no shell history file found"), "{line}");
}
