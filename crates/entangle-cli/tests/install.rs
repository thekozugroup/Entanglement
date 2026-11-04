//! `entangle install`, `entangle uninstall` and `entangle agent host
//! cleanup` (spec §8.3 cleanup-on-uninstall and wrapper item 2, §9.2).

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

struct Env {
    home: TempDir,
    sessions: TempDir,
}

impl Env {
    fn new() -> Self {
        let me = Self {
            home: TempDir::new().unwrap(),
            sessions: TempDir::new().unwrap(),
        };
        // The user's own agent configs, which must never be modified.
        let codex = me.home.path().join(".codex/config.toml");
        std::fs::create_dir_all(codex.parent().unwrap()).unwrap();
        std::fs::write(&codex, "[mcp_servers.fs]\ncommand = \"fs-server\"\n").unwrap();
        let claude = me.home.path().join(".claude/settings.json");
        std::fs::create_dir_all(claude.parent().unwrap()).unwrap();
        std::fs::write(&claude, "{\"mcpServers\":{}}\n").unwrap();
        me
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("entangle").expect("entangle binary built");
        c.env("HOME", self.home.path())
            .env("ENTANGLE_SESSIONS_DIR", self.sessions.path())
            .env("NO_COLOR", "1")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("ZDOTDIR");
        c
    }

    fn dot(&self) -> std::path::PathBuf {
        self.home.path().join(".entangle")
    }

    fn session(&self, name: &str, owner_pid: Option<u32>) -> std::path::PathBuf {
        let d = self.sessions.path().join(name);
        std::fs::create_dir_all(d.join(".claude")).unwrap();
        std::fs::write(d.join(".claude/settings.json"), "{}").unwrap();
        if let Some(pid) = owner_pid {
            std::fs::write(
                d.join(".entangle-session.json"),
                format!("{{\"pid\":{pid},\"agent\":\"claude-code\",\"started_unix\":0}}"),
            )
            .unwrap();
        }
        d
    }
}

/// A pid that is not running: one past the kernel's highest.
fn dead_pid() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map_or(4_194_304, |m| m + 1)
}

#[test]
fn install_initialises_records_checksums_and_respects_no_wrapper() {
    let env = Env::new();
    let before = std::fs::read(env.home.path().join(".codex/config.toml")).unwrap();
    env.cmd()
        .args(["install", "--headless", "--no-wrapper"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Not installing wrappers"))
        .stdout(predicate::str::contains("sha256 recorded"));
    assert!(env.dot().join("identity.key").exists());
    let rec: serde_json::Value = serde_json::from_slice(
        &std::fs::read(env.dot().join("agent-host/install-checksums.json")).unwrap(),
    )
    .unwrap();
    let files = rec["files"].as_array().unwrap();
    let codex = files
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with(".codex/config.toml"))
        .expect("codex config recorded");
    assert_eq!(codex["agent"], "codex");
    assert_eq!(codex["sha256"].as_str().unwrap().len(), 64);
    assert!(files.iter().any(|f| f["path"]
        .as_str()
        .unwrap()
        .ends_with(".claude/settings.json")));
    // The opt-out is recorded, no rc file was written, no config modified.
    let cfg = std::fs::read_to_string(env.dot().join("config.toml")).unwrap();
    assert!(cfg.contains("[wrappers]\ninstall = false"), "{cfg}");
    assert!(!env.home.path().join(".bashrc").exists());
    assert_eq!(
        std::fs::read(env.home.path().join(".codex/config.toml")).unwrap(),
        before
    );

    // A later install respects the recorded opt-out without asking.
    env.cmd()
        .arg("install")
        .write_stdin("")
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrappers stay off: you opted out"));
}

#[test]
fn install_asks_the_wrapper_question() {
    let env = Env::new();
    env.cmd().args(["init", "--headless"]).assert().success();
    env.cmd()
        .arg("install")
        .write_stdin("y\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Install shell wrappers that warn when agent hosts run outside Entanglement? [Y/n]:",
        ));
    let rc = std::fs::read_to_string(env.home.path().join(".bashrc")).unwrap();
    assert!(rc.contains(">>> entangle wrapper >>>"), "{rc}");
}

#[test]
fn agent_host_cleanup_removes_only_abandoned_sessions() {
    let env = Env::new();
    let stale = env.session("sess-00000000000000aa", Some(dead_pid()));
    let live = env.session("sess-00000000000000bb", Some(std::process::id()));
    let unrelated = env.sessions.path().join("notes");
    std::fs::create_dir(&unrelated).unwrap();
    env.cmd()
        .args(["agent", "host", "cleanup"])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"))
        .stdout(predicate::str::contains("is gone"))
        .stdout(predicate::str::contains("kept"));
    assert!(!stale.exists() && live.exists() && unrelated.exists());

    let out = env
        .cmd()
        .args(["agent", "host", "cleanup", "--all", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["sessions"][0]["action"], "removed");
    assert!(!live.exists() && unrelated.exists());
    assert!(env.home.path().join(".claude/settings.json").exists());
}

#[test]
fn uninstall_cleans_up_and_reports_agent_configs_that_changed() {
    let env = Env::new();
    env.cmd()
        .args(["install", "--headless", "--wrapper"])
        .assert()
        .success();
    assert!(std::fs::read_to_string(env.home.path().join(".bashrc"))
        .unwrap()
        .contains(">>> entangle wrapper >>>"));
    let session = env.session("sess-00000000000000cc", Some(std::process::id()));
    std::fs::write(env.home.path().join(".codex/config.toml"), "# edited\n").unwrap();

    env.cmd()
        .arg("uninstall")
        .assert()
        .success()
        .stdout(predicate::str::contains("CHANGED since install"))
        .stdout(predicate::str::contains(".codex/config.toml"))
        .stdout(predicate::str::contains("unchanged"))
        .stdout(predicate::str::contains("entangle uninstall --purge"));
    assert!(!session.exists(), "uninstall runs cleanup --all");
    assert!(!std::fs::read_to_string(env.home.path().join(".bashrc"))
        .unwrap()
        .contains(">>> entangle wrapper >>>"));
    assert!(
        env.dot().join("identity.key").exists(),
        "kept without --purge"
    );
    // The user's file is reported, never restored or touched.
    assert_eq!(
        std::fs::read_to_string(env.home.path().join(".codex/config.toml")).unwrap(),
        "# edited\n"
    );
}

#[test]
fn purge_needs_the_typed_word_or_yes() {
    let env = Env::new();
    env.cmd().args(["init", "--headless"]).assert().success();
    // `yes | entangle uninstall --purge` must not delete the identity.
    env.cmd()
        .args(["uninstall", "--purge"])
        .write_stdin("y\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0790"));
    assert!(env.dot().join("identity.key").exists());
    env.cmd()
        .args(["uninstall", "--purge"])
        .write_stdin("purge\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Deleted"));
    assert!(!env.dot().exists());

    let env = Env::new();
    env.cmd().args(["init", "--headless"]).assert().success();
    env.cmd()
        .args(["uninstall", "--purge", "--yes"])
        .assert()
        .success();
    assert!(!env.dot().exists());
    assert!(env.home.path().join(".codex/config.toml").exists());
}

/// Uninstall on a machine that was never set up removes nothing it should
/// not and does not create the directory it cleans up.
#[test]
fn uninstall_without_an_install_creates_nothing() {
    let env = Env::new();
    env.cmd()
        .arg("uninstall")
        .assert()
        .success()
        .stdout(predicate::str::contains("No checksums were recorded"));
    assert!(!env.dot().exists(), "~/.entangle must not be created");
}

/// The rc blocks are removed even when config.toml cannot be edited (an
/// inline `wrappers = { ... }` table, or a file that is not TOML): recording
/// the opt-out is best effort, removing what Entanglement wrote is not.
#[test]
fn uninstall_removes_the_wrappers_even_when_config_toml_cannot_be_edited() {
    for broken in [
        "wrappers = { install = true }\n",
        "[mesh\ntransports = [\"local\"]\n",
    ] {
        let env = Env::new();
        env.cmd().args(["init", "--headless"]).assert().success();
        env.cmd().args(["wrapper", "enable"]).assert().success();
        let bashrc = env.home.path().join(".bashrc");
        assert!(std::fs::read_to_string(&bashrc)
            .unwrap()
            .contains(">>> entangle wrapper >>>"));
        std::fs::write(env.dot().join("config.toml"), broken).unwrap();

        let out = env
            .cmd()
            .args(["uninstall", "--purge", "--yes"])
            .assert()
            .success()
            .get_output()
            .clone();
        for rc in [".bashrc", ".zshrc"] {
            let text = std::fs::read_to_string(env.home.path().join(rc)).unwrap_or_default();
            assert!(
                !text.contains(">>> entangle wrapper >>>"),
                "{broken:?}: the block stays in {rc}:\n{text}"
            );
        }
        assert!(!env
            .home
            .path()
            .join(".config/fish/conf.d/entangle.fish")
            .exists());
        assert!(!env.dot().exists(), "--purge still deletes ~/.entangle");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("could not record [wrappers] install = false"),
            "{stderr}"
        );
    }

    // An rc file the block cannot be removed from fails the command.
    let env = Env::new();
    env.cmd().args(["init", "--headless"]).assert().success();
    env.cmd().args(["wrapper", "enable"]).assert().success();
    std::fs::write(env.home.path().join(".zshrc"), b"\xff\xfe not utf-8\n").unwrap();
    env.cmd()
        .arg("uninstall")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("still in at least one rc file"));
    assert!(!std::fs::read_to_string(env.home.path().join(".bashrc"))
        .unwrap()
        .contains(">>> entangle wrapper >>>"));
}

/// `--purge` on a `~/.entangle` that is a symbolic link would delete only
/// the link while the identity key stays at its target: it refuses, names
/// the real directory, and changes nothing.
#[cfg(unix)]
#[test]
fn purge_refuses_a_symlinked_entangle_dir_and_names_its_target() {
    let env = Env::new();
    let data = TempDir::new().unwrap();
    let real = data.path().join("entangle-data");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, env.dot()).unwrap();
    env.cmd().args(["init", "--headless"]).assert().success();
    assert!(real.join("identity.key").exists());

    let out = env
        .cmd()
        .args(["uninstall", "--purge", "--yes"])
        .assert()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("Deleted"),
        "must not claim a deletion:\n{stdout}{stderr}"
    );
    assert!(
        real.join("identity.key").exists() && std::fs::symlink_metadata(env.dot()).is_ok(),
        "nothing is deleted"
    );
    assert!(!out.status.success(), "{stdout}{stderr}");
    assert!(
        stderr.contains("ENTANGLE-E0790")
            && stderr.contains("symbolic link")
            && stderr.contains(&std::fs::canonicalize(&real).unwrap().display().to_string()),
        "{stderr}"
    );
}

/// An explicit `--no-wrapper` wins over an opt-in recorded earlier: it
/// writes no rc file, removes a shim already there and records the opt-out
/// (spec §8.3 item 2).
#[test]
fn no_wrapper_wins_over_a_recorded_opt_in() {
    let env = Env::new();
    env.cmd().args(["init", "--headless"]).assert().success();
    env.cmd().args(["wrapper", "enable"]).assert().success();
    env.cmd().args(["wrapper", "disable"]).assert().success();
    // Opted in by hand, with no shim installed.
    let cfg = env.dot().join("config.toml");
    let text = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        text.replace("[wrappers]\ninstall = false", "[wrappers]\ninstall = true"),
    )
    .unwrap();
    let fish = env.home.path().join(".config/fish/conf.d/entangle.fish");
    let has_block = |rc: &str| {
        std::fs::read_to_string(env.home.path().join(rc))
            .unwrap_or_default()
            .contains(">>> entangle wrapper >>>")
    };
    env.cmd()
        .args(["install", "--headless", "--no-wrapper"])
        .assert()
        .success();
    assert!(
        !has_block(".bashrc") && !has_block(".zshrc") && !fish.exists(),
        "--no-wrapper installed the shim"
    );
    assert!(std::fs::read_to_string(&cfg)
        .unwrap()
        .contains("[wrappers]\ninstall = false"));

    // And a shim installed earlier is removed.
    env.cmd().args(["wrapper", "enable"]).assert().success();
    assert!(has_block(".bashrc"));
    env.cmd()
        .args(["install", "--no-wrapper"])
        .write_stdin("")
        .assert()
        .success()
        .stdout(predicate::str::contains("--no-wrapper"));
    assert!(!has_block(".bashrc") && !has_block(".zshrc") && !fish.exists());
}

/// `~/.claude.json` is Claude Code's own app state, which it rewrites on
/// every run (sessions started by `entangle agent run claude-code` too):
/// it is not a config Entanglement vouches for, so a rewrite is not
/// reported as a change. `~/.claude/settings.json` still is.
#[test]
fn claude_codes_own_app_state_is_not_reported_as_changed() {
    let env = Env::new();
    let state = env.home.path().join(".claude.json");
    std::fs::write(&state, "{\"numStartups\":1}\n").unwrap();
    env.cmd()
        .args(["install", "--headless", "--no-wrapper"])
        .assert()
        .success();
    // What Claude Code does on its next start.
    std::fs::write(&state, "{\"numStartups\":2}\n").unwrap();
    let out = env
        .cmd()
        .arg("uninstall")
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("CHANGED"), "{stdout}");
    assert!(!stdout.contains(".claude.json"), "{stdout}");
    assert!(
        stdout.lines().any(|l| l.contains("claude-code")
            && l.contains(".claude/settings.json")
            && l.trim_end().ends_with("unchanged")),
        "{stdout}"
    );
}
