//! ATC-WRP-1..3 (spec §16.6, §8.3): the opt-in shell shim and its doctor check.
//!
//! The spec names `tests/bats/wrapper.bats` and `tests/bats/doctor.bats`;
//! these are the same propositions as Rust integration tests that drive a real
//! `bash` (and POSIX `sh`) with a temporary `$HOME`, fake agent binaries on a
//! temporary `PATH`, and the real `entangle` binary.
//!
//! The spec's illustrative `claude-code` is the *adapter* name; the executable
//! the user types is `Adapter::binary()`, i.e. `claude`, so the warning reads
//! "claude launched outside Entanglement session".
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

struct Env {
    _tmp: TempDir,
    home: PathBuf,
    /// Directory with fake agent binaries.
    bin: PathBuf,
}

fn entangle_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_entangle"))
}

fn exe(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        // Fake agent hosts: print their args, exit 7.
        for name in ["claude", "codex", "opencode"] {
            exe(&bin.join(name), &format!("echo \"real {name} $*\"; exit 7"));
        }
        Self {
            _tmp: tmp,
            home,
            bin,
        }
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.bin.display())
    }

    fn entangle(&self, args: &[&str]) -> Output {
        Command::new(entangle_bin())
            .args(args)
            .env("HOME", &self.home)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let o = self.entangle(args);
        assert!(
            o.status.success(),
            "entangle {args:?}: {}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    /// Run `script` in a fresh interactive `bash` (reads ~/.bashrc), with an
    /// optional `ENTANGLE_SESSION_ID`.
    fn bash(&self, script: &str, session: Option<&str>) -> Output {
        let mut c = Command::new("bash");
        c.args(["-i", "-c", script])
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", self.path())
            .stdin(Stdio::null());
        if let Some(s) = session {
            c.env("ENTANGLE_SESSION_ID", s);
        }
        c.output().unwrap()
    }

    fn rc(&self) -> String {
        std::fs::read_to_string(self.home.join(".bashrc")).unwrap_or_default()
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}
fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

// ---------------------------------------------------------------------------
// ATC-WRP-1
// ---------------------------------------------------------------------------

/// ATC-WRP-1 — GIVEN the user opted in to wrappers, WHEN they run the agent
/// host in a fresh shell with ENTANGLE_SESSION_ID unset, THEN stderr contains
/// "<bin> launched outside Entanglement session" AND the exit code matches
/// `command <bin> --version` (the warning is non-blocking). Inside a session
/// the shim is silent.
#[test]
fn atc_wrp_1_warns_outside_session() {
    let e = Env::new();
    e.ok(&["wrapper", "enable"]);

    let wrapped = e.bash("claude --version", None);
    let plain = e.bash("command claude --version", None);
    assert!(
        stderr(&wrapped).contains("claude launched outside Entanglement session"),
        "{}",
        stderr(&wrapped)
    );
    assert!(stderr(&wrapped).contains("entangle agent run claude-code"));
    assert!(stderr(&wrapped).contains("entangle wrapper disable"));
    assert_eq!(wrapped.status.code(), Some(7), "exit status is preserved");
    assert_eq!(wrapped.status.code(), plain.status.code());
    // Same stdout as the real binary (arguments are passed through intact).
    assert_eq!(stdout(&wrapped), stdout(&plain));
    assert_eq!(stdout(&wrapped), "real claude --version\n");
    assert!(
        !stderr(&plain).contains("launched outside"),
        "`command` bypasses the shim by design"
    );

    // Arguments with spaces / globs survive.
    let o = e.bash("codex 'a b' '*' ''", None);
    assert_eq!(stdout(&o), "real codex a b * \n");
    assert!(stderr(&o).contains("codex launched outside Entanglement session"));

    // Inside an Entanglement session the shim is silent but still runs the binary.
    let quiet = e.bash("claude --version", Some("sess-1"));
    assert!(
        !stderr(&quiet).contains("launched outside"),
        "{}",
        stderr(&quiet)
    );
    assert_eq!(quiet.status.code(), Some(7));
    assert_eq!(stdout(&quiet), "real claude --version\n");
}

/// The block is POSIX shell, so a plain `sh` (dash on Debian) can source it.
#[test]
fn wrp_1_block_works_in_posix_sh() {
    let e = Env::new();
    e.ok(&["wrapper", "enable"]);
    let run = |session: Option<&str>| {
        let mut c = Command::new("sh");
        c.args(["-c", ". \"$HOME/.bashrc\"; opencode x y"])
            .env_clear()
            .env("HOME", &e.home)
            .env("PATH", e.path())
            .stdin(Stdio::null());
        if let Some(s) = session {
            c.env("ENTANGLE_SESSION_ID", s);
        }
        c.output().unwrap()
    };
    let o = run(None);
    assert!(
        stderr(&o).contains("opencode launched outside Entanglement session"),
        "{}",
        stderr(&o)
    );
    assert_eq!(o.status.code(), Some(7));
    assert_eq!(stdout(&o), "real opencode x y\n");
    assert_eq!(stderr(&run(Some("s"))), "");
}

/// Shells we may not have installed: run the same proposition when present.
#[test]
fn wrp_1_zsh_and_fish_blocks_when_those_shells_exist() {
    let e = Env::new();
    e.ok(&["wrapper", "enable"]);
    let have = |s: &str| Command::new(s).arg("--version").output().is_ok();
    if have("zsh") {
        let o = Command::new("zsh")
            .args(["-i", "-c", "claude --version"])
            .env_clear()
            .env("HOME", &e.home)
            .env("ZDOTDIR", &e.home)
            .env("PATH", e.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(stderr(&o).contains("claude launched outside Entanglement session"));
        assert_eq!(o.status.code(), Some(7));
    }
    if have("fish") {
        let o = Command::new("fish")
            .args(["-c", "claude --version"])
            .env_clear()
            .env("HOME", &e.home)
            .env("PATH", e.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(stderr(&o).contains("claude launched outside Entanglement session"));
        assert_eq!(o.status.code(), Some(7));
    }
    // The fish snippet is always written, in fish syntax.
    let fish = std::fs::read_to_string(e.home.join(".config/fish/conf.d/entangle.fish")).unwrap();
    assert!(fish.contains("function claude --wraps claude") && fish.contains("$argv"));
    assert!(!fish.contains("() {"));
}

/// An `alias claude=...` defined earlier in the rc file (a common setup) must
/// not break the shim: interactive bash alias-expands the first word of
/// `claude() {`, which is a syntax error that also stops every later line of
/// the rc file from running. The alias is kept and still goes through the
/// shim; a one-word alias must not turn into a function of another name.
#[test]
fn wrp_1_existing_alias_before_the_block_keeps_rc_file_working() {
    let e = Env::new();
    exe(&e.bin.join("codex-beta"), "echo \"real codex-beta $*\"");
    std::fs::write(
        e.home.join(".bashrc"),
        "alias claude='claude --dangerously-skip-permissions'\nalias codex=codex-beta\n",
    )
    .unwrap();
    e.ok(&["init", "--non-interactive"]);
    e.ok(&["wrapper", "enable"]);
    let rc = e.rc();
    std::fs::write(e.home.join(".bashrc"), format!("{rc}export LATER=1\n")).unwrap();

    let o = e.bash(
        "echo LATER=$LATER; claude x; type -t codex-beta; alias claude",
        None,
    );
    let err = stderr(&o);
    assert!(!err.contains("syntax error"), "{err}");
    let out = stdout(&o);
    assert!(out.contains("LATER=1\n"), "rest of the rc file ran: {out}{err}");
    assert!(
        out.contains("real claude --dangerously-skip-permissions x\n"),
        "the user's alias is kept: {out}"
    );
    assert!(
        err.contains("claude launched outside Entanglement session"),
        "and still goes through the shim: {err}"
    );
    assert!(
        out.contains("\nfile\n"),
        "`codex-beta` is still the binary, not a shim function: {out}"
    );
    assert!(
        out.contains("alias claude='claude --dangerously-skip-permissions'"),
        "{out}"
    );

    // Doctor: an alias that expands to the wrapped name is not a shadow; one
    // that points elsewhere (codex -> codex-beta) is.
    let o = doctor(&e);
    let out = stdout(&o);
    assert!(!out.contains("'claude' is shadowed"), "{out}");
    assert!(
        out.contains("'codex' is shadowed by alias 'codex-beta'"),
        "{out}"
    );
}

/// Enable is idempotent and never disturbs the user's own rc content.
#[test]
fn enable_is_idempotent_and_preserves_user_content() {
    let e = Env::new();
    std::fs::write(e.home.join(".bashrc"), "export KEEP=1\nalias ll='ls -l'\n").unwrap();
    std::fs::set_permissions(
        e.home.join(".bashrc"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    e.ok(&["wrapper", "enable"]);
    let once = e.rc();
    e.ok(&["wrapper", "enable"]);
    assert_eq!(e.rc(), once, "second enable changes nothing");
    assert!(once.starts_with("export KEEP=1\nalias ll='ls -l'\n"));
    assert_eq!(once.matches("# >>> entangle wrapper >>>").count(), 1);
    let mode = std::fs::metadata(e.home.join(".bashrc"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "permissions kept");
    // All three files are written and `status` reports each.
    let st = e.ok(&["wrapper", "status"]);
    assert!(st.contains("wrappers: enabled"), "{st}");
    for f in ["~/.bashrc", "~/.zshrc", "entangle.fish"] {
        assert!(st.contains(f), "{st}");
    }
    assert_eq!(st.matches("installed").count(), 3, "{st}");
    for host in ["claude", "codex", "opencode"] {
        assert!(once.contains(&format!("{host}() {{")), "{host}");
    }
}

/// `repair` rewrites a duplicated or damaged block; `enable` refuses to guess.
#[test]
fn repair_fixes_duplicated_and_damaged_blocks() {
    let e = Env::new();
    e.ok(&["wrapper", "enable"]);
    let good = e.rc();
    // Duplicate the block and add a user line between the copies.
    std::fs::write(e.home.join(".bashrc"), format!("{good}\nmid\n{good}")).unwrap();
    assert!(e.ok(&["wrapper", "status"]).contains("2 wrapper blocks"));
    let refused = e.entangle(&["wrapper", "enable"]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("ENTANGLE-E0751"),
        "{}",
        stderr(&refused)
    );
    e.ok(&["wrapper", "repair"]);
    assert_eq!(e.rc().matches("# >>> entangle wrapper >>>").count(), 1);
    assert!(e.rc().contains("\nmid\n"), "user line kept");
    // Damaged: drop the end marker.
    let broken = e.rc().replace("# <<< entangle wrapper <<<", "");
    std::fs::write(e.home.join(".bashrc"), broken).unwrap();
    assert!(e.ok(&["wrapper", "status"]).contains("damaged block"));
    e.ok(&["wrapper", "repair"]);
    let st = e.ok(&["wrapper", "status"]);
    assert_eq!(st.matches("installed").count(), 3, "{st}");
    assert!(e.rc().contains("\nmid\n"));
}

// ---------------------------------------------------------------------------
// ATC-WRP-2
// ---------------------------------------------------------------------------

/// ATC-WRP-2 — GIVEN `entangle wrapper disable` has run, WHEN the user runs
/// the agent host, THEN stderr does NOT contain the wrapper warning. The
/// choice is recorded in config.toml and nothing else in the rc file moves.
#[test]
fn atc_wrp_2_disable_silences() {
    let e = Env::new();
    let original = "export KEEP=1\n";
    std::fs::write(e.home.join(".bashrc"), original).unwrap();
    e.ok(&["wrapper", "enable"]);
    assert!(stderr(&e.bash("claude", None)).contains("launched outside"));

    let out = e.ok(&["wrapper", "disable"]);
    assert!(
        out.contains("DISABLED") && out.contains("install = false"),
        "{out}"
    );

    let o = e.bash("claude --version", None);
    assert!(
        !stderr(&o).contains("launched outside Entanglement session"),
        "{}",
        stderr(&o)
    );
    assert_eq!(o.status.code(), Some(7));
    assert_eq!(stdout(&o), "real claude --version\n");
    // Block gone, user content restored byte-for-byte, choice recorded.
    assert_eq!(e.rc(), original);
    assert!(!e.home.join(".config/fish/conf.d/entangle.fish").exists());
    let cfg = std::fs::read_to_string(e.home.join(".entangle/config.toml")).unwrap();
    assert!(
        cfg.contains("[wrappers]") && cfg.contains("install = false"),
        "{cfg}"
    );
    assert!(e.ok(&["wrapper", "status"]).contains("wrappers: disabled"));

    // Enable sets it back.
    e.ok(&["wrapper", "enable"]);
    let cfg = std::fs::read_to_string(e.home.join(".entangle/config.toml")).unwrap();
    assert!(cfg.contains("install = true"), "{cfg}");
    assert!(stderr(&e.bash("claude", None)).contains("launched outside"));
}

/// Config writes keep everything the typed CLI config does not know about.
#[test]
fn wrapper_config_writes_preserve_unknown_sections_and_comments() {
    let e = Env::new();
    std::fs::create_dir_all(e.home.join(".entangle")).unwrap();
    let original = "# my notes\n[mesh]\ntransports = [\"local\"] # lan\n\n[mesh.tailscale]\nenabled = false\n\n[security]\nmax_tier_allowed = 4\n\n[metrics]\nlisten = \"127.0.0.1:9100\"\n\n[telemetry]\nopt_in = false\n";
    std::fs::write(e.home.join(".entangle/config.toml"), original).unwrap();
    e.ok(&["wrapper", "enable"]);
    let cfg = std::fs::read_to_string(e.home.join(".entangle/config.toml")).unwrap();
    assert!(cfg.starts_with(original), "{cfg}");
    assert!(cfg.ends_with("[wrappers]\ninstall = true\n"), "{cfg}");
    e.ok(&["wrapper", "disable"]);
    let cfg = std::fs::read_to_string(e.home.join(".entangle/config.toml")).unwrap();
    assert!(
        cfg.starts_with(original) && cfg.contains("install = false"),
        "{cfg}"
    );
}

// ---------------------------------------------------------------------------
// ATC-WRP-3
// ---------------------------------------------------------------------------

fn doctor(e: &Env) -> Output {
    Command::new(entangle_bin())
        .arg("doctor")
        .env_clear()
        .env("HOME", &e.home)
        .env("PATH", e.path())
        .env("SHELL", "/bin/bash")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn wrapper_line(o: &Output) -> String {
    stdout(o)
        .lines()
        .find(|l| l.contains(" wrapper "))
        .unwrap_or_default()
        .to_owned()
}

/// ATC-WRP-3 — GIVEN the shell resolves `claude` to /…/bin/claude before the
/// shell function, WHEN `entangle doctor` runs, THEN stdout contains
/// "shadowed" (with the shadow source) AND the exit code is 1.
#[test]
fn atc_wrp_3_detects_shadowed_wrapper() {
    let e = Env::new();
    e.ok(&["init", "--non-interactive"]);
    e.ok(&["wrapper", "enable"]);

    // Healthy first: wrapper row is ok and names no shadow.
    let healthy = doctor(&e);
    assert!(
        wrapper_line(&healthy).contains("[ok]"),
        "{}",
        stdout(&healthy)
    );
    assert!(!stdout(&healthy).contains("shadowed"));

    // The function is removed after the block (as a later rc line, a plugin
    // manager, or a login profile would): bash now finds the file on PATH.
    let rc = e.rc();
    std::fs::write(e.home.join(".bashrc"), format!("{rc}\nunset -f claude\n")).unwrap();
    let o = doctor(&e);
    let out = stdout(&o);
    assert!(out.contains("shadowed"), "{out}");
    let src = format!("{}/claude", e.bin.display());
    assert!(out.contains(&src), "names the shadow source {src}: {out}");
    assert!(out.contains("entangle wrapper repair"), "{out}");
    assert!(wrapper_line(&o).contains("[fail]"), "{out}");
    assert_eq!(o.status.code(), Some(1), "{out}");

    // An alias defined after the block shadows it too.
    std::fs::write(
        e.home.join(".bashrc"),
        format!("{rc}\nalias claude='/opt/other/claude --fast'\n"),
    )
    .unwrap();
    let o = doctor(&e);
    assert!(
        stdout(&o).contains("shadowed by alias '/opt/other/claude --fast'"),
        "{}",
        stdout(&o)
    );
    assert_eq!(o.status.code(), Some(1));

    // So does a different function of the same name.
    std::fs::write(
        e.home.join(".bashrc"),
        format!("{rc}\nclaude() {{ echo mine; }}\n"),
    )
    .unwrap();
    let o = doctor(&e);
    assert!(
        stdout(&o).contains("shadowed by a different shell function"),
        "{}",
        stdout(&o)
    );
    assert_eq!(o.status.code(), Some(1));

    // Repair restores a healthy state and a clean doctor.
    e.ok(&["wrapper", "disable"]);
    e.ok(&["wrapper", "enable"]);
    let o = doctor(&e);
    assert!(wrapper_line(&o).contains("[ok]"), "{}", stdout(&o));
}

/// Wrappers enabled but the block missing: a warning naming
/// `entangle wrapper enable`; not enabled: skipped (opt-in).
#[test]
fn doctor_wrapper_missing_block_warns_and_opt_in_skips() {
    let e = Env::new();
    e.ok(&["init", "--non-interactive"]);
    // Not opted in: skip.
    let o = doctor(&e);
    assert!(wrapper_line(&o).contains("[skip]"), "{}", stdout(&o));
    // Opted in by config but no block anywhere.
    e.ok(&["wrapper", "enable"]);
    for f in [".bashrc", ".zshrc"] {
        std::fs::write(e.home.join(f), "# nothing here\n").unwrap();
    }
    std::fs::remove_file(e.home.join(".config/fish/conf.d/entangle.fish")).unwrap();
    let o = doctor(&e);
    let line = wrapper_line(&o);
    assert!(
        line.contains("[warn]") && line.contains("entangle wrapper enable"),
        "{}",
        stdout(&o)
    );
    assert!(!stdout(&o).contains("shadowed"));
}

/// An rc file that blocks is cut off by the probe timeout: doctor warns that
/// it could not check instead of hanging.
#[test]
fn doctor_probe_timeout_cuts_off_a_hanging_rc_file() {
    let e = Env::new();
    e.ok(&["init", "--non-interactive"]);
    e.ok(&["wrapper", "enable"]);
    let rc = e.rc();
    std::fs::write(e.home.join(".bashrc"), format!("{rc}\nsleep 60\n")).unwrap();
    let t = std::time::Instant::now();
    let o = Command::new(entangle_bin())
        .arg("doctor")
        .env_clear()
        .env("HOME", &e.home)
        .env("PATH", e.path())
        .env("SHELL", "/bin/bash")
        .env("ENTANGLE_DOCTOR_PROBE_TIMEOUT_MS", "700")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(t.elapsed() < std::time::Duration::from_secs(30));
    let line = wrapper_line(&o);
    assert!(
        line.contains("[warn]") && line.contains("shadow check could not run"),
        "{}",
        stdout(&o)
    );
}

/// `$SHELL` that is not bash/zsh: the shadow check is skipped and says so.
#[test]
fn doctor_skips_shadow_check_for_unsupported_shell() {
    let e = Env::new();
    e.ok(&["init", "--non-interactive"]);
    e.ok(&["wrapper", "enable"]);
    let o = Command::new(entangle_bin())
        .arg("doctor")
        .env_clear()
        .env("HOME", &e.home)
        .env("PATH", e.path())
        .env("SHELL", "/usr/bin/fish")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let line = wrapper_line(&o);
    assert!(
        line.contains("[ok]") && line.contains("only bash and zsh are probed"),
        "{}",
        stdout(&o)
    );
}

