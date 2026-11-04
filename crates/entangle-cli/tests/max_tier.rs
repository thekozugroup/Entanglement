//! ATC-MAX-1..3 (spec §16.7, §9.4.1): lowering `[security] max_tier_allowed`
//! below the tier of loaded plugins.
//!
//! The spec names `tests/bats/max_tier.bats`; these are the same propositions
//! as Rust integration tests. A real daemon (the `entangle-bin` kernel +
//! Unix-socket RPC server) runs in-process with signed Wasm plugins loaded at
//! tiers 5, 4 and 2; the real `entangle` binary is driven against it with a
//! temporary `$HOME`. The interactive prompt is exercised through a real pty
//! (`script`), so `stdin` is a terminal.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use entangle_bin::{config as dcfg, server, state::DaemonState};
use entangle_broker::AuditKind;
use entangle_peers::PeerStore;
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use tempfile::TempDir;

fn entangle_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_entangle"))
}

fn hello_pong() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .expect("hello-pong fixture")
}

/// Build `examples/native-echo` once per test binary (separate target dir,
/// shared with entangle-runtime's native e2e test) and return its bytes. Tier
/// 4 and 5 plugins must be native (a Wasm component is capped at tier 3).
fn native_echo() -> &'static [u8] {
    static BIN: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        let target_dir = root.join("target").join("native-examples");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let status = Command::new(cargo)
            .args(["build", "--quiet", "--manifest-path"])
            .arg(root.join("examples/native-echo/Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .status()
            .expect("cargo build examples/native-echo");
        assert!(status.success(), "building examples/native-echo failed");
        std::fs::read(target_dir.join("debug/entangle-native-echo")).expect("native-echo binary")
    })
}

/// Write a signed package for `name` at `tier`; returns (dir, plugin id).
fn package(root: &Path, kp: &IdentityKeyPair, name: &str, tier: u8) -> (PathBuf, String) {
    let dir = root.join(format!("pkg-{name}"));
    std::fs::create_dir_all(&dir).unwrap();
    let id = format!("{}/{name}@0.1.0", kp.fingerprint_hex());
    let (runtime, art, file, caps) = if tier >= 4 {
        (
            "native",
            native_echo().to_vec(),
            "plugin.bin",
            "\"storage.local\" = { scope = \"plugin\" }",
        )
    } else {
        ("wasm", hello_pong(), "plugin.wasm", "")
    };
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = {tier}\nruntime = \"{runtime}\"\n\n[capabilities]\n{caps}\n"
    );
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join(file), &art).unwrap();
    let bundle = sign_artifact(&art, manifest.as_bytes(), kp);
    std::fs::write(
        dir.join(format!("{file}.sig")),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    (dir, id)
}

struct Fixture {
    _tmp: TempDir,
    /// The trusted publisher key the fixture's packages are signed with.
    kp: IdentityKeyPair,
    home: PathBuf,
    state: Arc<DaemonState>,
    pkgs: std::collections::BTreeMap<&'static str, (PathBuf, String)>,
}

impl Fixture {
    /// `[security] max_tier_allowed = 5` on disk and in the daemon; plugins
    /// `agent-host` (tier 5), `cuda-runner` (tier 4), `tiny` (tier 2) loaded.
    /// `extra_config` is appended to config.toml.
    async fn new(extra_config: &str, serve: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("h");
        let cdir = home.join(".entangle");
        std::fs::create_dir_all(&cdir).unwrap();
        let base = "[security]\nmax_tier_allowed = 5\n";
        std::fs::write(cdir.join("config.toml"), base).unwrap();
        let cfg = dcfg::load_config(&cdir.join("config.toml")).unwrap();
        // Sections the daemon would not accept are only used by tests that run
        // no daemon: written after the kernel is built.
        std::fs::write(cdir.join("config.toml"), format!("{base}{extra_config}")).unwrap();

        let kp = IdentityKeyPair::generate();
        let mut kr = Keyring::new();
        kr.add(TrustEntry {
            fingerprint: kp.fingerprint(),
            public_key: *kp.public().as_bytes(),
            publisher_name: "atc-max".into(),
            added_at: 0,
            note: String::new(),
        });
        let kernel = Arc::new(Kernel::new(dcfg::kernel_config(&cfg, &cdir), kr).unwrap());
        let pool = WorkerPool::new();
        let identity = IdentityKeyPair::generate();
        let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
        let dispatcher = Arc::new(Dispatcher::new(pool.clone(), kernel.clone(), local));
        let state = Arc::new(DaemonState::new(
            kernel,
            dispatcher,
            pool,
            PeerStore::new(),
            identity,
            "atc-max".into(),
        ));

        let mut pkgs = std::collections::BTreeMap::new();
        for (name, tier) in [("agent-host", 5u8), ("cuda-runner", 4), ("tiny", 2)] {
            let p = package(tmp.path(), &kp, name, tier);
            state.kernel.load_plugin_from_dir(&p.0).await.unwrap();
            pkgs.insert(name, p);
        }
        if serve {
            let sock = cdir.join("sock");
            let st = state.clone();
            tokio::spawn(async move {
                let _ = server::serve(sock.clone(), st).await;
            });
            for _ in 0..200 {
                if cdir.join("sock").exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(cdir.join("sock").exists(), "daemon socket never appeared");
        }
        Self {
            _tmp: tmp,
            kp,
            home,
            state,
            pkgs,
        }
    }

    fn config_path(&self) -> PathBuf {
        self.home.join(".entangle/config.toml")
    }
    fn config(&self) -> String {
        std::fs::read_to_string(self.config_path()).unwrap()
    }
    fn id(&self, name: &str) -> String {
        self.pkgs[name].1.clone()
    }
    fn loaded(&self) -> Vec<String> {
        self.state
            .kernel
            .list_plugins()
            .iter()
            .map(|p| p.to_string())
            .collect()
    }
    /// Lines of `~/.entangle/audit.log` that carry `code`.
    fn audit_file(&self, code: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.home.join(".entangle/audit.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|v| v["code"] == code)
            .collect()
    }
    /// Broker audit events with `code`.
    fn audit_broker(&self, kind: AuditKind) -> Vec<entangle_broker::AuditEvent> {
        self.state
            .kernel
            .broker()
            .audit_log()
            .snapshot()
            .into_iter()
            .filter(|e| e.kind() == kind)
            .collect()
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(entangle_bin());
        c.args(args)
            .env("HOME", &self.home)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::null());
        c
    }
}

fn run_blocking(mut c: Command) -> std::process::Output {
    c.output().unwrap()
}

/// What a run on a pty produced. `stdout` is the terminal transcript of the
/// CLI's stdout only (what the user sees at the prompt); `stderr` was
/// redirected to a file inside the pty command, so the two never mix.
struct Tty {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run `entangle <args>` on a pty (so stdin/stdout are terminals), stderr
/// captured separately. With `expect_prompt`, wait until "Decision [u/c]:" is
/// on screen, run `at_prompt` (while the CLI waits for the answer), then type
/// `input`; otherwise just type `input`. Every wait has a deadline: a CLI that
/// hangs fails the test instead of hanging CI.
fn run_pty(
    home: &Path,
    args: &[&str],
    expect_prompt: bool,
    at_prompt: impl FnOnce(),
    input: &str,
) -> Tty {
    use std::io::{Read as _, Write as _};
    // The pty tests need util-linux `script`; a missing one is a failure, not
    // a silent pass (the interactive half of the spec would go unchecked).
    assert!(
        have_script(),
        "util-linux `script` is required for the pty tests (ATC-MAX-1/3)"
    );
    let err_file = home.parent().unwrap_or(home).join("pty-stderr.txt");
    let _ = std::fs::remove_file(&err_file);
    let mut cmdline = format!("'{}'", entangle_bin().display());
    for a in args {
        cmdline.push_str(&format!(" '{a}'"));
    }
    cmdline.push_str(&format!(" 2>'{}'", err_file.display()));
    let mut child = Command::new("script")
        .args(["-qec", &cmdline, "/dev/null"])
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawning `script`");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let screen = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let reader = {
        let screen = screen.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                screen.lock().unwrap().extend_from_slice(&chunk[..n]);
            }
        })
    };
    let shown = || String::from_utf8_lossy(&screen.lock().unwrap()).into_owned();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    if expect_prompt {
        while !shown().contains("Decision [u/c]:") {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                panic!("the prompt never appeared: {}", shown());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    at_prompt();
    stdin.write_all(input.as_bytes()).unwrap();
    stdin.flush().unwrap();
    // Keep stdin open until the child exits so `script` forwards no early EOF.
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("the CLI never exited: {}", shown());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    drop(stdin);
    reader.join().unwrap();
    Tty {
        code: status.code().unwrap_or(-1),
        stdout: shown().replace('\r', ""),
        stderr: std::fs::read_to_string(&err_file).unwrap_or_default(),
    }
}

/// [`run_pty`] for a CLI that prompts: type `input` at the prompt.
fn run_on_tty(home: &Path, args: &[&str], input: &str) -> Tty {
    run_pty(home, args, true, || {}, input)
}

fn have_script() -> bool {
    Command::new("script")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// ATC-MAX-1
// ---------------------------------------------------------------------------

/// ATC-MAX-1 — GIVEN a daemon with max_tier_allowed = 5 AND tier-5 plugin
/// "agent-host" loaded, WHEN the user lowers to 3 via interactive
/// `entangle config reload`, THEN stdout contains "agent-host" in the
/// affected list AND the default action is unload-and-disable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn atc_max_1_interactive_lowering_prompts() {
    let f = Fixture::new("", true).await;
    // The operator edits the file by hand (comment must survive the edit).
    let edited = f
        .config()
        .replace("max_tier_allowed = 5", "max_tier_allowed = 3 # lowered");
    std::fs::write(f.config_path(), &edited).unwrap();

    // An empty answer (just Enter) takes the default.
    let home = f.home.clone();
    let t = tokio::task::spawn_blocking(move || run_on_tty(&home, &["config", "reload"], "\n"))
        .await
        .unwrap();
    let (code, out) = (t.code, t.stdout.as_str());

    assert_eq!(code, 0, "{out}");
    assert!(out.contains("will affect 2 running plugins"), "{out}");
    // The affected list is on STDOUT (the transcript holds stdout only; the
    // post-unload W0214 lines went to stderr) and precedes the choices.
    let (listing, choices) = out
        .split_once("Choose action:")
        .unwrap_or_else(|| panic!("no prompt on stdout: {out}"));
    for (name, tier) in [("agent-host", 5), ("cuda-runner", 4)] {
        let id = f.id(name);
        let line = listing
            .lines()
            .find(|l| l.contains(&id))
            .unwrap_or_else(|| panic!("{name} missing from the stdout list: {out}"));
        assert!(
            line.starts_with("  - ") && line.contains(&format!("(tier {tier}, native subprocess,")),
            "{line:?}"
        );
    }
    assert!(
        !out.contains("/tiny@"),
        "tier-2 plugin is not affected: {out}"
    );
    assert!(
        choices.contains("[u] unload-and-disable  (default"),
        "{out}"
    );
    assert!(choices.contains("Decision [u/c]:"), "{out}");
    assert!(
        !t.stdout.contains("ENTANGLE-W0214") && t.stderr.contains("ENTANGLE-W0214"),
        "W0214 is a stderr line: {out}"
    );

    // Default = unload-and-disable.
    assert_eq!(
        f.loaded(),
        vec![f.id("tiny")],
        "only the tier-2 plugin stays"
    );
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 3);
    let cfg = f.config();
    assert!(cfg.contains("max_tier_allowed = 3 # lowered"), "{cfg}");
    assert!(
        cfg.contains(&f.id("agent-host")) && cfg.contains(&f.id("cuda-runner")),
        "{cfg}"
    );
    assert!(cfg.contains("disabled"), "{cfg}");
    assert_eq!(f.audit_file("ENTANGLE-W0214").len(), 2);
    assert_eq!(f.audit_file("ENTANGLE-I0215").len(), 1);
}

// ---------------------------------------------------------------------------
// ATC-MAX-2
// ---------------------------------------------------------------------------

/// ATC-MAX-2 — GIVEN the same precondition, WHEN
/// `entangle security set-max-tier 3 --force-unload` runs, THEN stderr
/// contains the affected-plugin list AND the audit log has an
/// ENTANGLE-W0214 entry per plugin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn atc_max_2_force_unload_is_loud() {
    let f = Fixture::new("", true).await;
    let mut c = f.cmd(&["security", "set-max-tier", "3", "--force-unload"]);
    let out = tokio::task::spawn_blocking(move || {
        run_blocking(std::mem::replace(&mut c, Command::new("true")))
    })
    .await
    .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stderr}\n{stdout}");

    // The affected list is on stderr, with tiers.
    assert!(
        stderr.contains(&f.id("agent-host")) && stderr.contains("tier 5"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&f.id("cuda-runner")) && stderr.contains("tier 4"),
        "{stderr}"
    );
    assert!(!stderr.contains(&f.id("tiny")), "{stderr}");
    assert_eq!(stderr.matches("ENTANGLE-W0214").count(), 2, "{stderr}");

    // Durable operator audit trail: one W0214 per unloaded plugin.
    let w = f.audit_file("ENTANGLE-W0214");
    let mut plugins: Vec<_> = w
        .iter()
        .map(|v| v["plugin"].as_str().unwrap().to_owned())
        .collect();
    plugins.sort();
    let mut want = vec![f.id("agent-host"), f.id("cuda-runner")];
    want.sort();
    assert_eq!(plugins, want);
    // Daemon-side (broker) audit log: one W0214 per plugin, grants released.
    let ev = f.audit_broker(AuditKind::PluginDisabledByCeiling);
    assert_eq!(ev.len(), 2);
    assert!(ev.iter().all(|e| e.code() == Some("ENTANGLE-W0214")));
    assert_eq!(f.audit_broker(AuditKind::PluginUnregistered).len(), 2);

    // State: ceiling lowered in daemon and file, plugins gone and disabled.
    assert_eq!(f.loaded(), vec![f.id("tiny")]);
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 3);
    let cfg = f.config();
    assert!(cfg.contains("max_tier_allowed = 3"), "{cfg}");
    assert!(cfg.contains(&f.id("agent-host")), "{cfg}");

    // Later loads above the ceiling fail with the existing E0043; below work.
    let err = f
        .state
        .kernel
        .load_plugin_from_dir(&f.pkgs["agent-host"].0)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ENTANGLE-E0043"), "{err}");
}

/// Without a terminal and without `--force-unload`, lowering over loaded
/// plugins is refused and changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lowering_without_tty_or_force_is_refused_and_changes_nothing() {
    let f = Fixture::new("", true).await;
    let before = f.config();
    let mut c = f.cmd(&["security", "set-max-tier", "3"]);
    let out = tokio::task::spawn_blocking(move || {
        run_blocking(std::mem::replace(&mut c, Command::new("true")))
    })
    .await
    .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("ENTANGLE-E0753"), "{stderr}");
    assert!(stderr.contains(&f.id("agent-host")), "{stderr}");
    assert_eq!(f.config(), before);
    assert_eq!(f.loaded().len(), 3);
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 5);
}

/// Raising the ceiling never unloads anything; lowering to a value above all
/// loaded tiers needs no confirmation either (and is audited).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raising_or_harmless_lowering_never_unloads() {
    let f = Fixture::new("", true).await;
    // Lowering 5 -> 4 would affect the tier-5 plugin: consent with --force-unload.
    let mut c = f.cmd(&["security", "set-max-tier", "4", "--force-unload"]);
    let out = tokio::task::spawn_blocking(move || {
        run_blocking(std::mem::replace(&mut c, Command::new("true")))
    })
    .await
    .unwrap();
    assert!(out.status.success());
    assert_eq!(
        f.loaded().len(),
        2,
        "tier-5 plugin unloaded, tier 4 and 2 stay"
    );
    // Raise back to 5: nothing else changes, nothing unloads.
    let mut c = f.cmd(&["security", "set-max-tier", "5"]);
    let out = tokio::task::spawn_blocking(move || {
        run_blocking(std::mem::replace(&mut c, Command::new("true")))
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("raised 4 -> 5") && stdout.contains("nothing was unloaded"),
        "{stdout}"
    );
    assert_eq!(f.loaded().len(), 2);
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 5);
    assert_eq!(
        f.audit_file("ENTANGLE-W0214").len(),
        1,
        "only the first call unloaded"
    );
    // Harmless lowering: no loaded plugin is above 4 any more, so 5 -> 4
    // needs no confirmation (no flag, no terminal), unloads nothing and is
    // audited as I0215 with zero plugins affected.
    let mut c = f.cmd(&["security", "set-max-tier", "4"]);
    let out = tokio::task::spawn_blocking(move || {
        run_blocking(std::mem::replace(&mut c, Command::new("true")))
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("lowered 5 -> 4") && stdout.contains("no loaded plugin is above it"),
        "{stdout}"
    );
    assert_eq!(f.loaded().len(), 2, "nothing was unloaded");
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 4);
    assert_eq!(
        f.audit_file("ENTANGLE-W0214").len(),
        1,
        "still only the first call"
    );
    let harmless: Vec<_> = f
        .audit_file("ENTANGLE-I0215")
        .into_iter()
        .filter(|v| v["unloaded"] == 0)
        .collect();
    assert_eq!(harmless.len(), 1, "{harmless:?}");
    assert_eq!(harmless[0]["old_ceiling"], 5);
    assert_eq!(harmless[0]["new_ceiling"], 4);
    // Out-of-range values are rejected before anything is touched.
    let out = f.cmd(&["security", "set-max-tier", "9"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("ENTANGLE-E0752"));
}

/// Spec §9.4.1: raising the ceiling is "a privileged, audited operation".
/// Every change of the ceiling is audited — in the daemon's broker log and in
/// the durable `~/.entangle/audit.log` — whether it lowers or raises it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raising_the_ceiling_is_audited() {
    let f = Fixture::new("", true).await;
    for args in [
        &["security", "set-max-tier", "4", "--force-unload"][..],
        &["security", "set-max-tier", "5"][..],
    ] {
        let mut c = f.cmd(args);
        let out = tokio::task::spawn_blocking(move || {
            run_blocking(std::mem::replace(&mut c, Command::new("true")))
        })
        .await
        .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 5);
    let raised = f.audit_file("ENTANGLE-I0217");
    assert_eq!(raised.len(), 1, "{raised:?}");
    assert_eq!(raised[0]["old_ceiling"], 4);
    assert_eq!(raised[0]["new_ceiling"], 5);
    let daemon: Vec<_> = f
        .state
        .kernel
        .broker()
        .audit_log()
        .snapshot()
        .into_iter()
        .filter(|e| e.code() == Some("ENTANGLE-I0217"))
        .collect();
    assert_eq!(daemon.len(), 1, "{daemon:?}");
}

/// Without a daemon the change is still audited in the durable trail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ceiling_changes_without_daemon_are_audited() {
    let f = Fixture::new("", false).await;
    for n in ["3", "4"] {
        let out = f.cmd(&["security", "set-max-tier", n]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let lowered = f.audit_file("ENTANGLE-I0215");
    assert_eq!(lowered.len(), 1, "{lowered:?}");
    assert_eq!(lowered[0]["old_ceiling"], 5);
    assert_eq!(lowered[0]["new_ceiling"], 3);
    let raised = f.audit_file("ENTANGLE-I0217");
    assert_eq!(raised.len(), 1, "{raised:?}");
    assert_eq!(raised[0]["old_ceiling"], 3);
    assert_eq!(raised[0]["new_ceiling"], 4);
}

/// The daemon is only changed once config.toml is known to be editable, and
/// the file is written right after the daemon applied the change — before the
/// durable audit lines — so a later failure cannot leave the daemon lowered
/// with the old ceiling still in config.toml (restored at the next start).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_log_failure_after_lowering_still_persists_the_config() {
    let f = Fixture::new("", true).await;
    // An audit log that cannot be opened for appending.
    std::fs::create_dir_all(f.home.join(".entangle/audit.log")).unwrap();
    let mut c = f.cmd(&["security", "set-max-tier", "3", "--force-unload"]);
    let out = tokio::task::spawn_blocking(move || {
        run_blocking(std::mem::replace(&mut c, Command::new("true")))
    })
    .await
    .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the audit failure is reported: {stderr}"
    );
    assert!(stderr.contains("audit log"), "{stderr}");
    // The daemon was lowered, so config.toml must say so too.
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 3);
    let cfg = f.config();
    assert!(cfg.contains("max_tier_allowed = 3"), "{cfg}");
    assert!(
        cfg.contains(&f.id("agent-host")) && cfg.contains(&f.id("cuda-runner")),
        "{cfg}"
    );
}

/// A config.toml the CLI cannot edit (valid TOML the daemon accepts, but an
/// inline `[security]` table) is refused before the daemon is touched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uneditable_config_is_refused_before_the_daemon_changes() {
    let f = Fixture::new("", true).await;
    std::fs::write(f.config_path(), "security = { max_tier_allowed = 5 }\n").unwrap();
    let mut c = f.cmd(&["security", "set-max-tier", "3", "--force-unload"]);
    let out = tokio::task::spawn_blocking(move || {
        run_blocking(std::mem::replace(&mut c, Command::new("true")))
    })
    .await
    .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("ENTANGLE-E0754"), "{stderr}");
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 5, "{stderr}");
    assert_eq!(f.loaded().len(), 3, "nothing was unloaded: {stderr}");
    assert!(f.audit_file("ENTANGLE-W0214").is_empty());
    assert_eq!(f.config(), "security = { max_tier_allowed = 5 }\n");
}

/// `--yes` answers the prompt; without a terminal there is no prompt, so it
/// is refused like no flag at all (ENTANGLE-E0753). Only `--force-unload`
/// is the non-interactive path (spec §9.4.1 step 6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yes_without_a_terminal_is_refused() {
    let f = Fixture::new("", true).await;
    let before = f.config();
    let mut c = f.cmd(&["security", "set-max-tier", "3", "--yes"]);
    let out = tokio::task::spawn_blocking(move || {
        run_blocking(std::mem::replace(&mut c, Command::new("true")))
    })
    .await
    .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("ENTANGLE-E0753"), "{stderr}");
    assert_eq!(f.loaded().len(), 3);
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 5);
    assert_eq!(f.config(), before);
}

/// With no daemon nothing is loaded: the config is edited, preserving
/// everything else, and the operator is told so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_max_tier_without_daemon_edits_config_only() {
    let f = Fixture::new(
        "\n[mesh.tailscale]\nenabled = false # keep\n\n[telemetry]\nopt_in = false\n",
        false,
    )
    .await;
    let out = f.cmd(&["security", "set-max-tier", "3"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("daemon not running"), "{stderr}");
    let cfg = f.config();
    assert!(cfg.contains("max_tier_allowed = 3"), "{cfg}");
    assert!(
        cfg.contains("[mesh.tailscale]\nenabled = false # keep") && cfg.contains("[telemetry]"),
        "{cfg}"
    );
}

// ---------------------------------------------------------------------------
// ATC-MAX-3
// ---------------------------------------------------------------------------

/// ATC-MAX-3 — GIVEN the same precondition, WHEN the user chooses "cancel"
/// at the prompt, THEN max_tier_allowed remains 5 in config.toml AND the audit
/// log has an ENTANGLE-I0216 entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn atc_max_3_cancel_reverts_edit() {
    let f = Fixture::new("", true).await;
    let edited = f
        .config()
        .replace("max_tier_allowed = 5", "max_tier_allowed = 3");
    std::fs::write(f.config_path(), &edited).unwrap();

    let home = f.home.clone();
    let t = tokio::task::spawn_blocking(move || run_on_tty(&home, &["config", "reload"], "c\n"))
        .await
        .unwrap();
    let (code, out) = (t.code, format!("{}{}", t.stdout, t.stderr));

    assert_eq!(
        code, 1,
        "cancel exits non-zero so scripts cannot mistake it for success: {out}"
    );
    assert!(out.contains("agent-host"), "{out}");
    assert!(
        out.contains("Cancelled") && out.contains("ENTANGLE-I0216"),
        "{out}"
    );
    // Edit reverted, ceiling and plugins untouched.
    assert!(
        f.config().contains("max_tier_allowed = 5"),
        "{}",
        f.config()
    );
    assert!(!f.config().contains("max_tier_allowed = 3"));
    assert_eq!(f.loaded().len(), 3);
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 5);
    // Audited in the durable trail and in the daemon's broker log.
    let i = f.audit_file("ENTANGLE-I0216");
    assert_eq!(i.len(), 1, "{i:?}");
    assert_eq!(i[0]["requested_ceiling"], 3);
    assert_eq!(i[0]["current_ceiling"], 5);
    let ev = f.audit_broker(AuditKind::CeilingLoweringCancelled);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].code(), Some("ENTANGLE-I0216"));
    assert!(f.audit_file("ENTANGLE-W0214").is_empty());
}

/// Spec §9.4.1: the operator is prompted "with the list" and nothing is
/// unloaded silently. A plugin loaded while the prompt waits for an answer
/// was not on the list the operator confirmed: the daemon refuses
/// (ENTANGLE-E0758) instead of unloading it unseen, and nothing changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_loaded_while_prompting_is_not_unloaded_unconfirmed() {
    let f = Fixture::new("", true).await;
    let (late_dir, late_id) = package(f._tmp.path(), &f.kp, "late-gpu", 4);
    let before = f.config();
    let home = f.home.clone();
    let state = f.state.clone();
    let rt = tokio::runtime::Handle::current();
    let t = tokio::task::spawn_blocking(move || {
        run_pty(
            &home,
            &["security", "set-max-tier", "3"],
            true,
            || {
                rt.block_on(state.kernel.load_plugin_from_dir(&late_dir))
                    .expect("late load");
            },
            "u\n",
        )
    })
    .await
    .unwrap();
    let (code, out) = (t.code, format!("{}{}", t.stdout, t.stderr));

    assert!(
        !out.contains(&format!("unloaded and disabled {late_id}")),
        "a plugin the operator never saw was unloaded: {out}"
    );
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("ENTANGLE-E0758") && out.contains(&late_id),
        "{out}"
    );
    assert_eq!(f.loaded().len(), 4, "nothing was unloaded");
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 5);
    assert_eq!(f.config(), before);
    assert!(f.audit_file("ENTANGLE-W0214").is_empty());
}

/// Cancelling `set-max-tier` at the prompt leaves config.toml untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_max_tier_cancel_leaves_config_untouched() {
    let f = Fixture::new("", true).await;
    let before = f.config();
    let home = f.home.clone();
    let t = tokio::task::spawn_blocking(move || {
        run_on_tty(&home, &["security", "set-max-tier", "3"], "c\n")
    })
    .await
    .unwrap();
    assert_eq!(t.code, 1, "{}{}", t.stdout, t.stderr);
    assert_eq!(f.config(), before);
    assert_eq!(f.audit_file("ENTANGLE-I0216").len(), 1);
    assert_eq!(f.loaded().len(), 3);
}

/// `entangle config validate` reports the delta set without applying it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_validate_lists_orphans_without_applying() {
    let f = Fixture::new("", true).await;
    std::fs::write(
        f.config_path(),
        f.config()
            .replace("max_tier_allowed = 5", "max_tier_allowed = 3"),
    )
    .unwrap();
    let mut c = f.cmd(&["config", "validate"]);
    let out = tokio::task::spawn_blocking(move || {
        run_blocking(std::mem::replace(&mut c, Command::new("true")))
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains(&f.id("agent-host")), "{stdout}");
    assert_eq!(f.loaded().len(), 3, "validate changes nothing");
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 5);
}

// ---------------------------------------------------------------------------
// Prompt edge paths and flags
// ---------------------------------------------------------------------------

/// Run `args` on a pty against a fresh fixture; the typed `input` answers.
async fn prompted(f: &Fixture, args: &'static [&'static str], input: &'static str) -> Tty {
    let home = f.home.clone();
    tokio::task::spawn_blocking(move || run_on_tty(&home, args, input))
        .await
        .unwrap()
}

/// Nothing was unloaded, lowered or persisted, and the cancel is audited.
fn assert_cancelled(f: &Fixture, before: &str, t: &Tty) {
    let out = format!("{}{}", t.stdout, t.stderr);
    assert_eq!(t.code, 1, "{out}");
    assert_eq!(f.config(), before, "{out}");
    assert_eq!(f.loaded().len(), 3, "{out}");
    assert_eq!(f.state.kernel.max_tier_allowed() as u8, 5, "{out}");
    assert_eq!(f.audit_file("ENTANGLE-I0216").len(), 1, "{out}");
    assert!(f.audit_file("ENTANGLE-W0214").is_empty(), "{out}");
}

/// The explicit answers `u` and `unload` (any case) unload and disable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prompt_explicit_unload_answers_unload() {
    for answer in ["u\n", "UNLOAD\n"] {
        let f = Fixture::new("", true).await;
        let t = prompted(&f, &["security", "set-max-tier", "3"], answer).await;
        assert_eq!(t.code, 0, "{answer:?}: {}{}", t.stdout, t.stderr);
        assert_eq!(f.loaded(), vec![f.id("tiny")], "{answer:?}");
        assert_eq!(f.state.kernel.max_tier_allowed() as u8, 3);
    }
}

/// End of input at the prompt (Ctrl-D) is the safe answer: cancel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prompt_eof_cancels() {
    let f = Fixture::new("", true).await;
    let before = f.config();
    let t = prompted(&f, &["security", "set-max-tier", "3"], "\x04").await;
    assert_cancelled(&f, &before, &t);
}

/// Three unrecognised answers in a row fall through to cancel, each one
/// answered with a hint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prompt_three_unrecognised_answers_cancel() {
    let f = Fixture::new("", true).await;
    let before = f.config();
    let t = prompted(&f, &["security", "set-max-tier", "3"], "x\ny\nz\n").await;
    assert_eq!(
        t.stdout.matches("Unrecognised answer").count(),
        3,
        "{}",
        t.stdout
    );
    assert_cancelled(&f, &before, &t);
}

/// `--yes` at a terminal answers the prompt with its default (unload) and
/// still lists what it unloads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yes_at_a_terminal_takes_the_default_and_lists_the_plugins() {
    let f = Fixture::new("", true).await;
    let home = f.home.clone();
    let t = tokio::task::spawn_blocking(move || {
        run_pty(
            &home,
            &["security", "set-max-tier", "3", "--yes"],
            false,
            || {},
            "",
        )
    })
    .await
    .unwrap();
    let all = format!("{}{}", t.stdout, t.stderr);
    assert_eq!(t.code, 0, "{all}");
    assert!(
        t.stderr.contains(&f.id("agent-host")) && t.stderr.contains(&f.id("cuda-runner")),
        "{all}"
    );
    assert!(
        !all.contains("Decision [u/c]:"),
        "no prompt with --yes: {all}"
    );
    assert_eq!(f.loaded(), vec![f.id("tiny")]);
    assert_eq!(f.audit_file("ENTANGLE-W0214").len(), 2);
}

/// `config reload` with no daemon: nothing is loaded, nothing to reload; the
/// file is left exactly as the operator wrote it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_reload_without_daemon_changes_nothing() {
    let f = Fixture::new("", false).await;
    std::fs::write(
        f.config_path(),
        "[security]\nmax_tier_allowed = 3 # by hand\n",
    )
    .unwrap();
    let before = f.config();
    let out = f.cmd(&["config", "reload"]).output().unwrap();
    let (so, se) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{so}{se}");
    assert!(se.contains("daemon not running"), "{se}");
    assert!(so.contains("nothing to reload"), "{so}");
    assert_eq!(f.config(), before);
}

/// The ceiling edit changes `max_tier_allowed` only: the rest of
/// `[security]` — `deny_capabilities`, comment included — and the other
/// sections of both branches survive, and the daemon still parses the file
/// with its deny list intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_max_tier_keeps_deny_capabilities_and_every_other_section() {
    let f = Fixture::new(
        "deny_capabilities = [\"net.wan\", \"storage.share.*\"] # operator choice\n\n\
         [wrappers]\ninstall = true\n\n\
         [metrics]\nenabled = false\nlisten = \"127.0.0.1:9464\"\n\n\
         [telemetry.otlp]\nenabled = false\n",
        false,
    )
    .await;
    let out = f.cmd(&["security", "set-max-tier", "3"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let cfg = f.config();
    assert!(cfg.contains("max_tier_allowed = 3"), "{cfg}");
    assert!(
        cfg.contains("deny_capabilities = [\"net.wan\", \"storage.share.*\"] # operator choice"),
        "{cfg}"
    );
    assert!(
        cfg.contains("[wrappers]\ninstall = true")
            && cfg.contains("[metrics]")
            && cfg.contains("[telemetry.otlp]"),
        "{cfg}"
    );
    let daemon: dcfg::Config = toml::from_str(&cfg).unwrap_or_else(|e| panic!("{e}\n{cfg}"));
    assert_eq!(daemon.security.max_tier_allowed as u8, 3);
    assert_eq!(daemon.security.deny_capabilities.len(), 2);
    assert!(daemon.wrappers.install);
}
