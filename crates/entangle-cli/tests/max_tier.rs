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

/// Run `entangle <args>` on a pty (so stdin/stdout are terminals) with
/// `input` typed at the prompt. Returns (exit code, terminal transcript).
fn run_on_tty(home: &Path, args: &[&str], input: &str) -> (i32, String) {
    use std::io::Write as _;
    let mut cmdline = format!("'{}'", entangle_bin().display());
    for a in args {
        cmdline.push_str(&format!(" '{a}'"));
    }
    let mut child = Command::new("script")
        .args(["-qec", &cmdline, "/dev/null"])
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("`script` (util-linux) is required for the pty tests");
    let mut stdin = child.stdin.take().unwrap();
    // Let the prompt appear before answering, then keep stdin open until the
    // child exits so `script` does not forward an early EOF.
    std::thread::sleep(std::time::Duration::from_millis(700));
    stdin.write_all(input.as_bytes()).unwrap();
    stdin.flush().unwrap();
    let out = child.wait_with_output().unwrap();
    drop(stdin);
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text.replace('\r', ""))
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
    if !have_script() {
        eprintln!("skipping: `script` not installed");
        return;
    }
    let f = Fixture::new("", true).await;
    // The operator edits the file by hand (comment must survive the edit).
    let edited = f
        .config()
        .replace("max_tier_allowed = 5", "max_tier_allowed = 3 # lowered");
    std::fs::write(f.config_path(), &edited).unwrap();

    // An empty answer (just Enter) takes the default.
    let home = f.home.clone();
    let (code, out) =
        tokio::task::spawn_blocking(move || run_on_tty(&home, &["config", "reload"], "\n"))
            .await
            .unwrap();

    assert_eq!(code, 0, "{out}");
    assert!(out.contains("will affect 2 running plugins"), "{out}");
    assert!(
        out.contains("agent-host") && out.contains("tier 5"),
        "{out}"
    );
    assert!(
        out.contains("cuda-runner") && out.contains("tier 4"),
        "{out}"
    );
    assert!(
        !out.contains("/tiny@"),
        "tier-2 plugin is not affected: {out}"
    );
    assert!(out.contains("[u] unload-and-disable  (default"), "{out}");
    assert!(out.contains("Decision [u/c]:"), "{out}");

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
/// loaded tiers needs no confirmation either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raising_or_harmless_lowering_never_unloads() {
    let f = Fixture::new("", true).await;
    // Lower to 5 -> 5 (no change), then to 4 would affect tier 5: use force at 4.
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
    // Out-of-range values are rejected before anything is touched.
    let out = f.cmd(&["security", "set-max-tier", "9"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("ENTANGLE-E0752"));
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
    if !have_script() {
        eprintln!("skipping: `script` not installed");
        return;
    }
    let f = Fixture::new("", true).await;
    let edited = f
        .config()
        .replace("max_tier_allowed = 5", "max_tier_allowed = 3");
    std::fs::write(f.config_path(), &edited).unwrap();

    let home = f.home.clone();
    let (code, out) =
        tokio::task::spawn_blocking(move || run_on_tty(&home, &["config", "reload"], "c\n"))
            .await
            .unwrap();

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

/// Cancelling `set-max-tier` at the prompt leaves config.toml untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_max_tier_cancel_leaves_config_untouched() {
    if !have_script() {
        eprintln!("skipping: `script` not installed");
        return;
    }
    let f = Fixture::new("", true).await;
    let before = f.config();
    let home = f.home.clone();
    let (code, out) = tokio::task::spawn_blocking(move || {
        run_on_tty(&home, &["security", "set-max-tier", "3"], "c\n")
    })
    .await
    .unwrap();
    assert_eq!(code, 1, "{out}");
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
