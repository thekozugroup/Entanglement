//! `entangle logs` and `entangle trace task`, driving the real `entangle`
//! binary against a real daemon (`entangle-bin`'s kernel, RPC server and the
//! daemon's own `tracing` subscriber) running in this process, with a
//! temporary `$HOME`.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

use entangle_bin::{config as dcfg, server, state::DaemonState};
use entangle_observability::logs::{LogConfig, LogHub};
use entangle_observability::traces::{TraceConfig, TraceStore};
use entangle_peers::PeerStore;
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use tempfile::TempDir;

fn entangle_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_entangle"))
}

/// The daemon's subscriber, installed once for this test binary.
fn stores() -> &'static (LogHub, TraceStore) {
    static S: OnceLock<(LogHub, TraceStore)> = OnceLock::new();
    S.get_or_init(|| {
        let hub = LogHub::new(LogConfig::default());
        let store = TraceStore::new(TraceConfig::default());
        entangle_observability::init_daemon("error", None, &hub, &store).expect("subscriber");
        (hub, store)
    })
}

fn write_wasm_package(root: &Path, kp: &IdentityKeyPair, name: &str) -> (PathBuf, String) {
    let dir = root.join(format!("pkg-{name}"));
    std::fs::create_dir_all(&dir).unwrap();
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .unwrap();
    let id = format!("{}/{name}@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n\n[capabilities]\n"
    );
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join("plugin.wasm"), &wasm).unwrap();
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(&wasm, manifest.as_bytes(), kp)).unwrap(),
    )
    .unwrap();
    (dir, id)
}

struct Fixture {
    _tmp: TempDir,
    home: PathBuf,
    plugin: String,
}

impl Fixture {
    async fn new(name: &str) -> Self {
        let (hub, store) = stores();
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("h");
        let cdir = home.join(".entangle");
        std::fs::create_dir_all(&cdir).unwrap();
        let cfg = dcfg::load_config(&cdir.join("config.toml")).unwrap();
        let kp = IdentityKeyPair::generate();
        let mut kr = Keyring::new();
        kr.add(TrustEntry {
            fingerprint: kp.fingerprint(),
            public_key: *kp.public().as_bytes(),
            publisher_name: "obs-cli".into(),
            added_at: 0,
            note: String::new(),
        });
        let kernel = Arc::new(Kernel::new(dcfg::kernel_config(&cfg, &cdir), kr).unwrap());
        let pool = WorkerPool::new();
        let identity = IdentityKeyPair::generate();
        let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
        let dispatcher = Arc::new(Dispatcher::new(pool.clone(), kernel.clone(), local));
        let state = Arc::new(
            DaemonState::new(
                kernel,
                dispatcher,
                pool,
                PeerStore::new(),
                identity,
                "obs-cli".into(),
            )
            .with_observability(hub.clone(), store.clone()),
        );
        let (dir, plugin) = write_wasm_package(tmp.path(), &kp, name);
        state.kernel.load_plugin_from_dir(&dir).await.unwrap();
        let sock = cdir.join("sock");
        let st = state.clone();
        let s2 = sock.clone();
        tokio::spawn(async move {
            let _ = server::serve(s2, st).await;
        });
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(sock.exists(), "daemon socket never appeared");
        Self {
            _tmp: tmp,
            home,
            plugin,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(entangle_bin());
        c.args(args)
            .env("HOME", &self.home)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::null());
        c
    }

    async fn run(&self, args: &[&str]) -> Output {
        let mut c = self.cmd(args);
        tokio::task::spawn_blocking(move || c.output().unwrap())
            .await
            .unwrap()
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn emit(plugin: &str, level: &str, text: &str) {
    let id: PluginId = plugin.parse().unwrap();
    entangle_host::output::emit_line(&id, level, "stdout", text);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_show_a_plugins_output_with_filters_and_json() {
    let f = Fixture::new("cli-logs").await;
    emit(&f.plugin, "info", "starting up");
    emit(&f.plugin, "warn", "disk almost full");
    emit(&f.plugin, "error", "request failed: code 7");
    // Another plugin's output never shows here.
    emit(
        "0123456789abcdef0123456789abcdef/other@0.1.0",
        "info",
        "not mine",
    );

    let o = f.run(&["logs", "cli-logs"]).await;
    assert!(o.status.success(), "{}", err(&o));
    let text = out(&o);
    assert!(
        text.contains("starting up") && text.contains("disk almost full"),
        "{text}"
    );
    assert!(!text.contains("not mine"), "{text}");
    assert!(
        text.lines()
            .any(|l| l.contains("WARN") && l.contains("disk almost full")),
        "{text}"
    );

    let o = f.run(&["logs", &f.plugin, "--level", "warn"]).await;
    let text = out(&o);
    assert!(
        !text.contains("starting up") && text.contains("request failed"),
        "{text}"
    );

    let o = f.run(&["logs", "cli-logs", "--filter", "FULL"]).await;
    let text = out(&o);
    assert_eq!(text.lines().count(), 1, "{text}");

    let o = f
        .run(&["logs", "cli-logs", "--since", "1h", "--tail", "1", "--json"])
        .await;
    let text = out(&o);
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert_eq!(lines[0]["message"], "request failed: code 7");
    assert_eq!(lines[0]["level"], "error");

    // Bad inputs are clear, coded errors with a failing exit status.
    let o = f.run(&["logs", "nope-not-a-plugin"]).await;
    assert!(!o.status.success());
    let e = err(&o);
    assert!(
        e.contains("ENTANGLE-E0920") && e.contains("nope-not-a-plugin"),
        "{e}"
    );
    let o = f.run(&["logs", "daemon", "--level", "loud"]).await;
    assert!(err(&o).contains("ENTANGLE-E0922"), "{}", err(&o));
    let o = f.run(&["logs", "daemon", "--since", "soon"]).await;
    assert!(err(&o).contains("invalid duration"), "{}", err(&o));
}

#[tokio::test(flavor = "multi_thread")]
async fn follow_streams_a_line_logged_after_it_started_and_ctrl_c_ends_it_cleanly() {
    let f = Fixture::new("cli-follow").await;
    emit(&f.plugin, "info", "old line");
    let mut child = f
        .cmd(&["logs", "cli-follow", "--follow"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for l in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    // The first page arrives, then the command waits.
    let first = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("first page");
    assert!(first.contains("old line"), "{first}");
    assert!(
        rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "nothing new yet"
    );

    emit(&f.plugin, "info", "fresh line while following");
    let mut got = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(l) = rx.recv_timeout(Duration::from_millis(200)) {
            if l.contains("fresh line while following") {
                got = true;
                break;
            }
        }
    }
    assert!(got, "the follower never printed the new line");

    // Ctrl-C: SIGINT ends it with success and no error output.
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let t = Instant::now();
    let exit = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "did not exit after SIGINT"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(exit.success(), "{exit:?}");
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert!(!stderr.contains("error"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dispatch_prints_its_task_id_and_trace_task_shows_the_tree() {
    let f = Fixture::new("cli-trace").await;
    let o = f
        .run(&["compute", "dispatch", &f.plugin, "--input", "world"])
        .await;
    assert!(o.status.success(), "{}", err(&o));
    let text = out(&o);
    assert!(text.contains("Output: Hello, world!"), "{text}");
    let task = text
        .lines()
        .find_map(|l| l.strip_prefix("Task: "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("no Task: line in {text}"))
        .to_owned();

    let o = f.run(&["trace", "task", &task]).await;
    assert!(o.status.success(), "{}", err(&o));
    let tree = out(&o);
    let lines: Vec<&str> = tree.lines().collect();
    assert!(
        lines[0].starts_with("Trace ") && lines[0].contains(&task),
        "{tree}"
    );
    let dispatch = lines
        .iter()
        .position(|l| l.starts_with("└─ task.dispatch"))
        .expect(&tree);
    let invoke = lines
        .iter()
        .position(|l| l.contains("plugin.invoke"))
        .expect(&tree);
    assert!(invoke > dispatch, "{tree}");
    assert!(
        lines[invoke].contains("└─") || lines[invoke].contains("├─"),
        "nested: {tree}"
    );
    assert!(
        lines[dispatch].contains(&format!("task_id={task}")),
        "{tree}"
    );
    assert!(
        lines[invoke].contains(&format!("plugin={}", f.plugin)),
        "{tree}"
    );
    assert!(
        lines[invoke].contains("ms") || lines[invoke].contains("µs"),
        "duration: {tree}"
    );

    let o = f.run(&["trace", "task", &task, "--json"]).await;
    let v: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert!(
        v["traces"][0]["spans"].as_array().unwrap().len() >= 2,
        "{v}"
    );

    // Unknown and malformed ids.
    let o = f
        .run(&["trace", "task", "6f9619ff-8b86-d011-b42d-00c04fc964ff"])
        .await;
    assert!(!o.status.success());
    assert!(err(&o).contains("ENTANGLE-E0923"), "{}", err(&o));
    let o = f.run(&["trace", "task", "banana"]).await;
    assert!(err(&o).contains("ENTANGLE-E0924"), "{}", err(&o));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_daemon_both_commands_say_so() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        &["logs", "daemon"][..],
        &["trace", "task", "6f9619ff-8b86-d011-b42d-00c04fc964ff"][..],
    ] {
        let o = Command::new(entangle_bin())
            .args(args)
            .env("HOME", tmp.path())
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap();
        assert!(!o.status.success());
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("daemon not running"),
            "{args:?}"
        );
    }
}
