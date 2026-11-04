//! Fault isolation (spec §2.1), against the real `entangled` process.
//!
//! The daemon is started with `ENTANGLE_FAULT_INJECT` naming a debug-build
//! fault point (`entangle_core::fault::inject`). A panic in a core task —
//! the maintenance loop, the RPC server, the capability broker — must end
//! the process with the documented status 70 after one structured
//! `ENTANGLE-E0787` line at target `entangle::telemetry`; a supervised core
//! task that returns early must do the same. A panic in a host call inside a
//! plugin invocation is contained: that call fails with `ENTANGLE-E0788` and
//! the daemon keeps serving.

use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const PROBE: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/caps-probe.wasm");

/// The documented exit status of a core fault (`EXIT_CORE_FAULT`).
const CORE_FAULT: i32 = 70;

struct Daemon {
    child: Child,
    home: PathBuf,
    stderr: PathBuf,
}

impl Daemon {
    /// Start `entangled run` with `HOME=home` and the fault points `faults`
    /// armed (empty: none). Stderr goes to a file read after the fact.
    fn start(home: &Path, faults: &str) -> Self {
        let stderr = home.join(format!("stderr-{}.log", faults.replace(',', "_")));
        let file = std::fs::File::create(&stderr).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_entangled"));
        cmd.arg("run")
            .env("HOME", home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(file);
        if faults.is_empty() {
            cmd.env_remove(entangle_core::fault::FAULT_INJECT_ENV);
        } else {
            cmd.env(entangle_core::fault::FAULT_INJECT_ENV, faults);
        }
        Self {
            child: cmd.spawn().expect("spawn entangled"),
            home: home.to_path_buf(),
            stderr,
        }
    }

    fn socket(&self) -> PathBuf {
        self.home.join(".entangle/sock")
    }

    /// A client once the daemon answers `version`.
    async fn client(&mut self) -> entangle_rpc::Client {
        let client = entangle_rpc::Client::new(self.socket());
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if client.version().await.is_ok() {
                return client;
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("daemon exited early ({status}): {}", self.log());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("daemon never answered: {}", self.log());
    }

    /// Wait (bounded) for the process to exit.
    fn wait_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("daemon did not exit: {}", self.log());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    /// The JSON log lines whose `fields.code` is `code`.
    fn lines_with_code(&self, code: &str) -> Vec<serde_json::Value> {
        self.log()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["fields"]["code"] == code)
            .collect()
    }

    fn terminate(&mut self) -> ExitStatus {
        let pid = self.child.id().to_string();
        let _ = Command::new("kill").args(["-TERM", &pid]).status();
        self.wait_exit()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The one core-fault line: right code, target, a location in `file`, a
/// thread, and the panic message.
fn assert_core_fault_line(d: &Daemon, file: &str) -> serde_json::Value {
    let lines = d.lines_with_code("ENTANGLE-E0787");
    assert_eq!(lines.len(), 1, "exactly one fault line: {}", d.log());
    let line = lines[0].clone();
    assert_eq!(line["target"], "entangle::telemetry", "{line}");
    assert_eq!(line["level"], "ERROR", "{line}");
    assert_eq!(line["fields"]["exit_code"], CORE_FAULT, "{line}");
    assert!(
        line["fields"]["location"]
            .as_str()
            .is_some_and(|l| l.contains(file)),
        "location names {file}: {line}"
    );
    assert!(
        line["fields"]["thread"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "{line}"
    );
    assert!(
        line["fields"]["panic"]
            .as_str()
            .is_some_and(|m| m.contains("fault injection")),
        "{line}"
    );
    line
}

#[test]
fn panic_in_the_maintenance_loop_exits_with_the_core_fault_status() {
    let tmp = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(tmp.path(), "maintenance");
    let status = d.wait_exit();
    assert_eq!(status.code(), Some(CORE_FAULT), "{}", d.log());
    assert_core_fault_line(&d, "maintenance.rs");
    assert!(!d.socket().exists(), "socket left behind: {}", d.log());
}

#[test]
fn a_core_task_that_returns_early_ends_the_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(tmp.path(), "maintenance-return");
    let status = d.wait_exit();
    assert_eq!(status.code(), Some(CORE_FAULT), "{}", d.log());
    let lines = d.lines_with_code("ENTANGLE-E0787");
    assert_eq!(lines.len(), 1, "{}", d.log());
    assert_eq!(lines[0]["target"], "entangle::telemetry");
    assert_eq!(lines[0]["fields"]["task"], "maintenance", "{}", lines[0]);
    assert_eq!(lines[0]["fields"]["panicked"], false, "{}", lines[0]);
}

/// The RPC server refuses to unlink a socket path that is not a socket (a
/// regular file, a symbolic link): its task ends, the daemon exits 70 — and
/// that exit must not delete the file the server deliberately left alone.
#[test]
fn a_core_fault_exit_leaves_a_socket_path_that_is_not_a_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join(".entangle/sock");
    std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
    std::fs::write(&sock, b"not a socket").unwrap();
    let mut d = Daemon::start(tmp.path(), "");
    let status = d.wait_exit();
    assert_eq!(status.code(), Some(CORE_FAULT), "{}", d.log());
    assert!(
        d.log().contains("existing path is not a socket"),
        "{}",
        d.log()
    );
    assert_eq!(
        std::fs::read(&sock).ok().as_deref(),
        Some(&b"not a socket"[..]),
        "the fault exit removed a path that is not a socket: {}",
        d.log()
    );

    // A symbolic link in its place survives too (and so does its target).
    let target = tmp.path().join("target-file");
    std::fs::write(&target, b"keep").unwrap();
    std::fs::remove_file(&sock).unwrap();
    std::os::unix::fs::symlink(&target, &sock).unwrap();
    let mut d = Daemon::start(tmp.path(), "");
    assert_eq!(d.wait_exit().code(), Some(CORE_FAULT), "{}", d.log());
    assert!(
        std::fs::symlink_metadata(&sock).is_ok_and(|m| m.file_type().is_symlink()),
        "the fault exit removed the symbolic link: {}",
        d.log()
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
}

#[tokio::test(flavor = "multi_thread")]
async fn panic_in_the_rpc_server_exits_with_the_core_fault_status() {
    let tmp = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(tmp.path(), "rpc");
    // The first request handled panics: there is no successful answer.
    let client = entangle_rpc::Client::new(d.socket());
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        let _ = client.version().await;
        if let Some(status) = d.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "never exited: {}", d.log());
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(status.code(), Some(CORE_FAULT), "{}", d.log());
    assert_core_fault_line(&d, "methods.rs");
}

/// A signed caps-probe package declaring `storage.local`, trusted by the
/// daemon's keyring in `home`.
fn install_probe(home: &Path) -> (PathBuf, String) {
    let kp = IdentityKeyPair::generate();
    let config = home.join(".entangle");
    std::fs::create_dir_all(&config).unwrap();
    let mut keyring = Keyring::new();
    keyring.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "fault-isolation".into(),
        added_at: 0,
        note: String::new(),
    });
    keyring.save(&config.join("keyring.toml")).unwrap();

    let pkg = home.join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let id = format!("{}/caps-probe@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n\n\
         [capabilities]\n\"storage.local\" = {{ mode = \"rw\" }}\n"
    );
    std::fs::write(pkg.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(pkg.join("plugin.wasm"), PROBE).unwrap();
    std::fs::write(
        pkg.join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(PROBE, manifest.as_bytes(), &kp)).unwrap(),
    )
    .unwrap();
    (pkg, id)
}

#[tokio::test(flavor = "multi_thread")]
async fn panic_in_a_plugin_host_call_is_contained() {
    let tmp = tempfile::tempdir().unwrap();
    let (pkg, id) = install_probe(tmp.path());
    let mut d = Daemon::start(tmp.path(), "host-call");
    let client = d.client().await;
    client.plugins_load(&pkg).await.expect("load");

    // `info` calls host-info.get, where the fault point panics.
    let err = client
        .plugins_invoke(&id, b"info".to_vec(), 10_000)
        .await
        .expect_err("the call fails");
    assert!(err.to_string().contains("ENTANGLE-E0788"), "{err}");

    // The daemon is still up, the plugin still loaded and still callable on
    // paths that do not reach the fault point.
    assert!(d.child.try_wait().unwrap().is_none(), "{}", d.log());
    client.version().await.expect("still serving");
    let listed = client.plugins_list().await.unwrap();
    assert_eq!(listed.plugins, vec![id.clone()]);
    let out = client
        .plugins_invoke(&id, b"write /data/f hi\nread /data/f".to_vec(), 10_000)
        .await
        .expect("a call that does not reach the fault point");
    assert_eq!(String::from_utf8_lossy(&out.output), "ok\nok:hi\n");

    let contained = d.lines_with_code("ENTANGLE-E0788");
    assert_eq!(contained.len(), 1, "{}", d.log());
    assert_eq!(contained[0]["target"], "entangle::telemetry");
    assert_eq!(contained[0]["fields"]["contained"], true);
    assert!(contained[0]["fields"]["location"]
        .as_str()
        .is_some_and(|l| l.contains("bindings.rs")));
    assert!(
        d.lines_with_code("ENTANGLE-E0787").is_empty(),
        "{}",
        d.log()
    );

    // A clean stop is still status 0.
    assert_eq!(d.terminate().code(), Some(0), "{}", d.log());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broker_panic_inside_a_plugin_call_still_exits() {
    let tmp = tempfile::tempdir().unwrap();
    let (pkg, id) = install_probe(tmp.path());
    let mut d = Daemon::start(tmp.path(), "broker");
    let client = d.client().await;
    client.plugins_load(&pkg).await.expect("load");

    // `fetch storage-local` reaches Broker::grant_by_key (a critical
    // section) from inside the contained plugin call.
    let _ = client
        .plugins_invoke(&id, b"fetch storage-local".to_vec(), 10_000)
        .await;
    let status = d.wait_exit();
    assert_eq!(status.code(), Some(CORE_FAULT), "{}", d.log());
    let line = assert_core_fault_line(&d, "broker.rs");
    assert_eq!(line["fields"]["contained"], false, "{line}");
}

/// Both service definitions restart the daemon on a non-zero exit (status
/// 70 included) and not on a clean one.
#[test]
fn service_definitions_restart_on_failure_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging");
    let unit = std::fs::read_to_string(root.join("entangled.service")).unwrap();
    assert!(
        unit.lines().any(|l| l.trim() == "Restart=on-failure"),
        "systemd unit restarts on failure"
    );
    let plist =
        std::fs::read_to_string(root.join("io.github.thekozugroup.entangled.plist")).unwrap();
    let compact: String = plist.split_whitespace().collect();
    assert!(
        compact.contains("<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>"),
        "launchd plist keeps the daemon alive on a non-zero exit only"
    );
    assert!(compact.contains("<string>/usr/local/bin/entangled</string><string>run</string>"));
}

/// Spec §2.1 end to end: after the process dies (here SIGKILL, as after a
/// crash the service manager restarts), the new daemon reloads the plugins
/// the old one had loaded, through the full verification path.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_come_back_after_the_daemon_is_killed_and_restarted() {
    let tmp = tempfile::tempdir().unwrap();
    let (pkg, id) = install_probe(tmp.path());
    let mut d = Daemon::start(tmp.path(), "");
    let client = d.client().await;
    client.plugins_load(&pkg).await.expect("load");
    let out = client
        .plugins_invoke(&id, b"write /data/kept before\n".to_vec(), 10_000)
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.output), "ok\n");
    let _ = d.child.kill();
    let _ = d.child.wait();
    drop(d);

    let mut d = Daemon::start(tmp.path(), "");
    let client = d.client().await;
    assert_eq!(
        client.plugins_list().await.unwrap().plugins,
        vec![id.clone()]
    );
    let out = client
        .plugins_invoke(&id, b"read /data/kept\n".to_vec(), 10_000)
        .await
        .expect("the restored plugin answers");
    assert_eq!(String::from_utf8_lossy(&out.output), "ok:before\n");
    let restored = d
        .log()
        .lines()
        .any(|l| l.contains("plugin state restored") && l.contains("\"restored\":1"));
    assert!(restored, "{}", d.log());
    assert_eq!(d.terminate().code(), Some(0), "{}", d.log());
}
