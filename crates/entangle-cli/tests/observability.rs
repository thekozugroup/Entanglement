//! `entangle metrics` and `entangle diag mesh` against a daemon.
//!
//! The daemon is a stub on the CLI's real transport (a Unix socket at
//! `$HOME/.entangle/sock`) that records each request line and answers from a
//! canned result, so the tests pin what the CLI sends and how it renders what
//! comes back. The daemon side of both methods is exercised against the real
//! server in `entangle-bin`'s `observability` tests.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use entangle_rpc::methods::{
    DiagEndpoint, DiagMeshResult, DiagPath, DiagPeer, DiagTailscale, MetricsExportResult,
};
use predicates::prelude::*;
use tempfile::TempDir;

fn entangle(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", home);
    cmd
}

/// Serve exactly one request on `$HOME/.entangle/sock`, answering with
/// `result`. Returns the request line the CLI sent.
fn stub_daemon(home: &Path, result: serde_json::Value) -> Arc<Mutex<Option<String>>> {
    let dir = home.join(".entangle");
    std::fs::create_dir_all(&dir).unwrap();
    let listener = UnixListener::bind(dir.join("sock")).unwrap();
    let seen = Arc::new(Mutex::new(None));
    let seen2 = Arc::clone(&seen);
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        *seen2.lock().unwrap() = Some(line);
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": req["id"], "result": result});
        let mut w = &stream;
        writeln!(w, "{resp}").unwrap();
    });
    seen
}

fn sample_report() -> DiagMeshResult {
    DiagMeshResult {
        local_peer_id: "aa11".into(),
        local_display_name: "laptop".into(),
        transports_configured: vec!["iroh".into(), "tailscale".into()],
        transports_active: vec!["iroh".into()],
        endpoints: vec![DiagEndpoint {
            transport: "iroh".into(),
            address: "10.0.0.2:41641".into(),
        }],
        tailscale: Some(DiagTailscale {
            state: "stopped".into(),
            reason: Some("NeedsLogin".into()),
            since_secs: Some(5),
            transitions: 1,
            candidates: 0,
        }),
        peers: vec![
            DiagPeer {
                peer_id: "bb22".into(),
                display_name: "desk".into(),
                trust: "trusted".into(),
                paths: vec![DiagPath {
                    transport: "iroh".into(),
                    address: Some("10.0.0.9:41641".into()),
                    detail: "address book ([scheduler] peers)".into(),
                    rtt_ms: Some(2.5),
                    probe_error: None,
                }],
                route: None,
            },
            DiagPeer {
                peer_id: "cc33".into(),
                display_name: "ghost".into(),
                trust: "trusted".into(),
                paths: vec![],
                route: None,
            },
        ],
        untrusted_sightings: 0,
        probed: true,
    }
}

#[test]
fn metrics_prints_the_daemons_exposition_verbatim() {
    let home = TempDir::new().unwrap();
    let text = "# HELP x_total things\n# TYPE x_total counter\nx_total{a=\"b\"} 7\n";
    let seen = stub_daemon(
        home.path(),
        serde_json::to_value(MetricsExportResult { text: text.into() }).unwrap(),
    );
    entangle(home.path())
        .arg("metrics")
        .assert()
        .success()
        .stdout(text);
    let request: serde_json::Value =
        serde_json::from_str(seen.lock().unwrap().as_ref().unwrap()).unwrap();
    assert_eq!(request["method"], "metrics/export");
}

#[test]
fn metrics_without_a_daemon_fails_with_a_clear_error() {
    let home = TempDir::new().unwrap();
    entangle(home.path())
        .arg("metrics")
        .assert()
        .failure()
        .stderr(predicate::str::contains("daemon not running"))
        // The old behaviour printed the CLI process's own (empty) registry.
        .stdout(predicate::str::contains("entangle_cli_invocations_total").not());
}

#[test]
fn diag_mesh_renders_the_text_report_and_sends_the_probe_request() {
    let home = TempDir::new().unwrap();
    let seen = stub_daemon(home.path(), serde_json::to_value(sample_report()).unwrap());
    entangle(home.path())
        .args(["diag", "mesh", "--probe", "--timeout-ms", "750"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Mesh diagnostics for laptop (aa11)",
        ))
        .stdout(predicate::str::contains(
            "! tailscale is configured but not running",
        ))
        .stdout(predicate::str::contains("state: stopped (NeedsLogin)"))
        .stdout(predicate::str::contains("desk  bb22  [trusted]"))
        .stdout(predicate::str::contains("rtt 2.5 ms"))
        .stdout(predicate::str::contains(
            "no path: no transport currently knows",
        ))
        .stdout(predicate::str::contains(
            "Probe: 1 of 2 trusted peer(s) answered",
        ));
    let request: serde_json::Value =
        serde_json::from_str(seen.lock().unwrap().as_ref().unwrap()).unwrap();
    assert_eq!(request["method"], "diag/mesh");
    assert_eq!(request["params"]["probe"], true);
    assert_eq!(request["params"]["probe_timeout_ms"], 750);
}

#[test]
fn diag_mesh_json_is_the_daemons_report() {
    let home = TempDir::new().unwrap();
    let seen = stub_daemon(home.path(), serde_json::to_value(sample_report()).unwrap());
    let out = entangle(home.path())
        .args(["diag", "mesh", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: DiagMeshResult = serde_json::from_slice(&out).expect("--json is the report");
    assert_eq!(parsed, sample_report());
    // Without --probe the CLI asks for none.
    let request: serde_json::Value =
        serde_json::from_str(seen.lock().unwrap().as_ref().unwrap()).unwrap();
    assert_eq!(request["params"]["probe"], false);
}

#[test]
fn diag_mesh_without_a_daemon_fails_with_a_clear_error() {
    let home = TempDir::new().unwrap();
    entangle(home.path())
        .args(["diag", "mesh"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("daemon not running"));
}
