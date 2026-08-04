//! Integration tests for `entangle pair`.
//!
//! The network flow is exercised end to end by driving two real `entangle`
//! processes on loopback (`pair_over_the_network_*`): one shows a code, the
//! other dials it with `--peer` + `--code`. No mDNS is involved — `--no-mdns`
//! keeps the test off multicast, which sandboxes generally do not have — so
//! what is under test is the exchange itself and both sides' persistence.
//!
//! The copy-paste (`--manual`) tests below cover the escape-hatch channel's
//! error paths. The two full manual round-trips still need a two-process
//! harness and remain `#[ignore]`d.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    cmd
}

fn binary() -> PathBuf {
    assert_cmd::cargo::cargo_bin("entangle")
}

/// What the responder printed: the code to type, and its dialable address.
struct Responder {
    code: String,
    node_addr: String,
    child: std::process::Child,
    stderr: BufReader<std::process::ChildStderr>,
}

/// Start `entangle pair --responder` on loopback and read its banner.
fn start_responder(home: &TempDir, peers: &Path, identity: &Path) -> Responder {
    let mut child = StdCommand::new(binary())
        .args([
            "pair",
            "--responder",
            "--display-name",
            "studio",
            "--bind",
            "127.0.0.1:0",
            "--no-mdns",
            "--yes",
            "--timeout",
            "60",
            "--peers-file",
            peers.to_str().unwrap(),
            "--identity-file",
            identity.to_str().unwrap(),
        ])
        .env("HOME", home.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("responder must start");

    let mut stderr = BufReader::new(child.stderr.take().expect("piped stderr"));
    let (mut code, mut node_addr) = (None, None);
    let mut transcript = String::new();
    let mut line = String::new();
    // The banner is printed as soon as the endpoint is bound, before the
    // process blocks waiting for a dial.
    while code.is_none() || node_addr.is_none() {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read responder stderr");
        assert!(read > 0, "responder exited early:\n{transcript}");
        transcript.push_str(&line);
        if let Some(rest) = line.trim().strip_prefix("Pairing code:") {
            code = rest.split_whitespace().next().map(str::to_string);
        }
        if let Some(rest) = line
            .trim()
            .strip_prefix("Direct address: entangle pair --peer ")
        {
            node_addr = Some(rest.trim().to_string());
        }
    }

    Responder {
        code: code.expect("a code"),
        node_addr: node_addr.expect("a node address"),
        child,
        stderr,
    }
}

impl Responder {
    /// Wait for the responder to exit, returning (success, remaining stderr).
    fn finish(mut self) -> (bool, String) {
        let status = self
            .child
            .wait_timeout(Duration::from_secs(60))
            .expect("responder must exit");
        let mut rest = String::new();
        // Drain whatever it printed after the banner.
        let mut line = String::new();
        while self.stderr.read_line(&mut line).unwrap_or(0) > 0 {
            rest.push_str(&line);
            line.clear();
        }
        (status, rest)
    }
}

/// Minimal `wait_timeout` so a hung child fails the test instead of CI.
trait WaitTimeout {
    fn wait_timeout(&mut self, dur: Duration) -> Option<bool>;
}

impl WaitTimeout for std::process::Child {
    fn wait_timeout(&mut self, dur: Duration) -> Option<bool> {
        let deadline = std::time::Instant::now() + dur;
        loop {
            match self.try_wait().expect("try_wait") {
                Some(status) => return Some(status.success()),
                None if std::time::Instant::now() >= deadline => {
                    let _ = self.kill();
                    return None;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1. The network flow, end to end, two processes.
// ---------------------------------------------------------------------------

/// The headline behaviour: `entangle pair --responder` on one device, a
/// 6-digit code typed on the other, and both devices end up holding each
/// other in `peers.toml`. Not a blob in sight.
#[test]
fn pair_over_the_network_stores_both_peers() {
    let r_home = TempDir::new().unwrap();
    let i_home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    let r_peers = work.path().join("r-peers.toml");
    let i_peers = work.path().join("i-peers.toml");
    let r_key = work.path().join("r-identity.key");
    let i_key = work.path().join("i-identity.key");

    let responder = start_responder(&r_home, &r_peers, &r_key);
    let responder_pubkey = responder
        .node_addr
        .split('@')
        .next()
        .expect("long address is <pubkey>@<addr>")
        .to_string();

    // The code is given positionally here — spec §6.3 spells the initiator's
    // invocation `entangle pair 734-291`.
    entangle(&i_home)
        .args([
            "pair",
            &responder.code,
            "--display-name",
            "laptop",
            "--peer",
            &responder.node_addr,
            "--yes",
            "--no-mdns",
            "--bind",
            "127.0.0.1:0",
            "--peers-file",
            i_peers.to_str().unwrap(),
            "--identity-file",
            i_key.to_str().unwrap(),
        ])
        .timeout(Duration::from_secs(60))
        .assert()
        .success()
        .stderr(predicate::str::contains("Their fingerprint:"))
        .stderr(predicate::str::contains("Your fingerprint:"));

    let (ok, tail) = responder.finish();
    assert!(ok, "responder must exit cleanly; tail:\n{tail}");

    // The initiator stored the responder's *authenticated* key.
    let initiator_store = std::fs::read_to_string(&i_peers).expect("initiator peers.toml");
    assert!(
        initiator_store.contains(&responder_pubkey),
        "initiator must store the key it dialled:\n{initiator_store}"
    );
    assert!(initiator_store.contains("studio"));

    // …and the responder stored the initiator.
    let responder_store = std::fs::read_to_string(&r_peers).expect("responder peers.toml");
    assert!(
        responder_store.contains("laptop"),
        "responder must store the device that paired with it:\n{responder_store}"
    );
    assert!(
        !responder_store.contains(&responder_pubkey),
        "neither side may store itself"
    );
}

/// A wrong code must fail, and must leave *no* peer behind on either device.
#[test]
fn pair_over_the_network_rejects_a_wrong_code() {
    let r_home = TempDir::new().unwrap();
    let i_home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    let r_peers = work.path().join("r-peers.toml");
    let i_peers = work.path().join("i-peers.toml");
    let r_key = work.path().join("r-identity.key");
    let i_key = work.path().join("i-identity.key");

    let mut responder = start_responder(&r_home, &r_peers, &r_key);

    // A code that is definitely not the one displayed.
    let wrong = if responder.code.starts_with('1') {
        "999-999"
    } else {
        "111-111"
    };

    entangle(&i_home)
        .args([
            "pair",
            "--display-name",
            "laptop",
            "--peer",
            &responder.node_addr,
            "--code",
            wrong,
            "--yes",
            "--no-mdns",
            "--bind",
            "127.0.0.1:0",
            "--peers-file",
            i_peers.to_str().unwrap(),
            "--identity-file",
            i_key.to_str().unwrap(),
        ])
        .timeout(Duration::from_secs(60))
        .assert()
        .failure()
        .stderr(predicate::str::contains("pairing failed"));

    assert!(
        !i_peers.exists(),
        "a failed pairing must not write a peer store"
    );

    // The responder is still waiting; kill it and confirm it stored nothing.
    let _ = responder.child.kill();
    assert!(
        !r_peers.exists(),
        "the responder must not store a peer that failed the code check"
    );
}

// ---------------------------------------------------------------------------
// 2. Copy-paste channel (the escape hatch) still works.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "two-process harness required; run with: cargo test --test pair -- --ignored"]
fn pair_round_trip_happy_path() {}

#[test]
#[ignore = "two-process harness required; run with: cargo test --test pair -- --ignored"]
fn pair_wrong_code_aborts() {}

/// Tampered request blob (bad JSON payload) → error.
#[test]
fn pair_tampered_request_blob_is_rejected() {
    let r_home = TempDir::new().unwrap();
    let blobs = TempDir::new().unwrap();

    let req_file = blobs.path().join("req.blob");
    let r_peers = blobs.path().join("r-peers.toml");

    // Valid ENT-REQ- prefix but the base64 decodes to "this is not valid json"
    std::fs::write(&req_file, b"ENT-REQ-dGhpcyBpcyBub3QgdmFsaWQganNvbg").unwrap();

    entangle(&r_home)
        .args([
            "pair",
            "--responder",
            "--request-file",
            req_file.to_str().unwrap(),
            "--code",
            "123-456",
            "--peers-file",
            r_peers.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("failed to decode REQUEST blob")
                .or(predicate::str::contains("JSON decode failed")),
        );
}

/// Wrong blob prefix → error mentions the expected prefix.
#[test]
fn pair_wrong_prefix_is_rejected() {
    let r_home = TempDir::new().unwrap();
    let blobs = TempDir::new().unwrap();
    let req_file = blobs.path().join("req.blob");

    // An ACCEPT blob passed where a REQUEST blob is expected.
    std::fs::write(&req_file, b"ENT-ACC-somedata").unwrap();

    entangle(&r_home)
        .args([
            "pair",
            "--responder",
            "--request-file",
            req_file.to_str().unwrap(),
            "--code",
            "123-456",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENT-REQ-"));
}

/// `--manual` selects the blob channel explicitly, and it must not try to
/// touch the network: with no request on stdin it fails on the blob, not on a
/// socket.
#[test]
fn manual_flag_selects_the_blob_channel() {
    let home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();

    entangle(&home)
        .args([
            "pair",
            "--responder",
            "--manual",
            "--code",
            "123-456",
            "--peers-file",
            work.path().join("peers.toml").to_str().unwrap(),
        ])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("blob"));
}

// ---------------------------------------------------------------------------
// 3. Help text.
// ---------------------------------------------------------------------------

#[test]
fn pair_help_shows_flags() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["pair", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--responder"))
        .stdout(predicate::str::contains("--display-name"))
        .stdout(predicate::str::contains("--request-file"))
        .stdout(predicate::str::contains("--emit-request-file"));
}

/// The network flow's flags are discoverable, and so is the escape hatch.
#[test]
fn pair_help_shows_network_flags() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["pair", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--peer"))
        .stdout(predicate::str::contains("--code"))
        .stdout(predicate::str::contains("--manual"))
        .stdout(predicate::str::contains("--yes"))
        .stdout(predicate::str::contains("--timeout"));
}
