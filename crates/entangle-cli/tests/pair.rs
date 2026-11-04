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

/// What the responder printed: the code to type, its dialable address and
/// its own full fingerprint (the `SHA-256:` line of the code screen).
struct Responder {
    code: String,
    node_addr: String,
    sha256: String,
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
    let (mut code, mut node_addr, mut sha256) = (None, None, None);
    let mut transcript = String::new();
    let mut line = String::new();
    // The banner is printed as soon as the endpoint is bound, before the
    // process blocks waiting for a dial.
    while code.is_none() || node_addr.is_none() || sha256.is_none() {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read responder stderr");
        assert!(read > 0, "responder exited early:\n{transcript}");
        transcript.push_str(&line);
        if let Some(rest) = line.trim().strip_prefix("Pairing code:") {
            code = rest.split_whitespace().next().map(str::to_string);
        }
        if let Some(rest) = line.trim().strip_prefix("SHA-256:") {
            sha256 = Some(rest.trim().to_string());
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
        sha256: sha256.expect("a SHA-256 line"),
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

    // Spec §6.3 step 4: on accept both sides minted a `mesh.peer` token for
    // the other, exchanged them, and stored the one they received — and each
    // recorded the revocation ids of the one it issued.
    assert_tokens_exchanged(&i_peers, &i_key, &r_peers, &r_key);
}

/// The value after `label` on the line that starts with it.
fn line_value<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(label))
        .map(str::trim)
}

/// `SHA256:<hex>` of a raw public key, computed here independently of the
/// CLI: the SHA-256 digest of the 32 key bytes.
fn sha256_of_key(pubkey_hex: &str) -> String {
    use sha2::Digest as _;
    let key = hex::decode(pubkey_hex).expect("hex public key");
    assert_eq!(key.len(), 32, "an Ed25519 public key");
    format!("SHA256:{}", hex::encode(sha2::Sha256::digest(&key)))
}

/// Spec §6.3 / §9.4.2: after the exchange each device shows the *other*
/// device's full fingerprint as "Their SHA-256" — on the device that shows
/// the code too, where it must be the device that typed it, never itself.
#[test]
fn each_side_shows_the_other_devices_sha256() {
    let r_home = TempDir::new().unwrap();
    let i_home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let r_peers = work.path().join("r-peers.toml");
    let i_peers = work.path().join("i-peers.toml");
    let r_key = work.path().join("r-identity.key");
    let i_key = work.path().join("i-identity.key");

    let responder = start_responder(&r_home, &r_peers, &r_key);
    let responder_sha = responder.sha256.clone();
    let responder_pubkey = responder
        .node_addr
        .split('@')
        .next()
        .expect("long address is <pubkey>@<addr>")
        .to_string();
    assert_eq!(
        responder_sha,
        sha256_of_key(&responder_pubkey),
        "the code screen shows this device's own SHA-256"
    );

    let out = entangle(&i_home)
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
        .get_output()
        .stderr
        .clone();
    let i_stderr = String::from_utf8_lossy(&out).into_owned();
    let (ok, r_tail) = responder.finish();
    assert!(ok, "responder must exit cleanly; tail:\n{r_tail}");

    // The initiator's key, as the responder authenticated and stored it.
    let r_store = entangle_peers::PeerStore::open(&r_peers).unwrap();
    let stored = r_store.list();
    assert_eq!(stored.len(), 1, "the responder stored the initiator");
    let initiator_sha = sha256_of_key(&stored[0].public_key_hex);
    assert_ne!(initiator_sha, responder_sha);

    assert_eq!(
        line_value(&i_stderr, "Their SHA-256:"),
        Some(responder_sha.as_str()),
        "the typing device shows the code screen's SHA-256:\n{i_stderr}"
    );
    assert_eq!(
        line_value(&r_tail, "Their SHA-256:"),
        Some(initiator_sha.as_str()),
        "the code-showing device shows the typing device's SHA-256, not its own:\n{r_tail}"
    );
}

/// Both peer lists hold exactly the other device, with a `mesh.peer` token
/// that verifies under the *other* device's key, issued to *this* device, and
/// the revocation ids of the token this device issued — which are exactly the
/// ids of the token the other device holds.
fn assert_tokens_exchanged(a_peers: &Path, a_key: &Path, b_peers: &Path, b_key: &Path) {
    use entangle_biscuits::templates::{now_unix_secs, verify_mesh_peer_grant};
    use entangle_peers::PeerStore;
    use entangle_signing::IdentityKeyPair;
    use entangle_types::peer_id::PeerId;

    let identity = |p: &Path| {
        IdentityKeyPair::from_pem(&std::fs::read_to_string(p).expect("identity file"))
            .expect("identity parses")
    };
    let (a, b) = (identity(a_key), identity(b_key));
    let a_id = PeerId::from_public_key_bytes(a.public().as_bytes());
    let b_id = PeerId::from_public_key_bytes(b.public().as_bytes());
    let record = |peers: &Path, of: PeerId| {
        let list = PeerStore::open(peers).expect("peers.toml loads").list();
        assert_eq!(list.len(), 1, "exactly the other device: {list:?}");
        assert_eq!(list[0].peer_id, of);
        list.into_iter().next().unwrap()
    };
    let (a_rec, b_rec) = (record(a_peers, b_id), record(b_peers, a_id));

    let a_holds = a_rec
        .capability_token_bytes()
        .expect("side A stored the token side B issued it");
    let b_holds = b_rec
        .capability_token_bytes()
        .expect("side B stored the token side A issued it");
    let now = now_unix_secs();
    let a_grant = verify_mesh_peer_grant(&a_holds, b.public().as_bytes(), a_id, now)
        .expect("A's token is a mesh.peer grant rooted at B, issued to A");
    let b_grant = verify_mesh_peer_grant(&b_holds, a.public().as_bytes(), b_id, now)
        .expect("B's token is a mesh.peer grant rooted at A, issued to B");
    assert_eq!(a_grant.expires, None, "pairing tokens live until revoked");
    assert_eq!(b_grant.expires, None, "pairing tokens live until revoked");
    assert_eq!(
        a_rec.issued_revocation_ids(),
        b_grant.revocation_ids,
        "A recorded the revocation ids of the token it issued to B"
    );
    assert_eq!(
        b_rec.issued_revocation_ids(),
        a_grant.revocation_ids,
        "B recorded the revocation ids of the token it issued to A"
    );

    #[cfg(unix)]
    for peers in [a_peers, b_peers] {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(peers).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} holds tokens: mode 0600", peers.display());
    }
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
    // The initiator's capability token went out with its proof; the pairing
    // failed, so it is revoked locally (it must stay dead even if that device
    // is ever put on the allowlist by hand).
    let revoked = entangle_peers::RevocationStore::open(work.path().join("revoked-tokens.toml"))
        .expect("revocation set readable")
        .list()
        .expect("revocation set lists");
    let responder_id = {
        let key: [u8; 32] = hex::decode(responder.node_addr.split('@').next().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        entangle_types::peer_id::PeerId::from_public_key_bytes(&key).to_hex()
    };
    assert!(
        !revoked.is_empty() && revoked.iter().all(|r| r.peer_id == responder_id),
        "the token sent to the responder must be revoked: {revoked:?}"
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

/// The copy-paste channel end to end, two processes: the initiator writes
/// its REQUEST and FINALIZE blobs to files and reads the ACCEPT blob on
/// stdin; the responder reads REQUEST from a file and FINALIZE on stdin. Both
/// end holding the other's key and a `mesh.peer` token from it.
#[test]
fn pair_manual_round_trip_exchanges_capability_tokens() {
    use std::io::Write as _;

    let i_home = TempDir::new().unwrap();
    let r_home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let path = |n: &str| work.path().join(n);
    let (i_peers, r_peers) = (path("i-peers.toml"), path("r-peers.toml"));
    let (i_key, r_key) = (path("i-identity.key"), path("r-identity.key"));
    let (req, acc, fin) = (path("req.blob"), path("acc.blob"), path("fin.blob"));
    let s = |p: &Path| p.to_str().unwrap().to_string();

    let mut initiator = StdCommand::new(binary())
        .args(["pair", "--manual", "--display-name", "laptop"])
        .args(["--emit-request-file", &s(&req)])
        .args(["--emit-finalize-file", &s(&fin)])
        .args(["--peers-file", &s(&i_peers)])
        .args(["--identity-file", &s(&i_key)])
        .env("HOME", i_home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("initiator starts");
    // The code is printed before the REQUEST blob is written.
    let mut i_err = BufReader::new(initiator.stderr.take().unwrap());
    let mut code = None;
    let mut line = String::new();
    while code.is_none() {
        line.clear();
        assert!(i_err.read_line(&mut line).unwrap() > 0, "initiator exited");
        if let Some(rest) = line.trim().strip_prefix("Code:") {
            code = rest.split_whitespace().next().map(str::to_string);
        }
    }
    let code = code.unwrap();
    wait_for_file(&req);

    let mut responder = StdCommand::new(binary())
        .args([
            "pair",
            "--responder",
            "--manual",
            "--display-name",
            "studio",
        ])
        .args(["--request-file", &s(&req)])
        .args(["--emit-accept-file", &s(&acc)])
        .args(["--code", &code])
        .args(["--peers-file", &s(&r_peers)])
        .args(["--identity-file", &s(&r_key)])
        .env("HOME", r_home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("responder starts");
    wait_for_file(&acc);

    // The human carries ACCEPT to the initiator…
    let accept = std::fs::read_to_string(&acc).unwrap();
    writeln!(initiator.stdin.as_mut().unwrap(), "{}", accept.trim()).unwrap();
    let i_ok = initiator
        .wait_timeout(Duration::from_secs(60))
        .expect("initiator exits");
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut i_err, &mut rest).unwrap();
    assert!(i_ok, "initiator failed:\n{rest}");

    // …and FINALIZE to the responder.
    let finalize = std::fs::read_to_string(&fin).unwrap();
    writeln!(responder.stdin.as_mut().unwrap(), "{}", finalize.trim()).unwrap();
    let r_ok = responder
        .wait_timeout(Duration::from_secs(60))
        .expect("responder exits");
    let mut r_err = String::new();
    std::io::Read::read_to_string(responder.stderr.as_mut().unwrap(), &mut r_err).unwrap();
    assert!(r_ok, "responder failed:\n{r_err}");

    assert_tokens_exchanged(&i_peers, &i_key, &r_peers, &r_key);
}

fn wait_for_file(p: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while !p.exists() || std::fs::read(p).map(|b| b.is_empty()).unwrap_or(true) {
        assert!(
            std::time::Instant::now() < deadline,
            "{} never appeared",
            p.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

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

/// `--print-code` shows a code and waits on the network. On the copy-paste
/// channel the code is shown by the side that runs without `--responder`,
/// so `--print-code` with `--manual` (or a blob file option) is refused as a
/// usage error instead of running the side that asks for a REQUEST blob.
#[test]
fn print_code_is_refused_on_the_manual_channel() {
    let home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let peers = work.path().join("peers.toml");
    let req = work.path().join("req.txt");
    for extra in [
        vec!["--manual"],
        vec!["--request-file", req.to_str().unwrap()],
    ] {
        let mut args = vec![
            "pair",
            "--print-code",
            "--peers-file",
            peers.to_str().unwrap(),
        ];
        args.extend(extra.iter().copied());
        let out = entangle(&home)
            .args(&args)
            .write_stdin("\n")
            .assert()
            .code(2)
            .get_output()
            .clone();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("REQUEST"), "{extra:?}:\n{stderr}");
        assert!(stderr.contains("--print-code"), "{extra:?}:\n{stderr}");
    }
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

// ---------------------------------------------------------------------------
// 4. Pairing UX (spec §6.3 failure modes, §9.4.2).
// ---------------------------------------------------------------------------

/// `--print-code` shows the code, the short and the full SHA-256
/// fingerprint and a QR code; when nobody pairs in time it says the code
/// expired and how to get a new one, and records the attempt for
/// `entangle diag pair`.
#[test]
fn print_code_shows_sha256_and_qr_then_expires_with_a_remedy() {
    let home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let peers = work.path().join("peers.toml");
    let out = StdCommand::new(binary())
        .args([
            "pair",
            "--print-code",
            "--display-name",
            "studio",
            "--bind",
            "127.0.0.1:0",
            "--no-mdns",
            "--timeout",
            "10",
            "--peers-file",
            peers.to_str().unwrap(),
            "--identity-file",
            work.path().join("id.key").to_str().unwrap(),
        ])
        .env("HOME", home.path())
        .env_remove("TERM")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    let sha = stderr
        .lines()
        .find_map(|l| l.trim().strip_prefix("SHA-256:"))
        .unwrap_or_else(|| panic!("no SHA-256 line:\n{stderr}"))
        .trim();
    assert!(
        sha.starts_with("SHA256:") && sha.len() == 7 + 64,
        "full hex fingerprint: {sha}"
    );
    // The value is the SHA-256 of the identity file's raw public key,
    // computed here independently of the CLI.
    let identity = entangle_signing::IdentityKeyPair::from_pem(
        &std::fs::read_to_string(work.path().join("id.key")).expect("identity written"),
    )
    .expect("identity parses");
    assert_eq!(
        sha,
        sha256_of_key(&hex::encode(identity.public().as_bytes())),
        "the printed SHA-256 is the digest of this device's public key"
    );
    assert!(stderr.contains("Pairing code:"), "{stderr}");
    let qr_rows = stderr.lines().filter(|l| l.contains('█')).count();
    assert!(qr_rows > 10, "a QR code is drawn:\n{stderr}");
    assert!(stderr.contains("ENTANGLE-E0786: code expired"), "{stderr}");
    assert!(stderr.contains("entangle pair --print-code"), "{stderr}");

    let log = std::fs::read_to_string(work.path().join("pairing-attempts.json")).unwrap();
    assert!(
        log.contains("\"show-code\"") && log.contains("\"failed\""),
        "{log}"
    );
}

/// No reachability: the error lists each transport tried and why it failed,
/// names what was not tried, and points at `entangle diag pair`, which then
/// shows the attempt.
#[test]
fn unreachable_device_lists_what_was_tried_and_diag_pair_shows_it() {
    let home = TempDir::new().unwrap();
    let peers = home.path().join(".entangle/peers.toml");
    std::fs::create_dir_all(peers.parent().unwrap()).unwrap();
    // A key nobody listens for, on a loopback port nothing serves.
    let ghost = hex::encode(
        entangle_signing::IdentityKeyPair::generate()
            .public()
            .as_bytes(),
    );
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead = sock.local_addr().unwrap();
    drop(sock);
    let a = entangle(&home)
        .args([
            "pair",
            "--peer",
            &format!("{ghost}@{dead}"),
            "--code",
            "123-456",
            "--yes",
            "--no-mdns",
            "--bind",
            "127.0.0.1:0",
        ])
        .timeout(Duration::from_secs(90))
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&a.get_output().stderr).into_owned();
    for needle in [
        "ENTANGLE-E0788",
        "Transports tried:",
        "mesh.iroh (QUIC)",
        &dead.to_string(),
        "mesh.tailscale",
        "entangle diag pair",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?}:\n{stderr}");
    }

    let a = entangle(&home)
        .args([
            "diag",
            "pair",
            "--json",
            "--no-mdns",
            "--bind",
            "127.0.0.1:0",
        ])
        .env("PATH", "/nonexistent")
        .timeout(Duration::from_secs(60))
        .assert()
        .success();
    let report: serde_json::Value = serde_json::from_slice(&a.get_output().stdout).unwrap();
    assert_eq!(report["quic"]["status"], "ok", "{report:#}");
    assert_eq!(report["mdns"]["status"], "skipped");
    assert_eq!(report["tailscale"]["state"], "uninstalled");
    let last = &report["last_attempts"][0];
    assert_eq!(last["role"], "enter-code", "{report:#}");
    assert_eq!(last["outcome"], "failed");
    assert!(
        last["tried"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["transport"] == "mesh.iroh (QUIC)"),
        "{report:#}"
    );
    assert!(
        report["hints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h.as_str().unwrap().contains("last pairing attempt failed")),
        "{report:#}"
    );

    // The text form says the same.
    entangle(&home)
        .args(["diag", "pair", "--no-mdns", "--bind", "127.0.0.1:0"])
        .env("PATH", "/nonexistent")
        .timeout(Duration::from_secs(60))
        .assert()
        .success()
        .stdout(predicate::str::contains("Last pairing attempts"))
        .stdout(predicate::str::contains("enter-code"))
        .stdout(predicate::str::contains("QUIC endpoint"));
}

/// The copy-paste channel's expiry says so with a stable code and the remedy.
#[test]
fn manual_request_past_its_expiry_says_the_code_expired() {
    use base64::Engine as _;
    let home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let kp = entangle_signing::IdentityKeyPair::generate();
    let key = *kp.public().as_bytes();
    let code: entangle_pairing::PairingCode = "123-456".parse().unwrap();
    let request = entangle_pairing::PairingRequest {
        initiator_peer_id: entangle_types::peer_id::PeerId::from_public_key_bytes(&key),
        initiator_pubkey_hex: hex::encode(key),
        initiator_display_name: "old".into(),
        code_commit: entangle_pairing::make_code_commit(code, &key),
        nonce: [0; 32],
        created_at_secs: 1,
    };
    let blob = format!(
        "ENT-REQ-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&request).unwrap())
    );
    let req = work.path().join("req.blob");
    std::fs::write(&req, blob).unwrap();
    entangle(&home)
        .args([
            "pair",
            "--responder",
            "--request-file",
            req.to_str().unwrap(),
            "--code",
            "123-456",
            "--peers-file",
            work.path().join("peers.toml").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0786: code expired"))
        .stderr(predicate::str::contains("entangle pair --manual"));
}
