//! CLI integration tests for the `entangle mesh` subcommand.
//!
//! Tests avoid mDNS / multicast — all network-dependent paths are covered by
//! daemon-not-running assertions or direct on-disk file writes.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

// ── helpers ──────────────────────────────────────────────────────────────────

fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    cmd
}

/// Generate a valid 32-byte Ed25519 public key and return (peer_id_hex, pubkey_hex).
/// The peer_id is the PeerId::from_public_key_bytes hex (16 bytes = 32 hex chars).
fn make_test_peer() -> (String, String) {
    use entangle_signing::IdentityKeyPair;
    use entangle_types::peer_id::PeerId;
    let kp = IdentityKeyPair::generate();
    let verifying = kp.public();
    let pub_bytes = verifying.as_bytes();
    let peer_id = PeerId::from_public_key_bytes(pub_bytes);
    (peer_id.to_hex(), hex::encode(pub_bytes))
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Without a running daemon and without --allow-local, `mesh peers` must fail
/// with a message mentioning "daemon not running".
#[test]
fn mesh_peers_with_no_daemon_errors_clearly() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["mesh", "peers"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("daemon not running"));
}

/// Without a running daemon and without --allow-local, `mesh status` must fail
/// with a message mentioning "daemon not running".
#[test]
fn mesh_status_with_no_daemon_errors_clearly() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["mesh", "status"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("daemon not running"));
}

/// `entangle mesh trust <peer_id> --public-key-hex <hex> --display-name "test"`
/// must write a peers.toml in the HOME/.entangle directory.
#[test]
fn mesh_trust_writes_peers_toml() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let (peer_id, pub_hex) = make_test_peer();

    entangle(&tmp)
        .args([
            "mesh",
            "trust",
            &peer_id,
            "--public-key-hex",
            &pub_hex,
            "--display-name",
            "test-node",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("trusted"));

    let peers_toml = tmp.path().join(".entangle").join("peers.toml");
    assert!(peers_toml.exists(), "peers.toml was not created");

    let contents = std::fs::read_to_string(&peers_toml).unwrap();
    assert!(
        contents.contains("test-node"),
        "display_name not found in peers.toml: {contents}"
    );
}

/// Round-trip: trust then untrust removes the peer from peers.toml.
#[test]
fn mesh_untrust_removes_peer() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let (peer_id, pub_hex) = make_test_peer();

    // Trust the peer.
    entangle(&tmp)
        .args([
            "mesh",
            "trust",
            &peer_id,
            "--public-key-hex",
            &pub_hex,
            "--display-name",
            "to-remove",
        ])
        .assert()
        .success();

    let peers_toml = tmp.path().join(".entangle").join("peers.toml");
    let before = std::fs::read_to_string(&peers_toml).unwrap();
    assert!(before.contains("to-remove"), "peer not written");

    // Untrust the peer.
    entangle(&tmp)
        .args(["mesh", "untrust", &peer_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    let after = std::fs::read_to_string(&peers_toml).unwrap();
    assert!(
        !after.contains("to-remove"),
        "peer still present after untrust: {after}"
    );
}

/// `mesh trust` must reject a peer_id/public_key pair that does not correspond:
/// the id derived from the key must equal the supplied peer_id.
#[test]
fn mesh_trust_rejects_mismatched_id_and_key() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    // Two independent peers; cross the id of one with the pubkey of the other.
    let (peer_id_a, _pub_a) = make_test_peer();
    let (_peer_id_b, pub_b) = make_test_peer();

    entangle(&tmp)
        .args([
            "mesh",
            "trust",
            &peer_id_a,
            "--public-key-hex",
            &pub_b,
            "--display-name",
            "forged",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mismatch"));

    // Nothing should have been persisted.
    let peers_toml = tmp.path().join(".entangle").join("peers.toml");
    if peers_toml.exists() {
        let contents = std::fs::read_to_string(&peers_toml).unwrap();
        assert!(
            !contents.contains("forged"),
            "forged peer must not be written: {contents}"
        );
    }
}

/// `mesh peers --json` must emit output that parses as JSON.
#[test]
fn mesh_peers_json_parses_with_allow_local() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let out = entangle(&tmp)
        .args(["--allow-local", "mesh", "peers", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "mesh peers --json should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("mesh peers --json must emit valid JSON");
    assert!(
        value.get("peers").and_then(|p| p.as_array()).is_some(),
        "expected a `peers` array: {stdout}"
    );
}

/// `--allow-local` flag causes `mesh peers` to succeed even with no daemon.
#[test]
fn mesh_peers_with_allow_local_falls_back() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    entangle(&tmp)
        .args(["--allow-local", "mesh", "peers"])
        .assert()
        .success();
}

// ── capability-token revocation through the operator commands ────────────────
//
// Requirement 5 (`docs/architecture.md` §6.5: revocation is local): removing
// or revoking a peer must put the revocation ids of the `mesh.peer` token
// this node issued to it into `~/.entangle/revoked-tokens.toml`, so adding
// the peer back to the allowlist by hand (`mesh trust`) never revives that
// token. These tests drive the real `entangle` binary and then ask the real
// verifier, reading the same files the daemon reads, whether the old token
// still gets in.

mod tokens {
    use std::path::PathBuf;
    use std::sync::Arc;

    use entangle_biscuits::templates::{
        mint_mesh_peer, now_unix_secs, present_for_request, MintedToken, Operation,
        RequestVerifier, RevocationList, TokenError,
    };
    use entangle_peers::{PeerStore, RevocationStore, TrustedPeer, REVOCATIONS_FILE};
    use entangle_signing::IdentityKeyPair;
    use entangle_types::peer_id::PeerId;
    use tempfile::TempDir;

    use super::entangle;

    /// The daemon reads the revocation set the same way: through the
    /// persisted store, re-read when the file changes.
    #[derive(Debug)]
    struct FileRevocations(RevocationStore);

    impl RevocationList for FileRevocations {
        fn any_revoked(&self, ids: &[Vec<u8>]) -> Result<bool, String> {
            self.0.any_revoked(ids).map_err(|e| e.to_string())
        }
    }

    pub(super) struct Paired {
        pub home: TempDir,
        /// This node (the CLI's `HOME`).
        pub w: IdentityKeyPair,
        /// The peer.
        pub p_id: PeerId,
        pub p_pub_hex: String,
        /// The token `w` issued to the peer while pairing.
        pub issued: MintedToken,
        /// The token the peer issued to `w` (what `w` presents to it).
        pub presented: Vec<u8>,
    }

    pub(super) fn dir(home: &TempDir) -> PathBuf {
        home.path().join(".entangle")
    }

    /// A peer record as `entangle pair` stores it.
    pub(super) fn paired() -> Paired {
        let home = TempDir::new().unwrap();
        let w = IdentityKeyPair::generate();
        let p = IdentityKeyPair::generate();
        let w_id = PeerId::from_public_key_bytes(w.public().as_bytes());
        let p_id = PeerId::from_public_key_bytes(p.public().as_bytes());
        let issued = mint_mesh_peer(&w, p_id, None).unwrap();
        let presented = mint_mesh_peer(&p, w_id, None).unwrap().bytes;
        let p_pub_hex = hex::encode(p.public().as_bytes());
        std::fs::create_dir_all(dir(&home)).unwrap();
        PeerStore::open(dir(&home).join("peers.toml"))
            .unwrap()
            .add(
                TrustedPeer::new_validated(p_id, p_pub_hex.clone(), "peer".into())
                    .unwrap()
                    .with_tokens(Some(&presented), &issued.revocation_ids),
            )
            .unwrap();
        Paired {
            home,
            w,
            p_id,
            p_pub_hex,
            issued,
            presented,
        }
    }

    impl Paired {
        /// What `w`'s gate decides when the peer presents the token `w`
        /// issued it, attenuated for one request.
        pub fn w_admits_old_token(&self) -> Result<(), TokenError> {
            let revs = FileRevocations(RevocationStore::at(dir(&self.home).join(REVOCATIONS_FILE)));
            let verifier = RequestVerifier::new(self.w.public().as_bytes())
                .unwrap()
                .with_revocations(Arc::new(revs));
            let now = now_unix_secs();
            let request =
                present_for_request(&self.issued.bytes, self.w.public().as_bytes(), [9; 32], now)
                    .unwrap();
            verifier
                .verify(&request, self.p_id, [9; 32], Operation::Stream)
                .map(|_| ())
        }

        pub fn record(&self) -> Option<TrustedPeer> {
            PeerStore::open(dir(&self.home).join("peers.toml"))
                .unwrap()
                .get(&self.p_id)
        }

        pub fn trust_by_hand(&self, name: &str) {
            entangle(&self.home)
                .args([
                    "mesh",
                    "trust",
                    &self.p_id.to_hex(),
                    "--public-key-hex",
                    &self.p_pub_hex,
                    "--display-name",
                    name,
                ])
                .assert()
                .success();
        }
    }
}

#[test]
fn mesh_untrust_revokes_the_issued_token_so_a_manual_re_add_does_not_revive_it() {
    let paired = tokens::paired();
    paired
        .w_admits_old_token()
        .expect("before removal the peer's token is accepted");

    entangle(&paired.home)
        .args(["mesh", "untrust", &paired.p_id.to_hex()])
        .assert()
        .success();
    assert!(paired.record().is_none());

    paired.trust_by_hand("back-again");
    assert!(paired.record().is_some(), "re-added to the allowlist");
    assert_eq!(
        paired.w_admits_old_token(),
        Err(entangle_biscuits::templates::TokenError::Revoked),
        "the token issued before `mesh untrust` must stay revoked"
    );
}

#[test]
fn mesh_revoke_revokes_the_issued_token_so_re_trusting_does_not_revive_it() {
    let paired = tokens::paired();
    entangle(&paired.home)
        .args(["mesh", "revoke", &paired.p_id.to_hex()])
        .assert()
        .success();
    paired.trust_by_hand("forgiven");
    assert_eq!(
        paired.w_admits_old_token(),
        Err(entangle_biscuits::templates::TokenError::Revoked),
        "the token issued before `mesh revoke` must stay revoked"
    );
}

#[test]
fn mesh_trust_on_a_paired_peer_keeps_both_token_fields() {
    let paired = tokens::paired();
    paired.trust_by_hand("renamed");
    let record = paired.record().expect("still trusted");
    assert_eq!(record.display_name, "renamed");
    assert_eq!(
        record.capability_token_bytes(),
        Some(paired.presented.clone()),
        "re-trusting by hand must keep the token this node presents to the peer"
    );
    assert_eq!(
        record.issued_revocation_ids(),
        paired.issued.revocation_ids,
        "…and the record of the token it issued, so it can still be revoked"
    );
    // Which is what lets a later removal still revoke it.
    entangle(&paired.home)
        .args(["peers", "remove", &paired.p_id.to_hex()])
        .assert()
        .success();
    paired.trust_by_hand("again");
    assert_eq!(
        paired.w_admits_old_token(),
        Err(entangle_biscuits::templates::TokenError::Revoked)
    );
}

#[test]
fn peers_remove_revokes_the_issued_token_so_a_manual_re_add_does_not_revive_it() {
    let paired = tokens::paired();
    entangle(&paired.home)
        .args(["peers", "remove", &paired.p_id.to_hex()])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"));
    assert!(paired.record().is_none());
    let set = std::fs::read_to_string(tokens::dir(&paired.home).join("revoked-tokens.toml"))
        .expect("the revocation set is written");
    assert!(set.contains(&hex::encode(&paired.issued.revocation_ids[0])));

    paired.trust_by_hand("back-again");
    assert_eq!(
        paired.w_admits_old_token(),
        Err(entangle_biscuits::templates::TokenError::Revoked)
    );

    // Removing an unknown peer is an error, as with `mesh untrust`.
    entangle(&paired.home)
        .args(["peers", "remove", &make_test_peer().0])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn peers_list_shows_which_peers_hold_no_token() {
    let paired = tokens::paired();
    let (bare_id, bare_pub) = make_test_peer();
    entangle(&paired.home)
        .args([
            "mesh",
            "trust",
            &bare_id,
            "--public-key-hex",
            &bare_pub,
            "--display-name",
            "pre-token",
        ])
        .assert()
        .success();

    let out = entangle(&paired.home)
        .args(["peers", "list", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON");
    let peers = value["peers"].as_array().expect("a peers array");
    assert_eq!(peers.len(), 2, "{value}");
    let by_id = |id: &str| {
        peers
            .iter()
            .find(|p| p["peer_id"] == id)
            .unwrap_or_else(|| panic!("{id} listed: {value}"))
    };
    assert_eq!(by_id(&paired.p_id.to_hex())["has_token"], true);
    assert_eq!(by_id(&bare_id)["has_token"], false);
    // Never the token itself: it is a credential.
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains(&hex::encode(&paired.presented)));

    // The table says it in words, and says what to do.
    entangle(&paired.home)
        .args(["peers", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pre-token"))
        .stdout(predicate::str::contains("none"))
        .stdout(predicate::str::contains("entangle pair"));
}
