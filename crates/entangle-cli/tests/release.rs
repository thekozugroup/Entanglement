//! ATC-REL-1 (dual-signature release verification) and ATC-REL-2 (Shamir
//! 2-of-3 key ceremony), driven through the real `entangle` binary.
//!
//! The Ed25519 half uses the real signing path. The cosign half uses a **fake
//! `cosign` script** that exits 0 only when it receives exactly the argument
//! vector `entangle release verify` is specified to send:
//! `verify-blob --bundle <bundle> --certificate-identity-regexp <re>
//! --certificate-oidc-issuer <issuer> <artifact>`. Real cosign, against a real
//! Rekor entry, is exercised by the `sigstore-attest` job of
//! `.github/workflows/release.yml`, which runs the same flags.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const ID_RE: &str = "https://github.com/thekozugroup/Entanglement/.+";
const ISSUER: &str = "https://token.actions.githubusercontent.com";

fn entangle(home: &Path) -> Command {
    let mut c = Command::cargo_bin("entangle").unwrap();
    c.env("HOME", home);
    c
}

/// Fake cosign that validates its arguments and records them.
fn fake_cosign(dir: &Path) -> PathBuf {
    let bin = dir.join("cosign");
    std::fs::write(
        &bin,
        r#"#!/bin/sh
echo "$@" > "$COSIGN_ARGS_LOG"
[ "$1" = "verify-blob" ] || { echo "bad subcommand" >&2; exit 64; }
[ "$2" = "--bundle" ] && [ "$3" = "$EXPECT_BUNDLE" ] || { echo "bad bundle" >&2; exit 65; }
[ "$4" = "--certificate-identity-regexp" ] && [ "$5" = "$EXPECT_ID" ] || { echo "bad identity" >&2; exit 66; }
[ "$6" = "--certificate-oidc-issuer" ] && [ "$7" = "$EXPECT_ISSUER" ] || { echo "bad issuer" >&2; exit 67; }
[ "$8" = "$EXPECT_ARTIFACT" ] && [ "$#" -eq 8 ] || { echo "bad artifact/arity" >&2; exit 68; }
exit "${COSIGN_EXIT:-0}"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

struct Fixture {
    home: TempDir,
    bin_dir: TempDir,
    artifact: PathBuf,
    key: PathBuf,
    pubkey: String,
}

fn fixture() -> Fixture {
    let home = TempDir::new().unwrap();
    let bin_dir = TempDir::new().unwrap();
    fake_cosign(bin_dir.path());
    let artifact = home.path().join("entanglement-v1.0.0-rc1-x86_64.tar.gz");
    std::fs::write(&artifact, b"release tarball bytes").unwrap();
    std::fs::write(sidecar(&artifact, "sigstore"), b"fake bundle").unwrap();
    let key = home.path().join("release.pem");
    let out = entangle(home.path())
        .args(["release", "key", "generate", "--out"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let pubkey = text
        .lines()
        .find_map(|l| l.strip_prefix("public key:"))
        .unwrap()
        .trim()
        .to_owned();
    entangle(home.path())
        .args(["release", "sign"])
        .arg(&artifact)
        .arg("--key")
        .arg(&key)
        .assert()
        .success();
    Fixture {
        home,
        bin_dir,
        artifact,
        key,
        pubkey,
    }
}

fn sidecar(a: &Path, ext: &str) -> PathBuf {
    let mut s = a.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

impl Fixture {
    /// `entangle release verify` with the fake cosign first on PATH.
    fn verify(&self, extra: &[&str]) -> (Command, PathBuf) {
        let log = self.home.path().join("cosign-args.log");
        let mut c = entangle(self.home.path());
        let path = format!(
            "{}:{}",
            self.bin_dir.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        c.env("PATH", path)
            .env("COSIGN_ARGS_LOG", &log)
            .env("EXPECT_BUNDLE", sidecar(&self.artifact, "sigstore"))
            .env("EXPECT_ID", ID_RE)
            .env("EXPECT_ISSUER", ISSUER)
            .env("EXPECT_ARTIFACT", &self.artifact)
            .args(["release", "verify"])
            .arg(&self.artifact)
            .args(extra);
        (c, log)
    }

    fn trust_as_release_key(&self) {
        entangle(self.home.path())
            .args(["release", "key", "add", &self.pubkey, "--name", "rel"])
            .assert()
            .success();
    }
}

#[test]
fn atc_rel_1_dual_sig_pass() {
    let f = fixture();
    f.trust_as_release_key();
    let (mut c, log) = f.verify(&[]);
    c.assert()
        .success()
        .stdout(predicate::str::contains("ed25519: OK"))
        .stdout(predicate::str::contains("cosign:  OK"))
        .stdout(predicate::str::contains("PASS"));
    // The fake cosign saw exactly the specified invocation.
    let args = std::fs::read_to_string(log).unwrap();
    assert_eq!(
        args.trim(),
        format!(
            "verify-blob --bundle {}.sigstore --certificate-identity-regexp {ID_RE} \
             --certificate-oidc-issuer {ISSUER} {}",
            f.artifact.display(),
            f.artifact.display()
        )
    );
}

#[test]
fn atc_rel_1_explicit_release_key_replaces_the_keyring() {
    let f = fixture();
    // No keyring entry at all; the key is given on the command line.
    let (mut c, _) = f.verify(&["--release-key", &f.pubkey]);
    c.assert().success().stdout(predicate::str::contains("PASS"));
}

#[test]
fn atc_rel_1_cosign_failure_fails_even_when_ed25519_passes() {
    let f = fixture();
    f.trust_as_release_key();
    let (mut c, _) = f.verify(&[]);
    c.env("COSIGN_EXIT", "1")
        .assert()
        .failure()
        .stdout(predicate::str::contains("PASS").not())
        .stderr(predicate::str::contains("ENTANGLE-E0846"));
}

#[test]
fn atc_rel_1_ed25519_failure_fails_even_when_cosign_passes() {
    let f = fixture();
    // Signer is not in the (empty) release keyring.
    let (mut c, _) = f.verify(&[]);
    c.assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0843"))
        .stdout(predicate::str::contains("PASS").not());
}

#[test]
fn atc_rel_1_publisher_keys_are_not_release_keys() {
    let f = fixture();
    // Trust the signer as a *plugin publisher* only.
    entangle(f.home.path())
        .args(["keyring", "add", &f.pubkey, "--name", "publisher"])
        .assert()
        .success();
    let (mut c, _) = f.verify(&[]);
    c.assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0843"));
}

#[test]
fn atc_rel_1_tampered_artifact_fails() {
    let f = fixture();
    f.trust_as_release_key();
    std::fs::write(&f.artifact, b"release tarball bytes, tampered").unwrap();
    let (mut c, _) = f.verify(&[]);
    c.assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0842"));
}

#[test]
fn atc_rel_1_missing_cosign_is_an_error_not_a_pass() {
    let f = fixture();
    f.trust_as_release_key();
    let empty = TempDir::new().unwrap();
    let mut c = entangle(f.home.path());
    c.env("PATH", empty.path())
        .args(["release", "verify"])
        .arg(&f.artifact)
        .assert()
        .failure()
        .stdout(predicate::str::contains("PASS").not())
        .stderr(predicate::str::contains("ENTANGLE-E0845"))
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn atc_rel_1_cosign_path_and_identity_are_configurable() {
    let f = fixture();
    f.trust_as_release_key();
    let other = TempDir::new().unwrap();
    let cosign = fake_cosign(other.path());
    let (mut c, log) = f.verify(&[
        "--cosign",
        cosign.to_str().unwrap(),
        "--certificate-identity-regexp",
        "https://example.com/.+",
        "--certificate-oidc-issuer",
        "https://issuer.example",
    ]);
    // The fake still insists on the defaults, so a configured value must make
    // it reject, proving the flags reach cosign rather than being ignored.
    c.assert().failure();
    let args = std::fs::read_to_string(log).unwrap();
    assert!(args.contains("https://example.com/.+"), "{args}");
    assert!(args.contains("https://issuer.example"), "{args}");
}

#[test]
fn atc_rel_1_release_workflow_runs_real_cosign_with_the_same_flags() {
    let wf = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml"),
    )
    .unwrap();
    assert!(wf.contains("cosign verify-blob"), "{wf}");
    assert!(wf.contains("--certificate-identity-regexp"), "{wf}");
    assert!(wf.contains("--certificate-oidc-issuer"), "{wf}");
    assert!(wf.contains("--bundle"), "{wf}");
}

// ---------------------------------------------------------------------------
// ATC-REL-2
// ---------------------------------------------------------------------------

fn split_2_of_3(f: &Fixture, dir: &Path) -> Vec<PathBuf> {
    entangle(f.home.path())
        .args(["release", "key", "split", "--threshold", "2", "--shares", "3"])
        .arg(&f.key)
        .arg("--out-dir")
        .arg(dir)
        .assert()
        .success();
    (1..=3)
        .map(|i| dir.join(format!("release.pem.share-{i}")))
        .collect()
}

#[test]
fn atc_rel_2_two_of_three() {
    let f = fixture();
    let dir = f.home.path().join("shares");
    let shares = split_2_of_3(&f, &dir);
    let original = std::fs::read(&f.key).unwrap();

    // Any 2 of the 3 shares reconstruct the exact key, in either order.
    for (n, (a, b)) in [(0, 1), (0, 2), (1, 2), (2, 0)].into_iter().enumerate() {
        let out = f.home.path().join(format!("rebuilt-{n}.pem"));
        entangle(f.home.path())
            .args(["release", "key", "combine"])
            .arg(&shares[a])
            .arg(&shares[b])
            .arg("--out")
            .arg(&out)
            .assert()
            .success();
        assert_eq!(std::fs::read(&out).unwrap(), original, "pair {a},{b}");
    }

    // A reconstructed key really is the release key: it signs, and the
    // original public key verifies.
    let rebuilt = f.home.path().join("rebuilt-0.pem");
    let art2 = f.home.path().join("second.tar.gz");
    std::fs::write(&art2, b"another artifact").unwrap();
    entangle(f.home.path())
        .args(["release", "sign"])
        .arg(&art2)
        .arg("--key")
        .arg(&rebuilt)
        .assert()
        .success();
    std::fs::write(sidecar(&art2, "sigstore"), b"bundle").unwrap();
    let mut c = entangle(f.home.path());
    let log = f.home.path().join("l");
    c.env(
        "PATH",
        format!(
            "{}:{}",
            f.bin_dir.path().display(),
            std::env::var("PATH").unwrap()
        ),
    )
    .env("COSIGN_ARGS_LOG", log)
    .env("EXPECT_BUNDLE", sidecar(&art2, "sigstore"))
    .env("EXPECT_ID", ID_RE)
    .env("EXPECT_ISSUER", ISSUER)
    .env("EXPECT_ARTIFACT", &art2)
    .args(["release", "verify"])
    .arg(&art2)
    .args(["--release-key", &f.pubkey])
    .assert()
    .success();
}

#[test]
fn atc_rel_2_one_share_is_not_enough_and_wrong_shares_are_detected() {
    let f = fixture();
    let shares = split_2_of_3(&f, &f.home.path().join("shares"));

    // One share: reconstruction is impossible.
    let out = f.home.path().join("one.pem");
    entangle(f.home.path())
        .args(["release", "key", "combine"])
        .arg(&shares[0])
        .arg("--out")
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0855"));
    assert!(!out.exists(), "nothing may be written on failure");

    // The same share twice is still one share.
    entangle(f.home.path())
        .args(["release", "key", "combine"])
        .arg(&shares[0])
        .arg(&shares[0])
        .arg("--out")
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0854"));

    // Shares from a different split of the same key are rejected as mixed.
    let other = split_2_of_3_into(&f, &f.home.path().join("shares2"));
    entangle(f.home.path())
        .args(["release", "key", "combine"])
        .arg(&shares[0])
        .arg(&other[1])
        .arg("--out")
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0853"));

    // A typo in a share fails its checksum.
    let text = std::fs::read_to_string(&shares[1]).unwrap();
    let mut bytes = text.trim().to_owned().into_bytes();
    let i = bytes.len() - 7;
    bytes[i] = if bytes[i] == b'0' { b'1' } else { b'0' };
    let bad = f.home.path().join("bad.share");
    std::fs::write(&bad, bytes).unwrap();
    entangle(f.home.path())
        .args(["release", "key", "combine"])
        .arg(&shares[0])
        .arg(&bad)
        .arg("--out")
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0852"));
}

fn split_2_of_3_into(f: &Fixture, dir: &Path) -> Vec<PathBuf> {
    split_2_of_3(f, dir)
}

#[test]
fn atc_rel_2_ceremony_document_exists_with_a_rehearsal_template() {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/governance/key-ceremony.md"),
    )
    .unwrap();
    for needle in [
        "2-of-3",
        "entangle release key split --threshold 2 --shares 3",
        "entangle release key combine",
        "Rehearsal record",
    ] {
        assert!(doc.contains(needle), "key-ceremony.md lacks {needle:?}");
    }
}
