//! ATC-REL-1 (dual-signature release verification) and ATC-REL-2 (Shamir
//! 2-of-3 key ceremony), driven through the real `entangle` binary.
//!
//! The Ed25519 half uses the real signing path. The cosign half uses a **fake
//! `cosign` script** that exits 0 only when it receives exactly the argument
//! vector `entangle release verify` is specified to send:
//! `verify-blob --bundle <bundle> --certificate-identity-regexp <re>
//! --certificate-oidc-issuer <issuer> <blob>`, where `<blob>` holds the
//! bytes its bundle covers (by default the artifact's). Real cosign, against a real
//! Rekor entry, is exercised by the `sigstore-attest` job of
//! `.github/workflows/release.yml`, which runs the same flags and pins the
//! same identity (checked by the workflow test below).

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// The identity `entangle release verify` pins for the fixture's artifact
/// (`entanglement-v1.0.0-rc1-...`): that one tag, nothing else.
const ID_RE: &str = r"^https://github\.com/thekozugroup/Entanglement/\.github/workflows/release\.yml@refs/tags/v1\.0\.0-rc1$";
const ISSUER: &str = "https://token.actions.githubusercontent.com";

fn entangle(home: &Path) -> Command {
    let mut c = Command::cargo_bin("entangle").unwrap();
    c.env("HOME", home);
    c
}

/// Path of the fake cosign script, written once per test process.
///
/// Writing an executable per test would leave a window in which another test
/// thread forks while the script's write descriptor is still open, and a
/// later `exec` of it fails with "Text file busy" (ETXTBSY). Initialising it
/// once, before any test can spawn a process, closes that window.
fn fake_cosign_script() -> &'static Path {
    static SCRIPT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    SCRIPT.get_or_init(|| {
        let dir = TempDir::new().unwrap();
        let bin = dir.path().join("cosign");
        write_fake_cosign(&bin);
        // Keep the directory for the life of the process.
        std::mem::forget(dir);
        bin
    })
}

/// Fake cosign on `dir`'s PATH entry (a symlink to the shared script).
fn fake_cosign(dir: &Path) -> PathBuf {
    let link = dir.join("cosign");
    std::os::unix::fs::symlink(fake_cosign_script(), &link).unwrap();
    link
}

/// Fake cosign that validates its arguments and records them.
fn write_fake_cosign(bin: &Path) {
    std::fs::write(
        bin,
        r#"#!/bin/sh
echo "$@" > "$COSIGN_ARGS_LOG"
[ "$1" = "verify-blob" ] || { echo "bad subcommand" >&2; exit 64; }
[ "$2" = "--bundle" ] && [ "$3" = "$EXPECT_BUNDLE" ] || { echo "bad bundle" >&2; exit 65; }
# Like the real cosign, refuse a bundle that does not exist.
[ -f "$3" ] || { echo "bundle not found" >&2; exit 71; }
[ "$4" = "--certificate-identity-regexp" ] || { echo "bad identity flag" >&2; exit 66; }
[ -z "$EXPECT_ID" ] || [ "$5" = "$EXPECT_ID" ] || { echo "bad identity" >&2; exit 66; }
# The bundle's certificate identity (SAN) must match the regexp. cosign
# searches it unanchored with Go's regexp.MatchString; POSIX ERE (grep -E)
# agrees with RE2 on the patterns used here.
[ -z "$CERT_SAN" ] || printf '%s\n' "$CERT_SAN" | grep -Eq -- "$5" || { echo "no identity matched" >&2; exit 70; }
[ "$6" = "--certificate-oidc-issuer" ] && [ "$7" = "$EXPECT_ISSUER" ] || { echo "bad issuer" >&2; exit 67; }
[ "$#" -eq 8 ] || { echo "bad arity" >&2; exit 68; }
# A concurrent writer replacing the artifact at its path between the
# Ed25519 read and this one (the TOCTOU window).
[ -z "$SWAP_ARTIFACT_WITH" ] || cp "$SWAP_ARTIFACT_WITH" "$EXPECT_ARTIFACT"
# The bundle covers EXPECT_BLOB's bytes (default: the artifact's).
cmp -s "$8" "${EXPECT_BLOB:-$EXPECT_ARTIFACT}" || { echo "blob does not match the bundle" >&2; exit 69; }
exit "${COSIGN_EXIT:-0}"
"#,
    )
    .unwrap();
    std::fs::set_permissions(bin, std::fs::Permissions::from_mode(0o755)).unwrap();
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
    // The fake cosign saw exactly the specified invocation. The blob is a
    // private copy of the artifact's bytes (the fake compared its content),
    // not the artifact path, which could be re-read with other contents.
    let args = std::fs::read_to_string(log).unwrap();
    let (head, blob) = args.trim().rsplit_once(' ').unwrap();
    assert_eq!(
        head,
        format!(
            "verify-blob --bundle {}.sigstore --certificate-identity-regexp {ID_RE} \
             --certificate-oidc-issuer {ISSUER}",
            f.artifact.display()
        )
    );
    assert_ne!(
        Path::new(blob),
        f.artifact,
        "cosign must not re-read the artifact path"
    );
    assert!(Path::new(blob).is_absolute(), "{blob}");
    assert!(
        blob.ends_with("/entanglement-v1.0.0-rc1-x86_64.tar.gz"),
        "{blob}"
    );
    assert!(
        !Path::new(blob).exists(),
        "the private copy is removed afterwards"
    );
}

#[test]
fn atc_rel_1_explicit_release_key_replaces_the_keyring() {
    let f = fixture();
    // No keyring entry at all; the key is given on the command line.
    let (mut c, _) = f.verify(&["--release-key", &f.pubkey]);
    c.assert()
        .success()
        .stdout(predicate::str::contains("PASS"));
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

/// Either signature missing or malformed fails verification, and the other
/// half passing does not rescue it.
#[test]
fn atc_rel_1_missing_or_malformed_signature_files_fail() {
    // Missing .ed25519 sidecar: cosign alone is not enough.
    let f = fixture();
    f.trust_as_release_key();
    std::fs::remove_file(sidecar(&f.artifact, "ed25519")).unwrap();
    let (mut c, _) = f.verify(&[]);
    c.assert()
        .failure()
        .stdout(predicate::str::contains("PASS").not())
        .stderr(predicate::str::contains("ENTANGLE-E0841"));

    // Unparseable .ed25519 sidecar.
    let f = fixture();
    f.trust_as_release_key();
    std::fs::write(sidecar(&f.artifact, "ed25519"), "this is not toml {{{").unwrap();
    let (mut c, _) = f.verify(&[]);
    c.assert()
        .failure()
        .stdout(predicate::str::contains("PASS").not())
        .stderr(predicate::str::contains("ENTANGLE-E0841"));

    // Empty .ed25519 sidecar.
    let f = fixture();
    f.trust_as_release_key();
    std::fs::write(sidecar(&f.artifact, "ed25519"), "").unwrap();
    let (mut c, _) = f.verify(&[]);
    c.assert()
        .failure()
        .stdout(predicate::str::contains("PASS").not());

    // Missing .sigstore bundle: the Ed25519 half passing is not enough.
    let f = fixture();
    f.trust_as_release_key();
    std::fs::remove_file(sidecar(&f.artifact, "sigstore")).unwrap();
    let (mut c, _) = f.verify(&[]);
    c.assert()
        .failure()
        .stdout(predicate::str::contains("PASS").not())
        .stderr(predicate::str::contains("ENTANGLE-E0846"));
}

/// Both signatures must cover one byte string. An artifact replaced at its
/// path between the Ed25519 check and the cosign check (a FIFO, a symlink
/// swap, a network filesystem) must not combine a release-key signature over
/// one file with a cosign bundle over another.
#[test]
fn atc_rel_1_both_checks_cover_the_same_bytes() {
    let f = fixture();
    f.trust_as_release_key();
    // `legit`: what the cosign bundle covers. The artifact on disk (signed
    // with the release key) is different.
    let legit = f.home.path().join("legit.tar.gz");
    std::fs::write(&legit, b"legitimate release tarball").unwrap();
    let (mut c, _) = f.verify(&[]);
    c.env("EXPECT_BLOB", &legit)
        .env("SWAP_ARTIFACT_WITH", &legit)
        .assert()
        .failure()
        .stdout(predicate::str::contains("PASS").not())
        .stderr(predicate::str::contains("ENTANGLE-E0846"));
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

/// With the default identity, only a bundle signed by the release workflow on
/// the artifact's own tag is accepted: not another workflow, not a branch,
/// pull-request or dispatch run of release.yml (which any writer can start,
/// with that branch's copy of the file), not another repository, and not
/// another release's tag run (rollback).
#[test]
fn atc_rel_1_default_identity_accepts_only_the_artifacts_own_tag_run() {
    let f = fixture();
    f.trust_as_release_key();
    let wf = "https://github.com/thekozugroup/Entanglement/.github/workflows/release.yml@";
    let run = |san: &str| {
        let (mut c, _) = f.verify(&[]);
        c.env_remove("EXPECT_ID").env("CERT_SAN", san).assert()
    };
    run(&format!("{wf}refs/tags/v1.0.0-rc1"))
        .success()
        .stdout(predicate::str::contains("PASS"));
    for bad in [
        // Other releases (an older bundle renamed to this version).
        format!("{wf}refs/tags/v1.0.0"),
        format!("{wf}refs/tags/v0.9.0"),
        format!("{wf}refs/tags/v2.0.0-rc1"),
        format!("{wf}refs/tags/v1.0.0-rc10"),
        format!("{wf}refs/tags/v1x0x0-rc1"),
        format!("{wf}refs/tags/v1.0.0-rc1.1"),
        // Not a tag run of the release workflow.
        format!("{wf}refs/heads/main"),
        format!("{wf}refs/pull/7/merge"),
        format!("{wf}refs/tags/v1.0.0-rc1/x"),
        "https://github.com/thekozugroup/Entanglement/.github/workflows/other.yml@refs/tags/v1.0.0-rc1"
            .to_owned(),
        "https://github.com/thekozugroup/Entanglement2/.github/workflows/release.yml@refs/tags/v1.0.0-rc1"
            .to_owned(),
        format!("https://evil.example/{wf}refs/tags/v1.0.0-rc1"),
    ] {
        run(&bad)
            .failure()
            .stdout(predicate::str::contains("PASS").not())
            .stderr(predicate::str::contains("ENTANGLE-E0846"));
    }
}

/// `--tag` pins the identity when the file name does not carry the release;
/// a name that does must agree with it, and with neither the command refuses
/// instead of falling back to "any tag".
#[test]
fn atc_rel_1_tag_flag_and_inference() {
    let f = fixture();
    f.trust_as_release_key();
    let wf = "https://github.com/thekozugroup/Entanglement/.github/workflows/release.yml@";

    // A file renamed away from the release naming: --tag is required.
    let plain = f.home.path().join("download.tar.gz");
    std::fs::copy(&f.artifact, &plain).unwrap();
    std::fs::copy(sidecar(&f.artifact, "ed25519"), sidecar(&plain, "ed25519")).unwrap();
    std::fs::copy(
        sidecar(&f.artifact, "sigstore"),
        sidecar(&plain, "sigstore"),
    )
    .unwrap();
    let verify_plain = |extra: &[&str], san: &str| {
        let mut c = entangle(f.home.path());
        let path = format!(
            "{}:{}",
            f.bin_dir.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        c.env("PATH", path)
            .env("COSIGN_ARGS_LOG", f.home.path().join("log2"))
            .env("EXPECT_BUNDLE", sidecar(&plain, "sigstore"))
            .env("EXPECT_ISSUER", ISSUER)
            .env("EXPECT_ARTIFACT", &plain)
            .env("CERT_SAN", san)
            .args(["release", "verify"])
            .arg(&plain)
            .args(extra)
            .assert()
    };
    verify_plain(&[], &format!("{wf}refs/tags/v1.2.3"))
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0847").and(predicate::str::contains("--tag")))
        .stdout(predicate::str::contains("PASS").not());
    verify_plain(&["--tag", "v1.2.3"], &format!("{wf}refs/tags/v1.2.3"))
        .success()
        .stdout(predicate::str::contains("PASS"));
    // The renamed-older-release attack: the bundle is from v1.2.2's run.
    verify_plain(&["--tag", "v1.2.3"], &format!("{wf}refs/tags/v1.2.2"))
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0846"));
    for bad in ["1.2.3", "v1.2", "v1.2.3/x", ".*", "v1.2.3$|x"] {
        verify_plain(&["--tag", bad], &format!("{wf}refs/tags/v1.2.3"))
            .failure()
            .stderr(predicate::str::contains("ENTANGLE-E0847"));
    }
    // --tag may not contradict a release-style name.
    let (mut c, _) = f.verify(&["--tag", "v9.9.9"]);
    c.assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0848"))
        .stdout(predicate::str::contains("PASS").not());
    let (mut c, _) = f.verify(&["--tag", "v1.0.0-rc1"]);
    c.assert().success();
    // An explicit identity regexp replaces the pinning (and excludes --tag).
    // Rejected by argument validation (clap), before cosign is ever run.
    let (mut c, log) = f.verify(&["--certificate-identity-regexp", "x", "--tag", "v1.0.0-rc1"]);
    let _ = std::fs::remove_file(&log); // left by the earlier runs of this test
    c.assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
    assert!(!log.exists(), "cosign must not have been invoked");
}

/// The cosign half is only an independent control if its identity is narrow:
/// the release workflow, on the one tag ref. The workflow signs only on tag
/// runs and verifies with the identity `entangle release verify` pins for that
/// tag: the test runs the workflow's own verify step with a fake `cosign` and
/// compares the identity regexp it passes with the CLI's (`ID_RE`).
#[test]
fn atc_rel_1_release_workflow_signs_only_tag_runs_and_verifies_with_the_pinned_identity() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml"),
    )
    .unwrap();
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
    let job = &doc["jobs"]["sigstore-attest"];
    assert_eq!(
        job["if"].as_str(),
        Some("startsWith(github.ref, 'refs/tags/v')"),
        "sigstore-attest must not sign branch or dispatch runs"
    );
    let verify = job["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|s| {
            s["run"]
                .as_str()
                .is_some_and(|r| r.contains("cosign verify-blob"))
        })
        .expect("a cosign verify-blob step");
    let run = verify["run"].as_str().unwrap();
    assert!(run.contains("--certificate-identity-regexp \"${identity_re}\""));
    // The env the step declares, filled as GitHub would for the fixture's tag.
    assert_eq!(verify["env"]["REPO"].as_str(), Some("${{ github.repository }}"));
    assert_eq!(verify["env"]["REF_NAME"].as_str(), Some("${{ github.ref_name }}"));

    let dir = TempDir::new().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let cosign = bin.join("cosign");
    std::fs::write(
        &cosign,
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = --certificate-identity-regexp ]; then printf '%s' \"$2\" > \"$OUT\"; fi\n  shift\ndone\n",
    )
    .unwrap();
    std::fs::set_permissions(&cosign, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.path().join("entanglement-v1.0.0-rc1-x.tar.gz"), b"x").unwrap();
    let out = dir.path().join("identity");
    let status = std::process::Command::new("bash")
        .arg("-ec")
        .arg(run)
        .current_dir(dir.path())
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("REPO", "thekozugroup/Entanglement")
        .env("REF_NAME", "v1.0.0-rc1")
        .env("OUT", &out)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(std::fs::read_to_string(&out).unwrap(), ID_RE);
}

// ---------------------------------------------------------------------------
// ATC-REL-2
// ---------------------------------------------------------------------------

fn split_2_of_3(f: &Fixture, dir: &Path) -> Vec<PathBuf> {
    entangle(f.home.path())
        .args([
            "release",
            "key",
            "split",
            "--threshold",
            "2",
            "--shares",
            "3",
        ])
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
    .args(["--release-key", &f.pubkey, "--tag", "v1.0.0-rc1"])
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
