use std::fs;

use assert_cmd::Command;
use entangle_signing::IdentityKeyPair;
use predicates::str::contains;

#[test]
fn release_verify_requires_both_signatures_at_the_normal_entry_point() {
    let files = tempfile::tempdir().unwrap();
    let name = "entanglement-v1.2.3-x86_64-unknown-linux-gnu.tar.gz";
    let artifact = files.path().join(name);
    let bundle = files.path().join(format!("{name}.sigstore"));
    let signature = files.path().join(format!("{name}.sig"));
    let publisher = files.path().join("release.pub");
    let fixture_bytes = b"release fixture";
    let key = IdentityKeyPair::generate();
    fs::write(&artifact, fixture_bytes).unwrap();
    fs::write(&signature, key.sign(fixture_bytes).as_bytes()).unwrap();
    fs::write(&publisher, key.public().to_pem()).unwrap();

    let verify = || {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entangle"));
        command
            .args(["release", "verify"])
            .arg(&artifact)
            .arg("--publisher-key")
            .arg(&publisher);
        command
    };
    verify()
        .assert()
        .failure()
        .stderr(contains("reading Sigstore bundle"));

    fs::write(&bundle, "{}").unwrap();
    verify()
        .assert()
        .failure()
        .stderr(contains("invalid Sigstore blob bundle"));

    fs::write(&artifact, b"changed fixture").unwrap();
    verify()
        .assert()
        .failure()
        .stderr(contains("Ed25519 release publisher verification failed"));
}
