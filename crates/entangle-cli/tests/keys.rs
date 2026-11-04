//! `entangle keys gen` (spec §9.3 step 2, §12 M2).

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn entangle(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", home.path());
    cmd
}

#[test]
fn gen_writes_a_private_pem_and_its_public_half_and_never_overwrites() {
    let home = TempDir::new().unwrap();
    let out = entangle(&home)
        .args(["keys", "gen", "--label", "alice"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ed25519:"))
        .stdout(predicate::str::contains("fingerprint:"))
        .stdout(predicate::str::contains("entangle plugins build --key"))
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    let dir = home.path().join(".entangle/publishers");
    let pem = std::fs::read_to_string(dir.join("alice.key")).unwrap();
    let public = std::fs::read_to_string(dir.join("alice.pub")).unwrap();
    // The same key format every signing command reads.
    let kp = entangle_signing::IdentityKeyPair::from_pem(&pem).unwrap();
    assert_eq!(public.trim(), hex::encode(kp.public().as_bytes()));
    assert!(out.contains(&format!("ed25519:{}", public.trim())), "{out}");
    assert!(out.contains(&kp.fingerprint_hex()), "{out}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &str| std::fs::metadata(dir.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("alice.key"), 0o600);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    // A second run with the same label refuses and leaves the key alone.
    entangle(&home)
        .args(["keys", "gen", "--label", "alice"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0785"))
        .stderr(predicate::str::contains("refusing to overwrite"));
    assert_eq!(std::fs::read_to_string(dir.join("alice.key")).unwrap(), pem);
    // Not trusted unless asked.
    assert!(!home.path().join(".entangle/keyring.toml").exists());
}

#[test]
fn gen_with_trust_adds_the_key_to_the_keyring() {
    let home = TempDir::new().unwrap();
    entangle(&home)
        .args(["keys", "gen", "--label", "ci-signer", "--trust"])
        .assert()
        .success()
        .stdout(predicate::str::contains("trusted in"));
    let public =
        std::fs::read_to_string(home.path().join(".entangle/publishers/ci-signer.pub")).unwrap();
    let kr = entangle_signing::Keyring::load(&home.path().join(".entangle/keyring.toml")).unwrap();
    let entry = kr.entries().next().expect("one trusted key");
    assert_eq!(hex::encode(entry.public_key), public.trim());
    assert_eq!(entry.publisher_name, "ci-signer");
}

#[test]
fn a_label_that_is_not_a_safe_file_name_is_refused() {
    let home = TempDir::new().unwrap();
    entangle(&home)
        .args(["keys", "gen", "--label", "../escape"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0785"));
    assert!(!home.path().join(".entangle").exists());
}
