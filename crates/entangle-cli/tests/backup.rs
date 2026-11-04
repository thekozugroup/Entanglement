//! `entangle backup` / `entangle restore` end to end (spec §6.5, §9.6).
//!
//! Each test runs the real binary with HOME pointing at a temp dir, so the
//! operator's `~/.entangle/` is never touched.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use entangle_signing::IdentityKeyPair;
use predicates::prelude::*;
use tempfile::TempDir;

fn entangle(home: &Path) -> Command {
    let mut c = Command::cargo_bin("entangle").expect("entangle binary built");
    c.env("HOME", home).env_remove("ENTANGLE_BACKUP_PASSPHRASE");
    c
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// A populated `~/.entangle/`; returns the PeerId of its identity.
fn populate(home: &Path) -> String {
    let dir = home.join(".entangle");
    std::fs::create_dir_all(&dir).unwrap();
    let kp = IdentityKeyPair::generate();
    std::fs::write(dir.join("identity.key"), kp.to_pem()).unwrap();
    std::fs::write(
        dir.join("peers.toml"),
        "[[peers]]\nname = \"laptop\"\npeer_id = \"00112233445566778899aabbccddeeff\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("keyring.toml"),
        "# publisher keys\n[[keys]]\nname = \"me\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.toml"),
        "[security]\nmax_tier_allowed = 4\n",
    )
    .unwrap();
    kp.fingerprint_hex()
}

fn passfile(dir: &Path, pass: &str) -> PathBuf {
    let p = dir.join("pass.txt");
    std::fs::write(&p, format!("{pass}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn backup(home: &Path, to: &Path, pass: &Path, extra: &[&str]) -> assert_cmd::assert::Assert {
    entangle(home)
        .args(["backup", "--to"])
        .arg(to)
        .arg("--passphrase-file")
        .arg(pass)
        .args(extra)
        .assert()
}

fn restore(home: &Path, from: &Path, pass: &Path, extra: &[&str]) -> assert_cmd::assert::Assert {
    entangle(home)
        .args(["restore", "--from"])
        .arg(from)
        .arg("--passphrase-file")
        .arg(pass)
        .args(extra)
        .assert()
}

#[test]
fn round_trip_restores_identity_peers_and_keyring_bit_for_bit() {
    let old = TempDir::new().unwrap();
    let peer_id = populate(old.path());
    let work = TempDir::new().unwrap();
    let pass = passfile(work.path(), "correct horse battery");
    let ar = work.path().join("node.bak");

    backup(old.path(), &ar, &pass, &["--include-config"])
        .success()
        .stdout(predicate::str::contains(&peer_id));
    assert_eq!(mode(&ar), 0o600);
    // The sentinel that silences the daemon's backup nag is set.
    assert!(old.path().join(".entangle/.identity_backed_up").exists());

    let new = TempDir::new().unwrap();
    restore(new.path(), &ar, &pass, &[])
        .success()
        .stdout(predicate::str::contains(&peer_id));

    let (o, n) = (old.path().join(".entangle"), new.path().join(".entangle"));
    for f in ["identity.key", "peers.toml", "keyring.toml", "config.toml"] {
        assert_eq!(
            std::fs::read(o.join(f)).unwrap(),
            std::fs::read(n.join(f)).unwrap(),
            "{f}"
        );
        assert_eq!(mode(&n.join(f)), 0o600, "{f} mode");
    }
    assert_eq!(mode(&n), 0o700);
    let kp = IdentityKeyPair::from_pem(&std::fs::read_to_string(n.join("identity.key")).unwrap())
        .unwrap();
    assert_eq!(kp.fingerprint_hex(), peer_id);
}

#[test]
fn config_is_excluded_unless_asked_for() {
    let old = TempDir::new().unwrap();
    populate(old.path());
    let work = TempDir::new().unwrap();
    let pass = passfile(work.path(), "correct horse battery");
    let ar = work.path().join("node.bak");
    backup(old.path(), &ar, &pass, &[]).success();
    let new = TempDir::new().unwrap();
    restore(new.path(), &ar, &pass, &[]).success();
    assert!(!new.path().join(".entangle/config.toml").exists());
    assert!(new.path().join(".entangle/peers.toml").exists());
}

#[test]
fn wrong_passphrase_fails_clearly_and_writes_nothing() {
    let old = TempDir::new().unwrap();
    populate(old.path());
    let work = TempDir::new().unwrap();
    let good = passfile(work.path(), "correct horse battery");
    let ar = work.path().join("node.bak");
    backup(old.path(), &ar, &good, &[]).success();

    let bad_dir = TempDir::new().unwrap();
    let bad = passfile(bad_dir.path(), "wrong horse battery");
    let new = TempDir::new().unwrap();
    restore(new.path(), &ar, &bad, &[]).failure().stderr(
        predicate::str::contains("ENTANGLE-E0862")
            .and(predicate::str::contains("wrong passphrase")),
    );
    assert!(
        !new.path().join(".entangle").exists(),
        "nothing may be written"
    );
}

#[test]
fn tampered_and_truncated_archives_are_rejected_without_writing() {
    let old = TempDir::new().unwrap();
    populate(old.path());
    let work = TempDir::new().unwrap();
    let pass = passfile(work.path(), "correct horse battery");
    let ar = work.path().join("node.bak");
    backup(old.path(), &ar, &pass, &[]).success();
    let bytes = std::fs::read(&ar).unwrap();

    // Header (magic, version, salt, nonce), body and tag, one byte each.
    for idx in [0, 9, 30, 50, 63, bytes.len() / 2, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[idx] ^= 0x80;
        let p = work.path().join(format!("bad{idx}.bak"));
        std::fs::write(&p, bad).unwrap();
        let new = TempDir::new().unwrap();
        restore(new.path(), &p, &pass, &[]).failure();
        assert!(!new.path().join(".entangle").exists(), "byte {idx}");
    }
    for len in [0, 8, 62, 70, bytes.len() - 1] {
        let p = work.path().join(format!("short{len}.bak"));
        std::fs::write(&p, &bytes[..len]).unwrap();
        let new = TempDir::new().unwrap();
        restore(new.path(), &p, &pass, &[]).failure();
        assert!(!new.path().join(".entangle").exists(), "len {len}");
    }
    // Not a backup at all.
    let p = work.path().join("junk");
    std::fs::write(&p, b"hello").unwrap();
    restore(TempDir::new().unwrap().path(), &p, &pass, &[])
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0861"));
}

#[test]
fn restore_onto_existing_identity_needs_force_and_keeps_a_copy() {
    let old = TempDir::new().unwrap();
    let peer_id = populate(old.path());
    let work = TempDir::new().unwrap();
    let pass = passfile(work.path(), "correct horse battery");
    let ar = work.path().join("node.bak");
    backup(old.path(), &ar, &pass, &[]).success();

    let new = TempDir::new().unwrap();
    let other_peer = populate(new.path());
    assert_ne!(other_peer, peer_id);
    let before = std::fs::read(new.path().join(".entangle/identity.key")).unwrap();

    restore(new.path(), &ar, &pass, &[])
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0864"));
    assert_eq!(
        std::fs::read(new.path().join(".entangle/identity.key")).unwrap(),
        before
    );

    restore(new.path(), &ar, &pass, &["--force"]).success();
    let dir = new.path().join(".entangle");
    let kp = IdentityKeyPair::from_pem(&std::fs::read_to_string(dir.join("identity.key")).unwrap())
        .unwrap();
    assert_eq!(kp.fingerprint_hex(), peer_id);
    let bak = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("restore-backup-")
        })
        .expect("restore-backup directory");
    assert_eq!(std::fs::read(bak.join("identity.key")).unwrap(), before);
    assert_eq!(mode(&bak.join("identity.key")), 0o600);
    assert_eq!(mode(&bak), 0o700);
}

#[test]
fn backup_refuses_to_clobber_and_needs_a_passphrase_source() {
    let old = TempDir::new().unwrap();
    populate(old.path());
    let work = TempDir::new().unwrap();
    let pass = passfile(work.path(), "correct horse battery");
    let ar = work.path().join("node.bak");
    backup(old.path(), &ar, &pass, &[]).success();
    backup(old.path(), &ar, &pass, &[])
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0865"));
    backup(old.path(), &ar, &pass, &["--force"]).success();
    assert_eq!(mode(&ar), 0o600);

    // No TTY, no file, no env: a clear error rather than a hang.
    entangle(old.path())
        .args(["backup", "--to"])
        .arg(work.path().join("x.bak"))
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0860"));
    // The env var works and never needs argv.
    entangle(old.path())
        .env("ENTANGLE_BACKUP_PASSPHRASE", "from the environment")
        .args(["backup", "--to"])
        .arg(work.path().join("env.bak"))
        .assert()
        .success();
    // Weak passphrases are refused when creating a backup.
    let short = passfile(work.path(), "abc");
    backup(old.path(), &work.path().join("s.bak"), &short, &[])
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0860"));
}

#[test]
fn backup_without_an_identity_is_refused() {
    let home = TempDir::new().unwrap();
    let pass = passfile(home.path(), "correct horse battery");
    backup(home.path(), &home.path().join("x.bak"), &pass, &[])
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0866"));
    assert!(!home.path().join("x.bak").exists());
}

/// `ENTANGLE_BACKUP_PASSPHRASE` takes precedence over the terminal prompt
/// (as `RESTIC_PASSWORD` or `BORG_PASSPHRASE` do), so it is never used
/// silently: both commands say where the passphrase came from.
#[test]
fn a_passphrase_from_the_environment_is_announced() {
    let old = TempDir::new().unwrap();
    populate(old.path());
    let work = TempDir::new().unwrap();
    let ar = work.path().join("env.bak");
    entangle(old.path())
        .env("ENTANGLE_BACKUP_PASSPHRASE", "from the environment")
        .args(["backup", "--to"])
        .arg(&ar)
        .assert()
        .success()
        .stderr(predicate::str::contains("ENTANGLE_BACKUP_PASSPHRASE"))
        .stderr(predicate::str::contains("from the environment").not());
    let new = TempDir::new().unwrap();
    entangle(new.path())
        .env("ENTANGLE_BACKUP_PASSPHRASE", "from the environment")
        .args(["restore", "--from"])
        .arg(&ar)
        .assert()
        .success()
        .stderr(predicate::str::contains("ENTANGLE_BACKUP_PASSPHRASE"));
    // The help text states the same order.
    entangle(old.path())
        .args(["backup", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("even at a terminal"));
}
