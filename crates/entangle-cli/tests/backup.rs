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
    // 11..23 is the Argon2 parameter block (m, t, p): flipped here too.
    for idx in [
        0,
        9,
        10,
        11,
        12,
        18,
        22,
        30,
        50,
        63,
        bytes.len() / 2,
        bytes.len() - 1,
    ] {
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

/// A hostile KDF parameter block is refused by the bounds check before any
/// key derivation runs (no 1 GiB+ allocation); an in-range change is caught by
/// the authenticated header instead.
#[test]
fn oversized_kdf_parameters_are_refused_before_the_kdf_runs() {
    let old = TempDir::new().unwrap();
    populate(old.path());
    let work = TempDir::new().unwrap();
    let pass = passfile(work.path(), "correct horse battery");
    let ar = work.path().join("node.bak");
    backup(old.path(), &ar, &pass, &[]).success();
    let bytes = std::fs::read(&ar).unwrap();

    // (offset of the big-endian u32, name): m_cost, t_cost, lanes.
    for (off, name) in [(11, "m_cost"), (15, "t_cost"), (19, "lanes")] {
        let mut bad = bytes.clone();
        bad[off..off + 4].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
        let p = work.path().join(format!("huge-{name}.bak"));
        std::fs::write(&p, bad).unwrap();
        let new = TempDir::new().unwrap();
        let started = std::time::Instant::now();
        restore(new.path(), &p, &pass, &[]).failure().stderr(
            predicate::str::contains("ENTANGLE-E0861")
                .and(predicate::str::contains("out of range")),
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{name}: the bound must trip before the KDF"
        );
        assert!(!new.path().join(".entangle").exists(), "{name}");
    }
    // In range but not what was sealed: the header is authenticated.
    let mut bad = bytes.clone();
    bad[18] = bad[18].wrapping_sub(1); // t_cost one lower
    let p = work.path().join("t-minus-one.bak");
    std::fs::write(&p, bad).unwrap();
    restore(TempDir::new().unwrap().path(), &p, &pass, &[])
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0862"));
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

/// `restore --force` that fails part-way (here the file-size limit stops the
/// keyring write after identity.key went through) must not leave the node
/// with the restored identity next to its old keyring and peer list, and
/// must say what state it left.
#[cfg(target_os = "linux")]
#[test]
fn a_restore_that_fails_part_way_changes_nothing() {
    let old = TempDir::new().unwrap();
    populate(old.path());
    // A keyring bigger than the file-size limit set below.
    let big = format!(
        "# publisher keys\n{}",
        "# padding padding padding padding\n".repeat(4096)
    );
    std::fs::write(old.path().join(".entangle/keyring.toml"), big).unwrap();
    let work = TempDir::new().unwrap();
    let pass = passfile(work.path(), "correct horse battery");
    let ar = work.path().join("node.bak");
    backup(old.path(), &ar, &pass, &[]).success();

    let new = TempDir::new().unwrap();
    populate(new.path());
    let dir = new.path().join(".entangle");
    let before: Vec<(&str, Vec<u8>)> = ["identity.key", "keyring.toml", "peers.toml"]
        .into_iter()
        .map(|f| (f, std::fs::read(dir.join(f)).unwrap()))
        .collect();
    // `ulimit -f 32` (16 or 32 KiB depending on the shell) lets the small
    // files through but not the keyring; with SIGXFSZ ignored the write
    // fails with EFBIG instead of killing the process.
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg("trap '' XFSZ; ulimit -f 32 && exec \"$@\"")
        .arg("sh")
        .arg(assert_cmd::cargo::cargo_bin("entangle"))
        .args(["restore", "--force", "--from"])
        .arg(&ar)
        .arg("--passphrase-file")
        .arg(&pass)
        .env("HOME", new.path())
        .env_remove("ENTANGLE_BACKUP_PASSPHRASE")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("ENTANGLE-E0867"), "{stderr}");
    assert!(stderr.contains("nothing was changed"), "{stderr}");
    for (f, bytes) in &before {
        assert_eq!(
            &std::fs::read(dir.join(f)).unwrap(),
            bytes,
            "{f} changed: {stderr}"
        );
    }
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-") || n.starts_with("restore-backup-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// Requirement 2 / spec §6.5: a restored node keeps its capability tokens
/// (the ones it presents, and the record of the ones it issued) **and** its
/// revocation set. Without the latter, every token revoked before the backup
/// would verify again on the restored node: same identity key, empty set.
#[test]
fn round_trip_keeps_capability_tokens_and_the_revocation_set() {
    use entangle_biscuits::templates::{
        mint_mesh_peer, now_unix_secs, present_for_request, Operation, RequestVerifier,
        RevocationList, TokenError,
    };
    use entangle_peers::{PeerStore, RevocationStore, TrustedPeer, REVOCATIONS_FILE};
    use entangle_types::peer_id::PeerId;

    #[derive(Debug)]
    struct FileRevocations(RevocationStore);
    impl RevocationList for FileRevocations {
        fn any_revoked(&self, ids: &[Vec<u8>]) -> Result<bool, String> {
            self.0.any_revoked(ids).map_err(|e| e.to_string())
        }
    }

    let old = TempDir::new().unwrap();
    let dir = old.path().join(".entangle");
    std::fs::create_dir_all(&dir).unwrap();
    let w = IdentityKeyPair::generate();
    std::fs::write(dir.join("identity.key"), w.to_pem()).unwrap();
    let w_id = PeerId::from_public_key_bytes(w.public().as_bytes());

    // Two paired peers: `kept` stays, `gone` is removed (its token revoked).
    let pair = |seed_name: &str| {
        let p = IdentityKeyPair::generate();
        let p_id = PeerId::from_public_key_bytes(p.public().as_bytes());
        let issued = mint_mesh_peer(&w, p_id, None).unwrap();
        let presented = mint_mesh_peer(&p, w_id, None).unwrap().bytes;
        let record =
            TrustedPeer::new_validated(p_id, hex::encode(p.public().as_bytes()), seed_name.into())
                .unwrap()
                .with_tokens(Some(&presented), &issued.revocation_ids);
        (p_id, issued, presented, record)
    };
    let (kept_id, kept_issued, kept_presented, kept) = pair("kept");
    let (gone_id, gone_issued, _, gone) = pair("gone");
    let store = PeerStore::open(dir.join("peers.toml")).unwrap();
    store.add(kept).unwrap();
    store.add(gone).unwrap();
    entangle(old.path())
        .args(["peers", "remove", &gone_id.to_hex()])
        .assert()
        .success();

    let work = TempDir::new().unwrap();
    let pass = passfile(work.path(), "correct horse battery");
    let ar = work.path().join("node.bak");
    backup(old.path(), &ar, &pass, &[])
        .success()
        .stdout(predicate::str::contains(REVOCATIONS_FILE));

    let new = TempDir::new().unwrap();
    restore(new.path(), &ar, &pass, &[]).success();
    let n = new.path().join(".entangle");
    assert_eq!(
        std::fs::read(dir.join(REVOCATIONS_FILE)).unwrap(),
        std::fs::read(n.join(REVOCATIONS_FILE)).expect("the revocation set is restored"),
    );
    assert_eq!(mode(&n.join(REVOCATIONS_FILE)), 0o600);

    // The tokens survive in the restored peer list.
    let restored = PeerStore::open(n.join("peers.toml")).unwrap();
    let record = restored.get(&kept_id).expect("kept peer restored");
    assert_eq!(record.capability_token_bytes(), Some(kept_presented));
    assert_eq!(record.issued_revocation_ids(), kept_issued.revocation_ids);

    // And the restored node, under its restored identity, still accepts the
    // live token and still refuses the revoked one — even after the removed
    // peer is put back on the allowlist by hand.
    let restored_identity =
        IdentityKeyPair::from_pem(&std::fs::read_to_string(n.join("identity.key")).unwrap())
            .unwrap();
    let verifier = RequestVerifier::new(restored_identity.public().as_bytes())
        .unwrap()
        .with_revocations(std::sync::Arc::new(FileRevocations(RevocationStore::at(
            n.join(REVOCATIONS_FILE),
        ))));
    let ask = |token: &[u8], holder: PeerId, nonce_binding: u8| {
        let now = now_unix_secs();
        let req =
            present_for_request(token, w.public().as_bytes(), [nonce_binding; 32], now).unwrap();
        verifier
            .verify(&req, holder, [nonce_binding; 32], Operation::Stream)
            .map(|_| ())
    };
    ask(&kept_issued.bytes, kept_id, 1).expect("a live token still verifies after restore");
    assert_eq!(
        ask(&gone_issued.bytes, gone_id, 2),
        Err(TokenError::Revoked),
        "a token revoked before the backup must stay revoked after the restore"
    );
}
