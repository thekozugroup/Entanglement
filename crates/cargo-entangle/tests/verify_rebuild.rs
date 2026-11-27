use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as Process;

use assert_cmd::Command;
use entangle_signing::{IdentityKeyPair, Keyring, TrustEntry};
use predicates::prelude::*;
use sha2::{Digest, Sha256};

const SOURCE_URL: &str = "https://example.invalid/entanglement/hello-world";

fn cargo_entangle(cwd: &Path) -> Command {
    let binary = Path::new(env!("CARGO_BIN_EXE_cargo-entangle"));
    let path = env::var_os("PATH").unwrap_or_default();
    let path = env::join_paths(
        std::iter::once(binary.parent().unwrap().to_owned()).chain(env::split_paths(&path)),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO"));
    command.current_dir(cwd).env("PATH", path).arg("entangle");
    command
}

fn git(dir: &Path, args: &[&str]) {
    let result = Process::new("git")
        .current_dir(dir)
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn clone_repository(source: &Path, target: &Path) {
    git(
        source,
        &[
            "clone",
            "--no-hardlinks",
            "--",
            source.to_str().unwrap(),
            target.to_str().unwrap(),
        ],
    );
}

fn package(repository: &Path, key: &Path, out: &Path) {
    cargo_entangle(out.parent().unwrap())
        .arg("package")
        .arg(repository.join("examples/hello-world"))
        .args(["--source-url", SOURCE_URL])
        .arg("--key")
        .arg(key)
        .arg("--out")
        .arg(out)
        .assert()
        .success()
        .stdout(predicate::str::contains("SHA-256"));
}

fn verify(archive: &Path, repository: &Path, keyring: &Path) -> Command {
    let mut command = cargo_entangle(archive.parent().unwrap());
    command
        .args(["verify", "--rebuild"])
        .arg(archive)
        .arg("--source")
        .arg(repository)
        .arg("--keyring")
        .arg(keyring);
    command
}

#[test]
#[ignore = "builds the pinned hello-world component from independent Git checkouts"]
fn happy_path() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let test = tempfile::tempdir().unwrap();
    let first = test.path().join("signed source with spaces");
    let second = test.path().join("another checkout");
    clone_repository(&workspace, &first);
    let toolchain = "examples/hello-world/rust-toolchain.toml";
    fs::copy(workspace.join(toolchain), first.join(toolchain)).unwrap();
    git(&first, &["add", "--", toolchain]);
    git(
        &first,
        &["commit", "--allow-empty", "-m", "Package fixture"],
    );
    clone_repository(&first, &second);

    let key = test.path().join("fixture publisher.pem");
    let keyring = test.path().join("trusted keys.toml");
    let publisher = IdentityKeyPair::from_seed(&[41; 32]);
    fs::write(&key, publisher.to_pem()).unwrap();
    let mut trust = Keyring::new();
    trust.add(TrustEntry {
        fingerprint: publisher.fingerprint(),
        public_key: *publisher.public().as_bytes(),
        publisher_name: "package test fixture".into(),
        added_at: 0,
        note: String::new(),
    });
    trust.save(&keyring).unwrap();

    let archive = test.path().join("first package.tar.zst");
    let again = test.path().join("second package.tar.zst");
    package(&first, &key, &archive);
    package(&first, &key, &again);
    let original = fs::read(&archive).unwrap();
    let repeated = fs::read(&again).unwrap();
    assert_eq!(Sha256::digest(&original), Sha256::digest(&repeated));

    cargo_entangle(test.path())
        .arg("sign")
        .arg(&archive)
        .arg("--key")
        .arg(&key)
        .assert()
        .success();
    assert_eq!(
        fs::read(test.path().join("first package.tar.zst.sig"))
            .unwrap()
            .len(),
        64
    );
    verify(&archive, &second, &keyring)
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));

    let mut modified = original;
    modified[0] ^= 1;
    fs::write(&archive, modified).unwrap();
    verify(&archive, &test.path().join("nonexistent source"), &keyring)
        .assert()
        .failure()
        .stderr(predicate::str::contains("authenticating the package"));
}
