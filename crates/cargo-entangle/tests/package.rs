use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn no_lockfile_rejected() {
    let repository = tempfile::tempdir().unwrap();
    fs::write(
        repository.path().join("Cargo.toml"),
        "[workspace]\n[package]\nname = 'repro-fixture'\nversion = '0.1.0'\nedition = '2021'\n[lib]\npath = 'lib.rs'\n",
    )
    .unwrap();
    fs::write(repository.path().join("lib.rs"), "").unwrap();

    Command::new(env!("CARGO_BIN_EXE_cargo-entangle"))
        .arg("entangle")
        .arg("package")
        .arg(repository.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Cargo.lock missing"));
}
