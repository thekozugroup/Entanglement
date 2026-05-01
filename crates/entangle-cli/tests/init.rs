//! Integration tests for `entangle init`.
//!
//! Each test sets HOME to a fresh tempdir so the real ~/.entangle/ is never touched.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    cmd
}

fn entangle_dir(tmp: &TempDir) -> std::path::PathBuf {
    tmp.path().join(".entangle")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `--non-interactive` creates all four expected files.
#[test]
fn init_non_interactive_creates_all_files() {
    let tmp = TempDir::new().unwrap();

    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrote").or(predicate::str::contains("Already")));

    let dir = entangle_dir(&tmp);
    assert!(dir.join("identity.key").exists(), "identity.key missing");
    assert!(dir.join("config.toml").exists(), "config.toml missing");
    assert!(dir.join("keyring.toml").exists(), "keyring.toml missing");
    assert!(dir.join("peers.toml").exists(), "peers.toml missing");
}

/// Running `--non-interactive` a second time does not regenerate identity.key.
#[test]
fn init_idempotent_second_run_does_not_regenerate_identity() {
    let tmp = TempDir::new().unwrap();

    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let id1 = std::fs::read_to_string(entangle_dir(&tmp).join("identity.key")).unwrap();

    // Second run — must report already initialized or keep existing.
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let id2 = std::fs::read_to_string(entangle_dir(&tmp).join("identity.key")).unwrap();
    assert_eq!(id1, id2, "identity.key was regenerated on second init");
}

/// If config.toml already exists, a second `--non-interactive` run preserves it.
#[test]
fn init_with_no_overwrite_default_preserves_existing_config() {
    let tmp = TempDir::new().unwrap();

    // First run creates config.toml.
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let cfg_path = entangle_dir(&tmp).join("config.toml");
    let original_cfg = std::fs::read_to_string(&cfg_path).unwrap();

    // Manually modify config.toml to add a sentinel value.
    let sentinel = format!("{}\n# sentinel-marker\n", original_cfg.trim_end());
    std::fs::write(&cfg_path, &sentinel).unwrap();

    // Second init run — must NOT overwrite config.toml.
    entangle(&tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();

    let after = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(
        after.contains("sentinel-marker"),
        "config.toml was overwritten on second init (sentinel gone)"
    );
}
