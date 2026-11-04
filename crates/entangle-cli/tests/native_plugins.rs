//! CLI paths for native (tier 4–5) plugins: scaffold → build → trust → load,
//! catalog install, and the install-time tier ceiling (ATC-MAN-4's CLI side:
//! a refused plugin is never built, signed, trusted, or written).
//!
//! The build steps run a real `cargo build --release` of tiny dependency-free
//! crates in a temp directory. Linux-only, because loading engages the real
//! OS sandbox (covered for macOS by entangle-sandbox's Seatbelt smoke test).
#![cfg(target_os = "linux")]

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn entangle(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", home);
    cmd.env_remove("ENTANGLE_SDK_PATH");
    cmd.env_remove("ENTANGLE_CATALOG");
    // No daemon in tests: the socket under the temp HOME never exists.
    cmd
}

fn init(home: &Path) {
    entangle(home)
        .args(["init", "--non-interactive"])
        .assert()
        .success();
}

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .join("examples")
}

/// Copy `examples/native-echo` (sources only) into `dst/native-echo`.
fn copy_native_echo(dst: &Path) -> PathBuf {
    let src = examples_dir().join("native-echo");
    let out = dst.join("native-echo");
    std::fs::create_dir_all(out.join("src")).unwrap();
    for f in ["Cargo.toml", "entangle.toml", "src/main.rs"] {
        std::fs::copy(src.join(f), out.join(f)).unwrap();
    }
    out
}

fn tree(root: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p.clone());
                }
                v.push(p);
            }
        }
    }
    v.sort();
    v
}

#[test]
fn scaffold_build_trust_and_load_a_native_plugin() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    init(&home);
    let proj = tmp.path().join("my-native");

    entangle(&home)
        .args(["plugins", "new", "my-native", "--native", "--path"])
        .arg(&proj)
        .assert()
        .success()
        .stdout(predicate::str::contains("runtime:    native"));
    assert!(proj.join("src/main.rs").exists());

    let built = entangle(&home)
        .args(["plugins", "build"])
        .arg(&proj)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&built.get_output().stdout).into_owned();
    let dist = proj.join("dist");
    for f in ["plugin.bin", "plugin.bin.sig", "entangle.toml"] {
        assert!(dist.join(f).exists(), "{f} missing from dist/:\n{stdout}");
    }
    assert!(!dist.join("plugin.wasm").exists());
    let manifest = std::fs::read_to_string(dist.join("entangle.toml")).unwrap();
    assert!(manifest.contains("runtime = \"native\""), "{manifest}");
    assert!(!manifest.contains("PUBLISHER_PLACEHOLDER"));

    // The build prints the exact trust command; run it.
    let keyring_line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("entangle keyring add "))
        .expect("trust command printed");
    let pubkey = keyring_line.split_whitespace().nth(3).unwrap().to_owned();
    entangle(&home)
        .args(["keyring", "add", &pubkey, "--name", "self"])
        .assert()
        .success();

    entangle(&home)
        .args(["--allow-local", "plugins", "load"])
        .arg(&dist)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("loaded ").and(predicate::str::contains("/my-native@0.1.0")),
        );
}

#[test]
fn catalog_install_builds_and_loads_a_native_plugin() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    init(&home);
    let catalog = tmp.path().join("catalog");
    copy_native_echo(&catalog);

    entangle(&home)
        .args([
            "--allow-local",
            "plugins",
            "install",
            "native-echo",
            "--catalog",
        ])
        .arg(&catalog)
        .assert()
        .success()
        .stdout(predicate::str::contains("tier 5, native"))
        .stdout(predicate::str::contains("loaded "));
    assert!(home
        .join(".entangle/plugins/native-echo/plugin.bin")
        .exists());
}

/// ATC-MAN-4, CLI side: with `max_tier_allowed = 4` (the one line that
/// disables tier 5), installing a tier-5 plugin fails with ENTANGLE-E0043
/// before anything is built, signed, trusted, or written.
#[test]
fn install_refuses_above_the_ceiling_without_writing_anything() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    init(&home);
    std::fs::write(
        home.join(".entangle/config.toml"),
        "[security]\nmax_tier_allowed = 4\n",
    )
    .unwrap();
    let catalog = tmp.path().join("catalog");
    let proj = copy_native_echo(&catalog);
    let home_before = tree(&home);
    let catalog_before = tree(&catalog);

    entangle(&home)
        .args([
            "--allow-local",
            "plugins",
            "install",
            "native-echo",
            "--catalog",
        ])
        .arg(&catalog)
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0043"))
        .stderr(predicate::str::contains("max_tier_allowed=4"));

    assert_eq!(tree(&home), home_before, "nothing written under HOME");
    assert_eq!(
        tree(&catalog),
        catalog_before,
        "nothing built in the project"
    );
    assert!(!proj.join("target").exists() && !proj.join("dist").exists());
}
