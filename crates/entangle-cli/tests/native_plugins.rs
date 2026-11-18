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
    for f in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "entangle.toml",
        "src/main.rs",
    ] {
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

/// Native plugins are packaged reproducibly: two builds of the same source
/// from different project and target directories give byte-identical
/// archives (same host, same toolchain), the archive carries `plugin.bin`
/// with its provenance and detached signature, `verify --rebuild` passes on
/// it, and it installs and loads through the ordinary archive path.
#[test]
fn native_plugin_archives_are_reproducible_and_installable() {
    use sha2::{Digest as _, Sha256};
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    init(&home);

    let mut archives = Vec::new();
    let mut projects = Vec::new();
    for n in ["first", "second/nested deeper"] {
        let root = tmp.path().join(n);
        let project = copy_native_echo(&root);
        let out = root.join("out");
        let built = entangle(&home)
            .env("CARGO_TARGET_DIR", root.join("target dir"))
            .env_remove("SOURCE_DATE_EPOCH")
            .args(["plugins", "build"])
            .arg(&project)
            .arg("--out")
            .arg(&out)
            .assert()
            .success();
        let stdout = String::from_utf8_lossy(&built.get_output().stdout).into_owned();
        let archive = out.join("native-echo-0.1.0.tar.zst");
        assert!(archive.is_file(), "no native archive:\n{stdout}");
        assert!(out.join("native-echo-0.1.0.tar.zst.sig").is_file());
        assert!(out.join("provenance.json").is_file());
        archives.push(archive);
        projects.push((project, stdout));
    }
    let bytes: Vec<Vec<u8>> = archives.iter().map(|a| std::fs::read(a).unwrap()).collect();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes[0])),
        hex::encode(Sha256::digest(&bytes[1])),
        "two native builds from different directories differ"
    );

    // What is in the archive.
    let files = entangle_oci::unpack(&bytes[0]).unwrap();
    assert!(files.native);
    assert_eq!(files.artifact_name(), "plugin.bin");
    assert!(files.wasm.starts_with(b"\x7fELF"), "not an ELF executable");
    let prov: serde_json::Value =
        serde_json::from_slice(files.provenance.as_ref().expect("provenance recorded")).unwrap();
    let host = prov["build"]["host"].as_str().expect("host recorded");
    assert!(host.contains("linux"), "{host}");
    assert!(prov["build"]["cargo_args"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a == "--locked"));
    let recorded = serde_json::to_string(&prov).unwrap();
    assert!(
        !recorded.contains(tmp.path().to_str().unwrap()),
        "a build path leaked into provenance: {recorded}"
    );

    // Trust the key, then: rebuild verification passes from the other copy.
    let pubkey = projects[0]
        .1
        .lines()
        .find(|l| l.trim_start().starts_with("entangle keyring add "))
        .and_then(|l| l.split_whitespace().nth(3))
        .expect("trust command printed")
        .to_owned();
    entangle(&home)
        .args(["keyring", "add", &pubkey, "--name", "self"])
        .assert()
        .success();
    entangle(&home)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("SOURCE_DATE_EPOCH")
        .args(["plugins", "verify", "--rebuild"])
        .arg(&archives[0])
        .arg("--source")
        .arg(&projects[1].0)
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"))
        .stdout(predicate::str::contains("plugin.bin blake3"));
    // ...and fails, naming the artifact, when the source no longer matches.
    let main_rs = projects[1].0.join("src/main.rs");
    let mut src = std::fs::read_to_string(&main_rs).unwrap();
    src.push_str("\n// edited after packaging\n");
    std::fs::write(&main_rs, src).unwrap();
    entangle(&home)
        .env_remove("CARGO_TARGET_DIR")
        .args(["plugins", "verify", "--rebuild"])
        .arg(&archives[0])
        .arg("--source")
        .arg(&projects[1].0)
        .assert()
        .failure()
        .stdout(predicate::str::contains("FAIL: source digest differs"));

    // The archive installs and loads like any other package.
    entangle(&home)
        .args(["--allow-local", "plugins", "install"])
        .arg(&archives[0])
        .assert()
        .success()
        .stdout(predicate::str::contains("effective tier 5"))
        .stdout(predicate::str::contains("loaded "));
    let installed = home.join(".entangle/plugins/native-echo");
    assert!(installed.join("plugin.bin").is_file());
    assert!(installed.join("plugin.bin.sig").is_file());
    assert!(!installed.join("plugin.wasm").exists());
}
