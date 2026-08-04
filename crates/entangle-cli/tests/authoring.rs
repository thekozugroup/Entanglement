//! End-to-end tests for the plugin-authoring path:
//! `entangle plugins new` → `entangle plugins build` → loadable `dist/`.
//!
//! These exercise a directory that is **not** one of the two bundled examples,
//! which is the whole point of generalising the build away from
//! `cargo xtask hello-world build`.
//!
//! Compiling real wasm needs the `wasm32-wasip2` target plus a network fetch of
//! the SDK, so the cargo-invoking half is covered by an `#[ignore]`d test at the
//! bottom. Everything else runs on the packaging path via `--wasm`, which
//! packages a pre-built artifact instead of shelling out to cargo.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    // Keep `--sdk auto` deterministic: without this the scaffolder would walk
    // up from the test's cwd and find this very repository's SDK checkout.
    cmd.env_remove("ENTANGLE_SDK_PATH");
    cmd
}

/// `entangle init --non-interactive` so a publisher key exists.
fn init(tmp: &TempDir) {
    entangle(tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();
}

/// A minimal but structurally valid wasm module header — enough to be copied,
/// hashed and signed. Loading it into the kernel is a separate concern.
const FAKE_WASM: &[u8] = b"\0asm\x01\x00\x00\x00";

fn write_fake_wasm(dir: &Path) -> PathBuf {
    let p = dir.join("prebuilt.wasm");
    std::fs::write(&p, FAKE_WASM).unwrap();
    p
}

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

#[test]
fn plugins_new_generates_a_complete_project() {
    let tmp = TempDir::new().unwrap();
    let proj = tmp.path().join("acme-widget");

    entangle(&tmp)
        .args([
            "plugins",
            "new",
            "acme-widget",
            "--sdk",
            "crates-io",
            "--path",
        ])
        .arg(&proj)
        .assert()
        .success()
        .stdout(predicate::str::contains("Scaffolded plugin 'acme-widget'"));

    for f in [
        "Cargo.toml",
        "entangle.toml",
        "src/lib.rs",
        "README.md",
        ".gitignore",
    ] {
        assert!(proj.join(f).exists(), "{f} was not generated");
    }

    // The generated Cargo.toml must be a cdylib pinned to the wasm profile —
    // the two things an author would otherwise have to reverse-engineer.
    let cargo: toml::Value =
        toml::from_str(&std::fs::read_to_string(proj.join("Cargo.toml")).unwrap()).unwrap();
    assert_eq!(cargo["package"]["name"].as_str(), Some("acme-widget"));
    assert_eq!(
        cargo["lib"]["crate-type"].as_array().unwrap()[0].as_str(),
        Some("cdylib")
    );
    assert!(cargo["dependencies"].get("entangle-sdk").is_some());

    // The generated manifest must name wasm32-wasip2 so the author never has to
    // guess the target triple.
    let manifest = std::fs::read_to_string(proj.join("entangle.toml")).unwrap();
    assert!(manifest.contains("wasm32-wasip2"), "{manifest}");
    assert!(manifest.contains("runtime = \"wasm\""), "{manifest}");
}

#[test]
fn plugins_new_rejects_an_invalid_plugin_name() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["plugins", "new", "Acme_Widget", "--sdk", "crates-io"])
        .current_dir(tmp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid plugin name"));
}

#[test]
fn plugins_new_rejects_a_native_only_tier() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args([
            "plugins",
            "new",
            "acme-widget",
            "--tier",
            "5",
            "--sdk",
            "crates-io",
        ])
        .current_dir(tmp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("out of range"));
}

// ---------------------------------------------------------------------------
// Build + sign, on a directory that is not a bundled example
// ---------------------------------------------------------------------------

#[test]
fn scaffold_then_build_produces_a_signed_dist() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);

    let proj = tmp.path().join("acme-widget");
    entangle(&tmp)
        .args([
            "plugins",
            "new",
            "acme-widget",
            "--sdk",
            "crates-io",
            "--path",
        ])
        .arg(&proj)
        .assert()
        .success();

    let wasm = write_fake_wasm(&proj);
    entangle(&tmp)
        .args(["plugins", "build"])
        .arg(&proj)
        .arg("--wasm")
        .arg(&wasm)
        .assert()
        .success()
        .stdout(predicate::str::contains("publisher fingerprint:"));

    let dist = proj.join("dist");
    assert!(
        dist.join("plugin.wasm").exists(),
        "dist/plugin.wasm missing"
    );
    assert!(
        dist.join("entangle.toml").exists(),
        "dist/entangle.toml missing"
    );
    assert!(
        dist.join("plugin.wasm.sig").exists(),
        "dist/plugin.wasm.sig missing"
    );

    // The shipped manifest must validate and carry a fully-qualified id.
    let shipped = std::fs::read_to_string(dist.join("entangle.toml")).unwrap();
    assert!(
        !shipped.contains("PUBLISHER_PLACEHOLDER"),
        "publisher placeholder survived into dist:\n{shipped}"
    );
    let vm = entangle_manifest::load_manifest(&dist.join("entangle.toml"))
        .expect("dist manifest must validate");
    assert_eq!(vm.plugin_id.name, "acme-widget");
    assert_eq!(vm.plugin_id.version.to_string(), "0.1.0");
    assert_eq!(vm.plugin_id.publisher.len(), 32);

    // The rendered id string itself is fully qualified: a missing `@<version>`
    // is rejected by the kernel with ENTANGLE-E0201.
    let id = vm.plugin_id.to_string();
    assert!(
        id.contains('/') && id.contains('@'),
        "id not qualified: {id}"
    );
    assert!(shipped.contains(&id), "dist manifest id != validated id");

    // The signature covers the exact wasm + manifest bytes we shipped.
    let bundle: entangle_signing::SignatureBundle =
        toml::from_str(&std::fs::read_to_string(dist.join("plugin.wasm.sig")).unwrap()).unwrap();
    let pem = std::fs::read_to_string(tmp.path().join(".entangle/identity.key")).unwrap();
    let kp = entangle_signing::IdentityKeyPair::from_pem(&pem).unwrap();
    let mut keyring = entangle_signing::Keyring::new();
    keyring.add(entangle_signing::TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "self".into(),
        added_at: 0,
        note: String::new(),
    });
    entangle_signing::verify_artifact(
        &std::fs::read(dist.join("plugin.wasm")).unwrap(),
        &std::fs::read(dist.join("entangle.toml")).unwrap(),
        &bundle,
        &keyring,
    )
    .expect("dist signature must verify");

    // And the publisher segment is the key that actually signed.
    assert_eq!(vm.plugin_id.publisher, kp.fingerprint_hex());
}

/// A hand-written project (no scaffolding involved, arbitrary layout, id with no
/// `@version` at all) still builds into a correct, fully-qualified package.
#[test]
fn build_works_on_a_hand_written_project_and_forces_a_qualified_id() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);

    let proj = tmp.path().join("somewhere/else/handrolled");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("entangle.toml"),
        // Deliberately missing `@<version>` — this is the ENTANGLE-E0201 bug.
        r#"[plugin]
id = "PUBLISHER_PLACEHOLDER/handrolled"
version = "2.5.1"
tier = 3
runtime = "wasm"
description = "hand-written, not scaffolded"

[capabilities]
"net.wan" = {}
"#,
    )
    .unwrap();

    let wasm = write_fake_wasm(&proj);
    entangle(&tmp)
        .args(["plugins", "build"])
        .arg(&proj)
        .arg("--wasm")
        .arg(&wasm)
        .assert()
        .success();

    let vm = entangle_manifest::load_manifest(&proj.join("dist/entangle.toml")).unwrap();
    assert_eq!(vm.plugin_id.name, "handrolled");
    assert_eq!(vm.plugin_id.version.to_string(), "2.5.1");
    assert!(
        vm.plugin_id.to_string().ends_with("/handrolled@2.5.1"),
        "id was not qualified: {}",
        vm.plugin_id
    );
    // Author-declared tier/capabilities survive untouched.
    assert_eq!(vm.effective_tier as u8, 3);
}

/// Declaring a capability above the declared tier fails at build time with
/// ENTANGLE-E0042, before anything is signed.
#[test]
fn build_rejects_a_tier_below_its_capabilities() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);

    let proj = tmp.path().join("under-declared");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("entangle.toml"),
        r#"[plugin]
id = "PUBLISHER_PLACEHOLDER/under-declared@0.1.0"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "tier 1 but wants the network"

[capabilities]
"net.wan" = {}
"#,
    )
    .unwrap();
    let wasm = write_fake_wasm(&proj);

    entangle(&tmp)
        .args(["plugins", "build"])
        .arg(&proj)
        .arg("--wasm")
        .arg(&wasm)
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0042"));

    assert!(
        !proj.join("dist").exists(),
        "nothing may be written when validation fails"
    );
}

#[test]
fn build_without_an_identity_key_explains_how_to_get_one() {
    let tmp = TempDir::new().unwrap(); // no `entangle init`
    let proj = tmp.path().join("acme-widget");
    entangle(&tmp)
        .args([
            "plugins",
            "new",
            "acme-widget",
            "--sdk",
            "crates-io",
            "--path",
        ])
        .arg(&proj)
        .assert()
        .success();

    entangle(&tmp)
        .args(["plugins", "build"])
        .arg(&proj)
        .assert()
        .failure()
        .stderr(predicate::str::contains("entangle init"));
}

#[test]
fn build_without_a_manifest_points_at_the_scaffolder() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let proj = tmp.path().join("empty");
    std::fs::create_dir_all(&proj).unwrap();

    entangle(&tmp)
        .args(["plugins", "build"])
        .arg(&proj)
        .assert()
        .failure()
        .stderr(predicate::str::contains("entangle plugins new"));
}

// ---------------------------------------------------------------------------
// The real thing (opt-in)
// ---------------------------------------------------------------------------

/// The complete author journey with nothing faked: scaffold → cargo build →
/// sign → trust the publisher key → load into a kernel → invoke.
///
/// This is the test that proves the claim "the generated project builds and
/// loads without editing boilerplate" — nothing in `acme-widget` is touched
/// between `plugins new` and `plugins invoke`.
///
/// `#[ignore]` because it needs the `wasm32-wasip2` target installed *and* a
/// network-reachable registry to resolve `wit-bindgen`, either of which makes it
/// flaky in a sandboxed CI runner; it also takes tens of seconds rather than
/// milliseconds.
///
/// Run it deliberately with:
/// ```text
/// rustup target add wasm32-wasip2
/// cargo test -p entangle-cli --test authoring -- --ignored
/// ```
#[tokio::test]
#[ignore = "compiles real wasm: needs the wasm32-wasip2 target and a reachable registry"]
async fn scaffolded_project_compiles_loads_and_invokes() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let proj = tmp.path().join("acme-widget");

    // Point the scaffolder at this repository's SDK so the test does not depend
    // on the crate having been published to crates.io.
    let sdk = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("entangle-sdk");
    entangle(&tmp)
        .args(["plugins", "new", "acme-widget", "--path"])
        .arg(&proj)
        .arg("--sdk")
        .arg(format!("path:{}", sdk.display()))
        .assert()
        .success();

    entangle(&tmp)
        .args(["plugins", "build"])
        .arg(&proj)
        .assert()
        .success();

    let dist = proj.join("dist");
    let bytes = std::fs::read(dist.join("plugin.wasm")).unwrap();
    assert_eq!(&bytes[..4], b"\0asm", "not a wasm binary");

    // Trust our own publisher key, exactly as `entangle keyring add` would.
    let pem = std::fs::read_to_string(tmp.path().join(".entangle/identity.key")).unwrap();
    let kp = entangle_signing::IdentityKeyPair::from_pem(&pem).unwrap();
    let mut keyring = entangle_signing::Keyring::new();
    keyring.add(entangle_signing::TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "self".into(),
        added_at: 0,
        note: String::new(),
    });

    let kernel = entangle_runtime::Kernel::new(entangle_runtime::KernelConfig::default(), keyring)
        .expect("kernel");
    let id = kernel
        .load_plugin_from_dir(&dist)
        .await
        .expect("scaffolded plugin must load");
    assert_eq!(id.name, "acme-widget");
    assert_eq!(id.publisher, kp.fingerprint_hex());

    let out = kernel
        .invoke(&id, b"world", 30_000)
        .await
        .expect("scaffolded plugin must invoke");
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("Hello, world!"), "got: {text}");
}
