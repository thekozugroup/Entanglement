//! `entangle plugins install oci://…`, `publish`, `tags`, `mirror-sign`
//! against an in-process mock registry.
//!
//! The CLI runs as a child process (`assert_cmd`) with `$HOME` pointed at a
//! temp dir, talking to the mock over loopback HTTP. No network is used.

use assert_cmd::Command;
use entangle_oci::testing::{MockAuth, MockOptions, MockRegistry};
use entangle_oci::{
    pack, Descriptor, ImageManifest, MirrorKeyring, PackageFiles, ARTIFACT_TYPE_PLUGIN,
    LAYER_TYPE_PLUGIN, MEDIA_TYPE_EMPTY, MEDIA_TYPE_MANIFEST,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn entangle(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", home.path());
    for k in [
        "ENTANGLE_ALLOW_LOCAL",
        "ENTANGLE_OCI_TOKEN",
        "ENTANGLE_OCI_USERNAME",
        "ENTANGLE_OCI_PASSWORD",
    ] {
        cmd.env_remove(k);
    }
    cmd
}

fn kp(seed: u8) -> IdentityKeyPair {
    IdentityKeyPair::from_seed(&[seed; 32])
}

fn trust(home: &TempDir, keys: &[&IdentityKeyPair]) {
    let mut ring = Keyring::new();
    for k in keys {
        ring.add(TrustEntry {
            fingerprint: k.fingerprint(),
            public_key: *k.public().as_bytes(),
            publisher_name: "test".into(),
            added_at: 0,
            note: String::new(),
        });
    }
    ring.save(&home.path().join(".entangle/keyring.toml"))
        .unwrap();
}

fn files(k: &IdentityKeyPair, name: &str, tier: u8) -> PackageFiles {
    let manifest = format!(
        r#"[plugin]
id = "{}/{name}@0.1.0"
version = "0.1.0"
tier = {tier}
runtime = "wasm"
description = "test plugin"

[capabilities]

[build]
wit_world = "entangle:plugin@0.1.0/plugin"
target = "wasm32-wasip2"
"#,
        k.fingerprint_hex()
    );
    let wasm = b"\0asm\x01\x00\x00\x00 not really a component".to_vec();
    let bundle = sign_artifact(&wasm, manifest.as_bytes(), k);
    PackageFiles {
        manifest: manifest.into_bytes(),
        wasm,
        signature: toml::to_string(&bundle).unwrap().into_bytes(),
    }
}

fn seed(mock: &MockRegistry, repo: &str, tag: &str, f: &PackageFiles) {
    let pkg = pack(f).unwrap();
    let layer = mock.put_blob(&pkg);
    let empty = mock.put_blob(b"{}");
    let m = ImageManifest {
        schema_version: 2,
        media_type: MEDIA_TYPE_MANIFEST.into(),
        artifact_type: Some(ARTIFACT_TYPE_PLUGIN.into()),
        config: Descriptor {
            media_type: MEDIA_TYPE_EMPTY.into(),
            digest: empty.parse().unwrap(),
            size: 2,
            artifact_type: None,
            annotations: None,
        },
        layers: vec![Descriptor {
            media_type: LAYER_TYPE_PLUGIN.into(),
            digest: layer.parse().unwrap(),
            size: pkg.len() as u64,
            artifact_type: None,
            annotations: None,
        }],
        annotations: None,
    };
    mock.put_manifest(
        repo,
        tag,
        MEDIA_TYPE_MANIFEST,
        &serde_json::to_vec(&m).unwrap(),
    );
}

fn read_dir_files(dir: &Path) -> PackageFiles {
    PackageFiles::read_dir(dir).expect("package files on disk")
}

fn out_of(home: &TempDir) -> PathBuf {
    home.path().join("installed")
}

fn s(o: &std::process::Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_from_oci_verifies_and_writes_the_package() {
    let mock = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    let f = files(&publisher, "hello", 1);
    seed(&mock, "acme/hello", "1.0.0", &f);

    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(format!("oci://{}/acme/hello:1.0.0", mock.registry()))
        .arg("--no-load")
        .arg("--out")
        .arg(out_of(&home))
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "stdout:\n{so}\nstderr:\n{se}");
    assert!(
        so.contains(&format!("{}/hello@0.1.0", publisher.fingerprint_hex())),
        "{so}"
    );
    assert_eq!(read_dir_files(&out_of(&home)), f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_refuses_an_untrusted_publisher_and_writes_nothing() {
    let mock = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    trust(&home, &[&kp(1)]);
    seed(&mock, "acme/hello", "1", &files(&kp(2), "hello", 1));

    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(format!("oci://{}/acme/hello:1", mock.registry()))
        .arg("--no-load")
        .arg("--out")
        .arg(out_of(&home))
        .output()
        .unwrap();
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(
        se.contains("ENTANGLE-E0814") && se.contains("ENTANGLE-E0101"),
        "{se}"
    );
    assert!(
        !out_of(&home).exists(),
        "nothing may be written for an unverified package"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_honours_max_tier_allowed() {
    let mock = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    std::fs::write(
        home.path().join(".entangle/config.toml"),
        "[security]\nmax_tier_allowed = 1\n",
    )
    .unwrap();
    // Tier 2 plugin, correctly signed by a trusted publisher.
    seed(&mock, "acme/hello", "1", &files(&publisher, "hello", 2));

    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(format!("oci://{}/acme/hello:1", mock.registry()))
        .arg("--no-load")
        .arg("--out")
        .arg(out_of(&home))
        .output()
        .unwrap();
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(se.contains("ENTANGLE-E0043"), "{se}");
    assert!(!out_of(&home).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_without_no_load_goes_through_the_shared_load_path() {
    let mock = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    seed(&mock, "acme/hello", "1", &files(&publisher, "hello", 1));

    // The wasm is a stub, so the kernel (same Session::load_package as the
    // catalog install) must reject it; the point is that loading is attempted
    // on the verified on-disk package and the error says how to retry.
    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(format!("oci://{}/acme/hello:1", mock.registry()))
        .arg("--out")
        .arg(out_of(&home))
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(!out.status.success(), "stub wasm cannot load\n{so}\n{se}");
    assert!(se.contains("entangle plugins load"), "{se}");
    assert!(out_of(&home).join("plugin.wasm.sig").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_then_install_round_trips_through_the_cli() {
    let mock = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    let f = files(&publisher, "rt", 1);
    let dist = home.path().join("dist");
    f.write_dir(&dist).unwrap();

    let reference = format!("oci://{}/acme/rt:2.0", mock.registry());
    let out = entangle(&home)
        .args(["plugins", "publish"])
        .arg(&dist)
        .arg(&reference)
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(
        so.contains("published oci://") && so.contains("@sha256:"),
        "{so}"
    );

    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(&reference)
        .arg("--no-load")
        .arg("--out")
        .arg(out_of(&home))
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert_eq!(
        read_dir_files(&out_of(&home)),
        f,
        "bytes survive publish -> install"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_come_from_the_environment_and_are_never_printed() {
    let mock = MockRegistry::start(MockOptions {
        auth: MockAuth::Basic {
            username: "alice".into(),
            password: "hunter2-very-secret".into(),
        },
        ..MockOptions::default()
    })
    .await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    seed(&mock, "acme/hello", "1", &files(&publisher, "hello", 1));
    let reference = format!("oci://{}/acme/hello:1", mock.registry());

    // No credentials: clear error naming the variables.
    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(&reference)
        .arg("--no-load")
        .arg("--out")
        .arg(out_of(&home))
        .output()
        .unwrap();
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(
        se.contains("ENTANGLE-E0804") && se.contains("ENTANGLE_OCI_USERNAME"),
        "{se}"
    );

    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(&reference)
        .arg("--no-load")
        .arg("--out")
        .arg(out_of(&home))
        .env("RUST_LOG", "trace")
        .env("ENTANGLE_OCI_USERNAME", "alice")
        .env("ENTANGLE_OCI_PASSWORD", "hunter2-very-secret")
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    for text in [&so, &se] {
        assert!(
            !text.contains("hunter2-very-secret"),
            "password leaked: {text}"
        );
        assert!(
            !text.contains("aHVudGVy"),
            "base64 of credentials leaked: {text}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tags_reports_listing_status_and_mirror_sign_publishes_one() {
    let mock = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    let mirror = kp(77);
    trust(&home, &[&publisher]);
    seed(&mock, "acme/hello", "1.0.0", &files(&publisher, "hello", 1));
    seed(&mock, "acme/hello", "1.1.0", &files(&publisher, "hello", 1));
    let repo = format!("oci://{}/acme/hello", mock.registry());

    // No listing yet.
    let out = entangle(&home)
        .args(["plugins", "tags", &repo])
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(so.contains("listing:    unsigned"), "{so}");
    assert!(so.contains("1.0.0") && so.contains("not covered"), "{so}");
    let out = entangle(&home)
        .args(["plugins", "tags", &repo, "--require-verified"])
        .output()
        .unwrap();
    assert!(!out.status.success());

    // A publisher key must not be used to sign listings.
    let pub_key = home.path().join("publisher.pem");
    std::fs::write(&pub_key, publisher.to_pem()).unwrap();
    let out = entangle(&home)
        .args(["plugins", "mirror-sign", &repo, "--key"])
        .arg(&pub_key)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(s(&out).1.contains("dedicated mirror key"), "{}", s(&out).1);

    // Mirror operator signs a listing.
    let mkey = home.path().join("mirror.pem");
    std::fs::write(&mkey, mirror.to_pem()).unwrap();
    let out = entangle(&home)
        .args(["plugins", "mirror-sign", &repo, "--key"])
        .arg(&mkey)
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");

    // Client without the mirror key: the listing is present but INVALID.
    let out = entangle(&home)
        .args(["plugins", "tags", &repo])
        .output()
        .unwrap();
    let so = s(&out).0;
    assert!(
        so.contains("INVALID") && so.contains("not in the mirror keyring"),
        "{so}"
    );

    // With the mirror key configured: verified, with digests.
    let mut keys = MirrorKeyring::new();
    keys.add_public_key(&mirror.public(), "test-mirror");
    keys.save(&home.path().join(".entangle/mirror-keys.toml"))
        .unwrap();
    let out = entangle(&home)
        .args(["plugins", "tags", &repo, "--require-verified"])
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(
        so.contains(&format!(
            "verified (mirror key {})",
            mirror.fingerprint_hex()
        )),
        "{so}"
    );
    assert!(so.contains("sha256:"), "{so}");

    let out = entangle(&home)
        .args(["plugins", "tags", &repo, "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verification"]["status"], "verified");
    assert_eq!(v["tags"].as_array().unwrap().len(), 2);
}
