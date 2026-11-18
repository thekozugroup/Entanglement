//! Plugin distribution through the CLI: plain-HTTPS installs with a detached
//! signature, `entangle pack` / `.entanglepack`, the mirror setting and its
//! fallback order, and listing rollback protection.
//!
//! The CLI runs as a child process with `$HOME` in a temp dir. Servers are
//! in-process (`entangle_oci::testing::MockRegistry`); the HTTPS ones present
//! a certificate from a CA generated for the test, which the child trusts
//! through `SSL_CERT_FILE` — the standard trust-store override the client's
//! TLS stack (`rustls-native-certs`) honours. That names an extra CA; it does
//! not turn certificate or host-name verification off, and the tests below
//! show the handshake failing without it. No network is used.

use assert_cmd::Command;
use entangle_oci::testing::{MockOptions, MockRegistry, TestCa};
use entangle_oci::{
    pack, publish_listing, read_pack, sign_archive, Descriptor, ImageManifest, MirrorKeyring,
    MirrorListing, OciClient, PackageFiles, Reference, ARTIFACT_TYPE_PLUGIN, LAYER_TYPE_PLUGIN,
    MEDIA_TYPE_EMPTY, MEDIA_TYPE_MANIFEST,
};
use entangle_signing::{sign_artifact_at, IdentityKeyPair, Keyring, TrustEntry};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn entangle(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", home.path());
    for k in [
        "ENTANGLE_ALLOW_LOCAL",
        "ENTANGLE_OCI_TOKEN",
        "ENTANGLE_OCI_USERNAME",
        "ENTANGLE_OCI_PASSWORD",
        "ENTANGLE_OCI_REGISTRY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        cmd.env_remove(k);
    }
    cmd
}

/// The CLI with the test CA as its trust store.
fn entangle_trusting(home: &TempDir, ca_pem: &Path) -> Command {
    let mut cmd = entangle(home);
    cmd.env("SSL_CERT_FILE", ca_pem);
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

fn keyring_of(home: &TempDir) -> Keyring {
    Keyring::load(&home.path().join(".entangle/keyring.toml")).unwrap()
}

fn files(k: &IdentityKeyPair, name: &str, tier: u8, version: &str) -> PackageFiles {
    let wasm = format!("\0asm\x01\x00\x00\x00 fake component for {name} {version}").into_bytes();
    let manifest = format!(
        r#"[plugin]
id = "{}/{name}@{version}"
version = "{version}"
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
    let bundle = sign_artifact_at(&wasm, manifest.as_bytes(), k, 1_704_067_200);
    PackageFiles {
        manifest: manifest.into_bytes(),
        wasm,
        signature: toml::to_string(&bundle).unwrap().into_bytes(),
        provenance: None,
        native: false,
    }
}

fn archive(k: &IdentityKeyPair, name: &str, tier: u8) -> Vec<u8> {
    pack(&files(k, name, tier, "0.1.0")).unwrap()
}

fn s(o: &std::process::Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// Everything under `~/.entangle/plugins` and the explicit `--out` dir: used
/// to assert that a refused install wrote nothing.
fn nothing_installed(home: &TempDir) {
    let plugins = home.path().join(".entangle/plugins");
    let listed: Vec<_> = std::fs::read_dir(&plugins)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    assert!(listed.is_empty(), "written under plugins/: {listed:?}");
    assert!(
        !home.path().join("installed").exists(),
        "the --out directory was created"
    );
    // No staging leftovers next to the --out directory either.
    let stray: Vec<_> = std::fs::read_dir(home.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("staging") || n.contains(".old-"))
        .collect();
    assert!(stray.is_empty(), "{stray:?}");
}

struct Https {
    mock: MockRegistry,
    ca_pem: PathBuf,
    _dir: TempDir,
}

/// An in-process HTTPS server with a certificate from a fresh test CA.
async fn https_server() -> Https {
    let ca = TestCa::generate();
    let dir = TempDir::new().unwrap();
    let ca_pem = dir.path().join("test-ca.pem");
    std::fs::write(&ca_pem, ca.root_pem()).unwrap();
    let mock = MockRegistry::start(MockOptions {
        tls: Some(ca),
        ..MockOptions::default()
    })
    .await;
    Https {
        mock,
        ca_pem,
        _dir: dir,
    }
}

/// The plugin id of the package in `archive`.
fn id_in(archive: &[u8]) -> String {
    let f = entangle_oci::unpack(archive).unwrap();
    let m: toml::Value = toml::from_str(std::str::from_utf8(&f.manifest).unwrap()).unwrap();
    m["plugin"]["id"].as_str().unwrap().to_owned()
}

/// The detached signature by `signer` over `archive`, vouching for the id of
/// the package inside.
fn detached(archive: &[u8], signer: &IdentityKeyPair) -> Vec<u8> {
    sign_archive(archive, &id_in(archive), signer).unwrap()
}

/// Publish `archive` and its detached signature by `signer` at `path`.
fn serve(mock: &MockRegistry, path: &str, archive: &[u8], signer: &IdentityKeyPair) {
    mock.put_file(path, archive);
    mock.put_file(&format!("{path}.sig"), &detached(archive, signer));
}

fn install_url(home: &TempDir, ca: &Path, url: &str) -> std::process::Output {
    entangle_trusting(home, ca)
        .args(["plugins", "install", url, "--no-load", "--out"])
        .arg(home.path().join("installed"))
        .output()
        .unwrap()
}

// ---------------------------------------------------------------------------
// 1. Plain HTTPS tarball + detached signature
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_install_over_tls_checks_the_detached_signature_then_installs() {
    let srv = https_server().await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    let pkg = archive(&publisher, "hello", 1);
    serve(
        &srv.mock,
        "/releases/v0.1/hello-0.1.0.tar.zst",
        &pkg,
        &publisher,
    );

    let url = format!("{}/releases/v0.1/hello-0.1.0.tar.zst", srv.mock.origin());
    assert!(url.starts_with("https://localhost:"), "{url}");
    let out = install_url(&home, &srv.ca_pem, &url);
    let (so, se) = s(&out);
    assert!(out.status.success(), "stdout:\n{so}\nstderr:\n{se}");
    assert!(
        so.contains(&format!("{}/hello@0.1.0", publisher.fingerprint_hex())),
        "{so}"
    );
    assert!(so.contains("the archive is not opened yet"), "{so}");

    // The signature was fetched first, then the archive; no credentials.
    let paths: Vec<String> = srv.mock.requests().iter().map(|r| r.path.clone()).collect();
    assert_eq!(
        paths,
        [
            "/releases/v0.1/hello-0.1.0.tar.zst.sig",
            "/releases/v0.1/hello-0.1.0.tar.zst"
        ]
    );
    assert!(srv
        .mock
        .requests()
        .iter()
        .all(|r| r.authorization.is_none()));

    // What is on disk is exactly the signed package.
    let on_disk = PackageFiles::read_dir(&home.path().join("installed")).unwrap();
    assert_eq!(on_disk, files(&publisher, "hello", 1, "0.1.0"));
}

/// `entangle install <url>` is the same path; with no argument `install`
/// keeps its first-run behaviour (covered by `tests/install.rs`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entangle_install_with_a_source_delegates_to_plugins_install() {
    let srv = https_server().await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    serve(
        &srv.mock,
        "/hello-0.1.0.tar.zst",
        &archive(&publisher, "hello", 1),
        &publisher,
    );
    let out = entangle_trusting(&home, &srv.ca_pem)
        .args([
            "install",
            &format!("{}/hello-0.1.0.tar.zst", srv.mock.origin()),
        ])
        .arg("--no-load")
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    // Default location, keyed on the plugin name.
    assert!(home
        .path()
        .join(".entangle/plugins/hello/plugin.wasm")
        .is_file());
    // The first-run flags do not mix with a source.
    let out = entangle(&home)
        .args(["install", "https://example.org/x.tar.zst", "--headless"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(s(&out).1.contains("cannot be used with"), "{}", s(&out).1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_install_needs_a_trusted_certificate_for_the_name_dialled() {
    let srv = https_server().await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    serve(
        &srv.mock,
        "/hello-0.1.0.tar.zst",
        &archive(&publisher, "hello", 1),
        &publisher,
    );
    let url = format!("{}/hello-0.1.0.tar.zst", srv.mock.origin());

    // Without the test CA: the production trust store does not know it.
    let out = entangle(&home)
        .args(["plugins", "install", &url, "--no-load", "--out"])
        .arg(home.path().join("installed"))
        .output()
        .unwrap();
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(se.contains("ENTANGLE-E0802") && se.contains("TLS"), "{se}");
    assert!(
        srv.mock.requests().is_empty(),
        "no request before the handshake"
    );
    nothing_installed(&home);

    // With the CA, but dialling the address the certificate is not for.
    let by_ip = url.replace("localhost", "127.0.0.1");
    let out = install_url(&home, &srv.ca_pem, &by_ip);
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(se.contains("ENTANGLE-E0802") && se.contains("TLS"), "{se}");
    assert!(srv.mock.requests().is_empty());
    nothing_installed(&home);
}

/// Every refusal leaves the disk untouched: no package directory, no staging
/// directory, no keyring change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_install_refusals_write_nothing() {
    let srv = https_server().await;
    let plain = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let (publisher, other, stranger) = (kp(1), kp(2), kp(3));
    trust(&home, &[&publisher, &other]);
    let keyring_before = std::fs::read(home.path().join(".entangle/keyring.toml")).unwrap();
    let pkg = archive(&publisher, "hello", 1);
    let origin = srv.mock.origin();
    let run = |path: &str| install_url(&home, &srv.ca_pem, &format!("{origin}{path}"));
    let refused = |out: &std::process::Output, needles: &[&str]| {
        let (so, se) = s(out);
        assert!(
            !out.status.success(),
            "should have been refused:\n{so}\n{se}"
        );
        for n in needles {
            assert!(se.contains(n), "expected {n:?} in:\n{se}");
        }
        nothing_installed(&home);
    };

    // No detached signature published.
    srv.mock.put_file("/nosig.tar.zst", &pkg);
    let before = srv.mock.requests().len();
    refused(
        &run("/nosig.tar.zst"),
        &["ENTANGLE-E0823", "nosig.tar.zst.sig"],
    );
    // ...and the archive itself was not even requested.
    assert_eq!(srv.mock.requests().len(), before + 1);

    // Signed, inside and out, by a publisher that is not in the keyring.
    serve(
        &srv.mock,
        "/stranger.tar.zst",
        &archive(&stranger, "hello", 1),
        &stranger,
    );
    refused(
        &run("/stranger.tar.zst"),
        &[
            "ENTANGLE-E0101",
            &stranger.fingerprint_hex(),
            "entangle keyring add",
        ],
    );

    // The archive was swapped after signing (the .sig is the genuine one).
    serve(&srv.mock, "/swapped.tar.zst", &pkg, &publisher);
    srv.mock
        .put_file("/swapped.tar.zst", &archive(&publisher, "evil", 1));
    refused(&run("/swapped.tar.zst"), &["ENTANGLE-E0823", "sha256"]);

    // A flipped byte in the archive.
    let mut corrupt = pkg.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0x55;
    srv.mock.put_file("/corrupt.tar.zst", &corrupt);
    srv.mock
        .put_file("/corrupt.tar.zst.sig", &detached(&pkg, &publisher));
    refused(&run("/corrupt.tar.zst"), &["ENTANGLE-E0823"]);

    // Detached signature by one trusted publisher over another's package.
    serve(&srv.mock, "/mixed.tar.zst", &pkg, &other);
    refused(
        &run("/mixed.tar.zst"),
        &["ENTANGLE-E0823", "must be the same publisher"],
    );

    // A signature document that is not one.
    srv.mock.put_file("/junk.tar.zst", &pkg);
    srv.mock
        .put_file("/junk.tar.zst.sig", b"-----BEGIN PGP SIGNATURE-----");
    refused(&run("/junk.tar.zst"), &["ENTANGLE-E0823"]);

    // An oversized "signature" is cut off at its cap.
    srv.mock.put_file("/bigsig.tar.zst", &pkg);
    srv.mock
        .serve_endless_file("/bigsig.tar.zst.sig", 8 * 1024 * 1024);
    refused(&run("/bigsig.tar.zst"), &["ENTANGLE-E0808"]);
    // An archive announcing more than the cap is refused from its header.
    serve(&srv.mock, "/huge.tar.zst", &pkg, &publisher);
    srv.mock
        .claim_file_length("/huge.tar.zst", 600 * 1024 * 1024);
    refused(&run("/huge.tar.zst"), &["ENTANGLE-E0808"]);

    // A redirect from HTTPS down to HTTP is not followed.
    plain.put_file("/hello.tar.zst", &pkg);
    plain.put_file("/hello.tar.zst.sig", &detached(&pkg, &publisher));
    srv.mock.redirect_file(
        "/moved.tar.zst.sig",
        &format!("{}/hello.tar.zst.sig", plain.origin()),
    );
    refused(
        &run("/moved.tar.zst"),
        &["ENTANGLE-E0810", "may not change the scheme"],
    );
    assert!(plain.requests().is_empty(), "cleartext server contacted");

    // Plain http to a host that is not loopback, and other schemes.
    for (url, needle) in [
        ("http://203.0.113.9/hello.tar.zst", "loopback"),
        ("https://user:pw@example.org/hello.tar.zst", "credentials"),
    ] {
        let out = install_url(&home, &srv.ca_pem, url);
        refused(&out, &["ENTANGLE-E0822", needle]);
        assert!(!s(&out).1.contains("pw@"), "{}", s(&out).1);
    }

    // Policy: tier above the ceiling, and a disabled plugin.
    std::fs::write(
        home.path().join(".entangle/config.toml"),
        format!(
            "[security]\nmax_tier_allowed = 2\n\n[plugins]\ndisabled = [\"{}/blocked@0.1.0\"]\n",
            publisher.fingerprint_hex()
        ),
    )
    .unwrap();
    serve(
        &srv.mock,
        "/tier3-0.1.0.tar.zst",
        &archive(&publisher, "tier3", 3),
        &publisher,
    );
    refused(&run("/tier3-0.1.0.tar.zst"), &["ENTANGLE-E0043"]);
    serve(
        &srv.mock,
        "/blocked-0.1.0.tar.zst",
        &archive(&publisher, "blocked", 1),
        &publisher,
    );
    refused(&run("/blocked-0.1.0.tar.zst"), &["ENTANGLE-E0759"]);

    // A native executable shipped under a wasm manifest.
    let mut elf = files(&publisher, "elf", 1, "0.1.0");
    elf.wasm = b"\x7fELF\x02\x01\x01\x00 not wasm".to_vec();
    let bundle = sign_artifact_at(&elf.wasm, &elf.manifest, &publisher, 1);
    elf.signature = toml::to_string(&bundle).unwrap().into_bytes();
    serve(
        &srv.mock,
        "/elf-0.1.0.tar.zst",
        &pack(&elf).unwrap(),
        &publisher,
    );
    refused(&run("/elf-0.1.0.tar.zst"), &["ENTANGLE-E0507"]);

    // Catalog-only and registry-only flags are refused for a URL.
    let out = entangle(&home)
        .args(["plugins", "install", "https://example.org/x.tar.zst"])
        .args(["--catalog", "/nowhere"])
        .output()
        .unwrap();
    assert!(!out.status.success() && s(&out).1.contains("--catalog"));
    let out = entangle(&home)
        .args(["plugins", "install", "https://example.org/x.tar.zst"])
        .arg("--insecure-registry")
        .output()
        .unwrap();
    assert!(!out.status.success() && s(&out).1.contains("--insecure-registry"));

    assert_eq!(
        std::fs::read(home.path().join(".entangle/keyring.toml")).unwrap(),
        keyring_before,
        "a refused install must not touch the keyring"
    );

    // After all that, the good package at the same server still installs
    // (with the ceiling lifted): the refusals were about those inputs.
    std::fs::remove_file(home.path().join(".entangle/config.toml")).unwrap();
    serve(&srv.mock, "/good/hello-0.1.0.tar.zst", &pkg, &publisher);
    let out = run("/good/hello-0.1.0.tar.zst");
    assert!(out.status.success(), "{}", s(&out).1);
}

/// A web host cannot answer one URL with another plugin, another version, or
/// a package whose detached signature vouches for a different id: the signed
/// id must match the URL's `<name>-<version>.tar.zst` (or `--expect`), and the
/// package inside must be that id. Checked before the archive is opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_install_binds_the_url_to_the_signed_name_and_version() {
    let srv = https_server().await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    let fp = publisher.fingerprint_hex();
    let hello = archive(&publisher, "hello", 1);
    let origin = srv.mock.origin();
    let refused = |out: &std::process::Output, needles: &[&str]| {
        let (so, se) = s(out);
        assert!(!out.status.success(), "installed:\n{so}\n{se}");
        for n in needles {
            assert!(se.contains(n), "expected {n:?} in:\n{se}");
        }
        assert!(
            !so.contains("verifying the package"),
            "archive opened:\n{so}"
        );
        nothing_installed(&home);
    };

    // Another plugin under this URL's name.
    serve(&srv.mock, "/dl/other-0.1.0.tar.zst", &hello, &publisher);
    refused(
        &install_url(
            &home,
            &srv.ca_pem,
            &format!("{origin}/dl/other-0.1.0.tar.zst"),
        ),
        &["ENTANGLE-E0945", "hello-0.1.0.tar.zst", "--expect"],
    );
    // An older release under a newer version's URL.
    serve(&srv.mock, "/dl/hello-0.2.0.tar.zst", &hello, &publisher);
    refused(
        &install_url(
            &home,
            &srv.ca_pem,
            &format!("{origin}/dl/hello-0.2.0.tar.zst"),
        ),
        &["ENTANGLE-E0945"],
    );
    // A free-form URL needs --expect, and --expect must match.
    serve(&srv.mock, "/dl/latest.tar.zst", &hello, &publisher);
    let latest = format!("{origin}/dl/latest.tar.zst");
    refused(
        &install_url(&home, &srv.ca_pem, &latest),
        &["ENTANGLE-E0945"],
    );
    let with_expect = |want: &str| {
        entangle_trusting(&home, &srv.ca_pem)
            .args(["plugins", "install", &latest, "--no-load", "--expect", want])
            .arg("--out")
            .arg(home.path().join("installed"))
            .output()
            .unwrap()
    };
    refused(
        &with_expect(&format!("{fp}/hello@0.2.0")),
        &["ENTANGLE-E0945", "--expect"],
    );
    refused(
        &with_expect(&format!("{}/hello@0.1.0", kp(9).fingerprint_hex())),
        &["ENTANGLE-E0945"],
    );
    // --expect is for URLs only.
    let out = entangle(&home)
        .args(["plugins", "install", "./x.tar.zst", "--expect"])
        .arg(format!("{fp}/x@0.1.0"))
        .output()
        .unwrap();
    assert!(!out.status.success() && s(&out).1.contains("--expect"));

    // A detached signature vouching for another id than the package inside.
    srv.mock.put_file("/dl/hello-0.3.0.tar.zst", &hello);
    srv.mock.put_file(
        "/dl/hello-0.3.0.tar.zst.sig",
        &sign_archive(&hello, &format!("{fp}/hello@0.3.0"), &publisher).unwrap(),
    );
    let out = install_url(
        &home,
        &srv.ca_pem,
        &format!("{origin}/dl/hello-0.3.0.tar.zst"),
    );
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(
        se.contains("ENTANGLE-E0823") && se.contains("vouches for"),
        "{se}"
    );
    nothing_installed(&home);

    // The right --expect installs the free-form URL.
    let out = with_expect(&format!("{fp}/hello@0.1.0"));
    assert!(out.status.success(), "{}", s(&out).1);
}

/// A lower version over an installed plugin of the same publisher is refused
/// on every path (URL, local archive, pack; OCI is covered with the mirror
/// tests) unless --allow-downgrade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_downgrade_is_refused_on_every_path_unless_allowed() {
    let srv = https_server().await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    trust(&home, &[&publisher]);
    let v2 = pack(&files(&publisher, "hello", 1, "0.2.0")).unwrap();
    let v1 = pack(&files(&publisher, "hello", 1, "0.1.0")).unwrap();
    let local = |bytes: &[u8], name: &str| {
        let p = home.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    };
    let installed = || {
        String::from_utf8(
            std::fs::read(home.path().join(".entangle/plugins/hello/entangle.toml")).unwrap(),
        )
        .unwrap()
    };
    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(local(&v2, "hello-0.2.0.tar.zst"))
        .arg("--no-load")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", s(&out).1);
    assert!(installed().contains("0.2.0"));
    let refused = |out: std::process::Output| {
        let (so, se) = s(&out);
        assert!(!out.status.success(), "downgraded:\n{so}\n{se}");
        assert!(
            se.contains("ENTANGLE-E0946") && se.contains("--allow-downgrade"),
            "{se}"
        );
        assert!(installed().contains("0.2.0"));
    };

    // Local archive.
    let old = local(&v1, "hello-0.1.0.tar.zst");
    refused(
        entangle(&home)
            .args(["plugins", "install"])
            .arg(&old)
            .arg("--no-load")
            .output()
            .unwrap(),
    );
    // URL, to the default directory and to an --out elsewhere (the default
    // directory still holds the newer version).
    serve(&srv.mock, "/hello-0.1.0.tar.zst", &v1, &publisher);
    let url = format!("{}/hello-0.1.0.tar.zst", srv.mock.origin());
    refused(
        entangle_trusting(&home, &srv.ca_pem)
            .args(["plugins", "install", &url, "--no-load"])
            .output()
            .unwrap(),
    );
    refused(install_url(&home, &srv.ca_pem, &url));
    // Pack.
    let pack_file = home.path().join("old.entanglepack");
    let out = entangle(&home)
        .args(["pack"])
        .arg(&old)
        .arg("--output")
        .arg(&pack_file)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", s(&out).1);
    refused(
        entangle(&home)
            .args(["plugins", "install"])
            .arg(&pack_file)
            .arg("--no-load")
            .output()
            .unwrap(),
    );
    // With the flag the older version goes in.
    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(&old)
        .args(["--no-load", "--allow-downgrade"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", s(&out).1);
    assert!(installed().contains("0.1.0"));
}

/// A package archive on disk installs through the same checks.
#[test]
fn a_local_archive_file_installs_only_if_it_verifies() {
    let home = TempDir::new().unwrap();
    let (publisher, stranger) = (kp(1), kp(2));
    trust(&home, &[&publisher]);
    let good = home.path().join("hello-0.1.0.tar.zst");
    std::fs::write(&good, archive(&publisher, "hello", 1)).unwrap();
    let bad = home.path().join("other-0.1.0.tar.zst");
    std::fs::write(&bad, archive(&stranger, "other", 1)).unwrap();

    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(&bad)
        .arg("--no-load")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(s(&out).1.contains("ENTANGLE-E0101"), "{}", s(&out).1);
    nothing_installed(&home);

    let out = entangle(&home)
        .args(["plugins", "install"])
        .arg(&good)
        .arg("--no-load")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", s(&out).1);
    assert!(home
        .path()
        .join(".entangle/plugins/hello/plugin.wasm.sig")
        .is_file());
}

// ---------------------------------------------------------------------------
// 2. entangle pack / .entanglepack
// ---------------------------------------------------------------------------

/// Write `f` as a package directory and return it.
fn package_dir(root: &Path, name: &str, f: &PackageFiles) -> PathBuf {
    let dir = root.join(name);
    f.write_dir(&dir).unwrap();
    dir
}

#[test]
fn pack_round_trip_installs_every_package_offline() {
    let sender = TempDir::new().unwrap();
    let (alice, bob) = (kp(1), kp(2));
    trust(&sender, &[&alice, &bob]);

    // Three ways to name a package: an archive, a package directory, and an
    // installed plugin by name.
    let alpha = sender.path().join("alpha-0.1.0.tar.zst");
    std::fs::write(&alpha, archive(&alice, "alpha", 1)).unwrap();
    let beta_dir = package_dir(sender.path(), "beta-dist", &files(&bob, "beta", 2, "0.3.0"));
    let gamma = sender.path().join("gamma-0.1.0.tar.zst");
    std::fs::write(&gamma, archive(&alice, "gamma", 1)).unwrap();
    let out = entangle(&sender)
        .args(["plugins", "install"])
        .arg(&gamma)
        .arg("--no-load")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", s(&out).1);

    let packfile = sender.path().join("site.entanglepack");
    let out = entangle(&sender)
        .arg("pack")
        .arg(&alpha)
        .arg(&beta_dir)
        .arg("gamma")
        .arg("-o")
        .arg(&packfile)
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(so.contains("3 package(s)"), "{so}");
    assert!(so.contains(&alice.fingerprint_hex()) && so.contains(&bob.fingerprint_hex()));
    // Refuses to overwrite without --force.
    let again = entangle(&sender)
        .arg("pack")
        .arg(&alpha)
        .arg("-o")
        .arg(&packfile)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(s(&again).1.contains("ENTANGLE-E0941"), "{}", s(&again).1);

    // The receiving machine: no network, its own keyring.
    let receiver = TempDir::new().unwrap();
    trust(&receiver, &[&alice, &bob]);
    let out = entangle(&receiver)
        .args(["plugins", "install"])
        .arg(&packfile)
        .arg("--no-load")
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    for (name, key, tier, version) in [
        ("alpha", &alice, 1, "0.1.0"),
        ("beta", &bob, 2, "0.3.0"),
        ("gamma", &alice, 1, "0.1.0"),
    ] {
        let dir = receiver.path().join(".entangle/plugins").join(name);
        assert_eq!(
            PackageFiles::read_dir(&dir).unwrap(),
            files(key, name, tier, version),
            "{name}"
        );
    }
    // `entangle install <pack>` is the same command.
    let third = TempDir::new().unwrap();
    trust(&third, &[&alice, &bob]);
    let out = entangle(&third)
        .arg("install")
        .arg(&packfile)
        .arg("--no-load")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", s(&out).1);
    assert!(third.path().join(".entangle/plugins/beta").is_dir());
}

#[test]
fn two_packs_of_the_same_inputs_are_byte_identical() {
    let home = TempDir::new().unwrap();
    let (alice, bob) = (kp(1), kp(2));
    trust(&home, &[&alice, &bob]);
    let a = home.path().join("alpha-0.1.0.tar.zst");
    std::fs::write(&a, archive(&alice, "alpha", 1)).unwrap();
    let b = package_dir(home.path(), "beta", &files(&bob, "beta", 1, "0.1.0"));

    let one = home.path().join("one.entanglepack");
    let two = home.path().join("sub/two.entanglepack");
    let out = entangle(&home)
        .arg("pack")
        .args([&a, &b])
        .arg("-o")
        .arg(&one)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", s(&out).1);
    // Later, arguments in the other order, from another directory.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let out = entangle(&home)
        .current_dir(home.path())
        .arg("pack")
        .args([&b, &a])
        .arg("-o")
        .arg(&two)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", s(&out).1);
    let (x, y) = (std::fs::read(&one).unwrap(), std::fs::read(&two).unwrap());
    assert_eq!(x, y, "the pack depends on its inputs only");
    assert_eq!(read_pack(&x).unwrap().packages.len(), 2);
}

#[test]
fn pack_with_a_tampered_package_is_refused_and_installs_nothing() {
    let sender = TempDir::new().unwrap();
    let alice = kp(1);
    trust(&sender, &[&alice]);
    let a = sender.path().join("alpha-0.1.0.tar.zst");
    let b = sender.path().join("beta-0.1.0.tar.zst");
    std::fs::write(&a, archive(&alice, "alpha", 1)).unwrap();
    std::fs::write(&b, archive(&alice, "beta", 1)).unwrap();
    let packfile = sender.path().join("p.entanglepack");
    let out = entangle(&sender)
        .arg("pack")
        .args([&a, &b])
        .arg("-o")
        .arg(&packfile)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", s(&out).1);
    let good = std::fs::read(&packfile).unwrap();
    let receiver = TempDir::new().unwrap();
    trust(&receiver, &[&alice]);
    let install = |bytes: &[u8]| {
        let p = receiver.path().join("in.entanglepack");
        std::fs::write(&p, bytes).unwrap();
        entangle(&receiver)
            .args(["plugins", "install"])
            .arg(&p)
            .arg("--no-load")
            .output()
            .unwrap()
    };

    // (1) One byte of the second package flipped: the index digest catches it.
    let beta = std::fs::read(&b).unwrap();
    let at = good
        .windows(beta.len())
        .position(|w| w == beta.as_slice())
        .expect("package stored verbatim");
    let mut flipped = good.clone();
    flipped[at + beta.len() / 2] ^= 0x01;
    let out = install(&flipped);
    assert!(!out.status.success());
    assert!(s(&out).1.contains("ENTANGLE-E0807"), "{}", s(&out).1);
    nothing_installed(&receiver);

    // (2) A package whose artifact was replaced, with the pack's index and
    // digests rebuilt to match (what an attacker who can rewrite the pack
    // would do): only the publisher signature can catch it, and it does.
    let mut evil = files(&alice, "beta", 1, "0.1.0");
    evil.wasm = b"\0asm\x01\x00\x00\x00 backdoored".to_vec();
    let evil_bytes = pack(&evil).unwrap();
    let mut pack_ = read_pack(&good).unwrap();
    let sha = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&evil_bytes))
    };
    let entry = pack_
        .index
        .packages
        .iter_mut()
        .find(|p| p.plugin_id.contains("/beta@"))
        .unwrap();
    entry.sha256 = sha.clone();
    entry.size = evil_bytes.len() as u64;
    entry.file = format!("packages/{sha}.tar.zst");
    let alpha_entry = pack_
        .packages
        .iter()
        .find(|p| p.entry.plugin_id.contains("/alpha@"))
        .unwrap();
    let evil_name = format!("packages/{sha}.tar.zst");
    let tar = raw_pack(
        &pack_.index,
        &[
            (&alpha_entry.entry.file, &alpha_entry.bytes),
            (&evil_name, &evil_bytes),
        ],
    );
    assert!(
        read_pack(&tar).is_ok(),
        "the forged container is well-formed"
    );
    let out = install(&tar);
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(
        se.contains("ENTANGLE-E0102") || se.contains("ENTANGLE-E0100"),
        "{se}"
    );
    assert!(se.contains("nothing from the pack was installed"), "{se}");
    // All or nothing: the untouched alpha was not installed either.
    nothing_installed(&receiver);

    // The genuine pack still installs.
    assert!(install(&good).status.success());
}

#[test]
fn pack_keys_are_never_trusted_automatically() {
    let sender = TempDir::new().unwrap();
    let (alice, bob) = (kp(1), kp(2));
    trust(&sender, &[&alice, &bob]);
    let a = sender.path().join("alpha-0.1.0.tar.zst");
    let b = sender.path().join("beta-0.1.0.tar.zst");
    std::fs::write(&a, archive(&alice, "alpha", 1)).unwrap();
    std::fs::write(&b, archive(&bob, "beta", 1)).unwrap();
    let packfile = sender.path().join("p.entanglepack");
    assert!(entangle(&sender)
        .arg("pack")
        .args([&a, &b])
        .arg("-o")
        .arg(&packfile)
        .output()
        .unwrap()
        .status
        .success());

    // The receiver trusts alice only. The pack carries bob's public key.
    let receiver = TempDir::new().unwrap();
    trust(&receiver, &[&alice]);
    let ring_before = std::fs::read(receiver.path().join(".entangle/keyring.toml")).unwrap();
    let out = entangle(&receiver)
        .args(["plugins", "install"])
        .arg(&packfile)
        .arg("--no-load")
        .output()
        .unwrap();
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(se.contains("ENTANGLE-E0940"), "{se}");
    assert!(se.contains(&bob.fingerprint_hex()), "fingerprint: {se}");
    assert!(
        se.contains(&format!(
            "entangle keyring add {} --name",
            hex::encode(bob.public().as_bytes())
        )),
        "the keyring add command: {se}"
    );
    assert!(se.contains("--trust-pack-keys"), "{se}");
    // Nothing installed (not even alice's package) and the keyring untouched.
    nothing_installed(&receiver);
    assert_eq!(
        std::fs::read(receiver.path().join(".entangle/keyring.toml")).unwrap(),
        ring_before
    );
    assert!(keyring_of(&receiver).lookup(&bob.fingerprint()).is_none());

    // The flag is refused for anything that is not a pack.
    let out = entangle(&receiver)
        .args(["plugins", "install"])
        .arg(&a)
        .args(["--no-load", "--trust-pack-keys"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(s(&out).1.contains("--trust-pack-keys"));

    // Explicit opt-in: fingerprints are printed, then the key is added.
    let out = entangle(&receiver)
        .args(["plugins", "install"])
        .arg(&packfile)
        .args(["--no-load", "--trust-pack-keys"])
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    let printed = so
        .find(&bob.fingerprint_hex())
        .expect("fingerprint printed");
    let saved = so.find("saved 1 new key").expect("key saved");
    assert!(printed < saved, "fingerprints come before the key is saved");
    let ring = keyring_of(&receiver);
    let entry = ring.lookup(&bob.fingerprint()).expect("bob trusted now");
    assert_eq!(entry.public_key, *bob.public().as_bytes());
    assert!(entry.note.contains("--trust-pack-keys"), "{}", entry.note);
    assert!(receiver.path().join(".entangle/plugins/beta").is_dir());

    // --trust-pack-keys does not rescue a pack whose package fails
    // verification, and such a pack leaves the keyring alone.
    let fresh = TempDir::new().unwrap();
    trust(&fresh, &[&alice]);
    let mut forged = files(&bob, "beta", 1, "0.1.0");
    // bob's manifest and fingerprint, but a signature that is not bob's.
    let attacker = kp(9);
    let mut bundle = sign_artifact_at(&forged.wasm, &forged.manifest, &attacker, 1);
    bundle.publisher_fingerprint = bob.fingerprint();
    forged.signature = toml::to_string(&bundle).unwrap().into_bytes();
    let forged_bytes = pack(&forged).unwrap();
    let genuine = read_pack(&std::fs::read(&packfile).unwrap()).unwrap();
    let mut index = genuine.index.clone();
    let sha = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&forged_bytes))
    };
    index.packages.retain(|p| p.plugin_id.contains("/beta@"));
    index.packages[0].sha256 = sha.clone();
    index.packages[0].size = forged_bytes.len() as u64;
    index.packages[0].file = format!("packages/{sha}.tar.zst");
    let forged_pack = raw_pack(&index, &[(&index.packages[0].file, &forged_bytes)]);
    let p = fresh.path().join("forged.entanglepack");
    std::fs::write(&p, forged_pack).unwrap();
    let out = entangle(&fresh)
        .args(["plugins", "install"])
        .arg(&p)
        .args(["--no-load", "--trust-pack-keys"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(s(&out).1.contains("ENTANGLE-E0100"), "{}", s(&out).1);
    assert!(keyring_of(&fresh).lookup(&bob.fingerprint()).is_none());
    nothing_installed(&fresh);
}

/// Assemble a pack by hand from an index and entries (forgery cases).
fn raw_pack(index: &entangle_oci::PackIndex, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    let mut put = |name: &str, data: &[u8]| {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[148..156].copy_from_slice(b"        ");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        tar.extend_from_slice(&h);
        tar.extend_from_slice(data);
        tar.resize(tar.len() + (512 - data.len() % 512) % 512, 0);
    };
    put("entanglepack.json", &serde_json::to_vec(index).unwrap());
    for (n, d) in entries {
        put(n, d);
    }
    tar.extend_from_slice(&[0u8; 1024]);
    tar
}

#[test]
fn pack_refuses_what_does_not_verify_or_cannot_be_found() {
    let home = TempDir::new().unwrap();
    let (alice, stranger) = (kp(1), kp(2));
    trust(&home, &[&alice]);
    let unknown = home.path().join("x-0.1.0.tar.zst");
    std::fs::write(&unknown, archive(&stranger, "x", 1)).unwrap();
    let out_file = home.path().join("o.entanglepack");
    let out = entangle(&home)
        .arg("pack")
        .arg(&unknown)
        .arg("-o")
        .arg(&out_file)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(s(&out).1.contains("ENTANGLE-E0101"), "{}", s(&out).1);
    assert!(!out_file.exists(), "nothing is written on failure");

    let out = entangle(&home)
        .args(["pack", "no-such-plugin", "-o"])
        .arg(&out_file)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(s(&out).1.contains("ENTANGLE-E0941"), "{}", s(&out).1);
    assert!(!out_file.exists());
}

// ---------------------------------------------------------------------------
// 3 + 4. Mirror setting, fallback order, TLS to a registry, listing rollback
// ---------------------------------------------------------------------------

fn seed(mock: &MockRegistry, repo: &str, tag: &str, pkg: &[u8]) {
    let layer = mock.put_blob(pkg);
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

#[test]
fn mirror_set_get_unset_round_trip_and_bad_urls_are_refused() {
    let home = TempDir::new().unwrap();
    let get = || {
        let o = entangle(&home).args(["mirror", "get"]).output().unwrap();
        assert!(o.status.success(), "{}", s(&o).1);
        s(&o).0
    };
    assert!(get().contains("no mirror configured"), "{}", get());

    for bad in [
        "http://mirror.example.org",
        "mirror.example.org",
        "https://u:hunter2@mirror.example.org",
    ] {
        let o = entangle(&home)
            .args(["mirror", "set", bad])
            .output()
            .unwrap();
        assert!(!o.status.success(), "{bad}");
        let se = s(&o).1;
        assert!(
            se.contains("ENTANGLE-E0825") || se.contains("ENTANGLE-E0801"),
            "{bad}: {se}"
        );
        assert!(!se.contains("hunter2"), "{se}");
    }
    assert!(!home.path().join(".entangle/mirror.toml").exists());

    let o = entangle(&home)
        .args(["mirror", "set", "https://mirror.example.org/oci/"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", s(&o).1);
    assert_eq!(get().trim(), "https://mirror.example.org/oci");
    let o = entangle(&home)
        .args(["mirror", "get", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["mirror"], "https://mirror.example.org/oci");

    let o = entangle(&home).args(["mirror", "unset"]).output().unwrap();
    assert!(o.status.success());
    assert!(get().contains("no mirror configured"));
    // Unsetting twice is not an error.
    assert!(entangle(&home)
        .args(["mirror", "unset"])
        .output()
        .unwrap()
        .status
        .success());

    // A damaged setting is an error, not "no mirror".
    std::fs::create_dir_all(home.path().join(".entangle")).unwrap();
    std::fs::write(home.path().join(".entangle/mirror.toml"), "url = [").unwrap();
    let o = entangle(&home).args(["mirror", "get"]).output().unwrap();
    assert!(!o.status.success());
    assert!(s(&o).1.contains("ENTANGLE-E0944"), "{}", s(&o).1);
}

/// The configured mirror is asked first, over a real TLS handshake; the
/// origin is asked only for what the mirror cannot supply; and the publisher
/// signature is required from either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oci_install_prefers_the_mirror_over_tls_and_falls_back_to_the_origin() {
    let mirror = https_server().await;
    let origin = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let (publisher, attacker) = (kp(1), kp(2));
    trust(&home, &[&publisher]);

    let on_mirror = pack(&files(&publisher, "hello", 1, "0.1.0")).unwrap();
    seed(&mirror.mock, "acme/hello", "0.1.0", &on_mirror);
    // The origin has a second plugin the mirror has not synced yet...
    seed(
        &origin,
        "acme/late",
        "0.1.0",
        &pack(&files(&publisher, "late", 1, "0.1.0")).unwrap(),
    );
    // ...and, for a third, the mirror holds bytes signed by someone else.
    seed(
        &mirror.mock,
        "acme/swapped",
        "0.1.0",
        &pack(&files(&attacker, "swapped", 1, "0.1.0")).unwrap(),
    );
    seed(
        &origin,
        "acme/swapped",
        "0.1.0",
        &pack(&files(&publisher, "swapped", 1, "0.1.0")).unwrap(),
    );

    let o = entangle_trusting(&home, &mirror.ca_pem)
        .args(["mirror", "set", &mirror.mock.origin()])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", s(&o).1);
    let install = |repo: &str| {
        entangle_trusting(&home, &mirror.ca_pem)
            .args([
                "plugins",
                "install",
                &format!("oci://{}/acme/{repo}:0.1.0", origin.registry()),
                "--no-load",
            ])
            .output()
            .unwrap()
    };

    // (a) Served by the mirror over TLS; the origin is never contacted.
    let out = install("hello");
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(so.contains("from mirror https://localhost:"), "{so}");
    assert!(origin.requests().is_empty(), "origin contacted needlessly");
    assert!(mirror
        .mock
        .requests()
        .iter()
        .any(|r| r.path == "/v2/acme/hello/manifests/0.1.0"));
    assert_eq!(
        PackageFiles::read_dir(&home.path().join(".entangle/plugins/hello")).unwrap(),
        files(&publisher, "hello", 1, "0.1.0")
    );

    // (b) Not on the mirror: the origin supplies it.
    let out = install("late");
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(
        se.contains("warning: mirror") && se.contains("trying the next source"),
        "{se}"
    );
    assert!(home.path().join(".entangle/plugins/late").is_dir());

    // (c) The mirror serves a package that does not verify: skipped with a
    // warning, and the origin's genuine one is installed. A mirror can fail
    // to deliver; it cannot substitute.
    let out = install("swapped");
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(se.contains("ENTANGLE-E0101"), "{se}");
    assert_eq!(
        PackageFiles::read_dir(&home.path().join(".entangle/plugins/swapped")).unwrap(),
        files(&publisher, "swapped", 1, "0.1.0")
    );

    // (d) Neither has it: the error names both attempts.
    let out = install("absent");
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(
        se.contains("every source failed") && se.contains("mirror https://"),
        "{se}"
    );

    // (e) Without the CA the mirror's certificate is not trusted: the pull
    // falls back to the origin instead of trusting the mirror blindly.
    let before = mirror.mock.requests().len();
    let out = entangle(&home)
        .args([
            "plugins",
            "install",
            &format!("oci://{}/acme/late:0.1.0", origin.registry()),
            "--no-load",
        ])
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(se.contains("TLS"), "{se}");
    assert_eq!(
        mirror.mock.requests().len(),
        before,
        "no request without TLS"
    );

    // (f) After `mirror unset` only the origin is used.
    assert!(entangle(&home)
        .args(["mirror", "unset"])
        .output()
        .unwrap()
        .status
        .success());
    let before = mirror.mock.requests().len();
    let out = install("late");
    assert!(out.status.success(), "{}", s(&out).1);
    assert_eq!(mirror.mock.requests().len(), before);
}

/// Every check runs inside each source's attempt, so a mirror that serves a
/// validly signed but wrong package (another name, another version, another
/// trusted publisher, an older release) is skipped and the origin is tried.
/// The first install pins the repository's publisher; `--publisher` states
/// and re-pins it. A floating tag goes through the verified listing when
/// mirror keys are configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oci_install_binds_each_source_pins_the_publisher_and_refuses_downgrades() {
    let mirror = MockRegistry::start(MockOptions::default()).await;
    let origin = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let (publisher, rival) = (kp(1), kp(2));
    // Both publishers are trusted: the pin is what keeps them apart.
    trust(&home, &[&publisher, &rival]);
    let pkg = |k: &IdentityKeyPair, name: &str, v: &str| pack(&files(k, name, 1, v)).unwrap();

    // The mirror answers acme/hello:0.2.0 with another plugin; the origin is right.
    seed(
        &mirror,
        "acme/hello",
        "0.2.0",
        &pkg(&publisher, "other", "0.2.0"),
    );
    seed(
        &origin,
        "acme/hello",
        "0.2.0",
        &pkg(&publisher, "hello", "0.2.0"),
    );
    std::fs::create_dir_all(home.path().join(".entangle")).unwrap();
    std::fs::write(
        home.path().join(".entangle/mirror.toml"),
        format!("url = \"{}\"\n", mirror.origin()),
    )
    .unwrap();
    let install = |r: &str, extra: &[&str]| {
        entangle(&home)
            .args([
                "plugins",
                "install",
                &format!("oci://{}/{r}", origin.registry()),
            ])
            .arg("--no-load")
            .args(extra)
            .output()
            .unwrap()
    };
    let installed = || {
        std::fs::read_to_string(home.path().join(".entangle/plugins/hello/entangle.toml"))
            .unwrap_or_default()
    };
    let out = install("acme/hello:0.2.0", &[]);
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(
        se.contains("ENTANGLE-E0945") && se.contains("trying the next source"),
        "{se}"
    );
    assert!(installed().contains(&format!("{}/hello@0.2.0", publisher.fingerprint_hex())));
    let pins = std::fs::read_to_string(home.path().join(".entangle/oci-publishers.toml")).unwrap();
    assert!(pins.contains(&publisher.fingerprint_hex()), "{pins}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(home.path().join(".entangle/oci-publishers.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    // An older, validly signed release from both sources: refused (no
    // source passes), the newer one stays.
    seed(
        &mirror,
        "acme/hello",
        "0.1.0",
        &pkg(&publisher, "hello", "0.1.0"),
    );
    seed(
        &origin,
        "acme/hello",
        "0.1.0",
        &pkg(&publisher, "hello", "0.1.0"),
    );
    let out = install("acme/hello:0.1.0", &[]);
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(
        se.contains("ENTANGLE-E0946") && se.contains("every source failed"),
        "{se}"
    );
    assert!(installed().contains("hello@0.2.0"));
    assert!(install("acme/hello:0.1.0", &["--allow-downgrade"])
        .status
        .success());
    assert!(installed().contains("hello@0.1.0"));

    // Another trusted publisher's `hello` in the pinned repository.
    seed(
        &mirror,
        "acme/hello",
        "0.3.0",
        &pkg(&rival, "hello", "0.3.0"),
    );
    seed(
        &origin,
        "acme/hello",
        "0.3.0",
        &pkg(&rival, "hello", "0.3.0"),
    );
    let out = install("acme/hello:0.3.0", &[]);
    let (_, se) = s(&out);
    assert!(!out.status.success());
    assert!(
        se.contains("ENTANGLE-E0947")
            && se.contains(&format!("--publisher {}", rival.fingerprint_hex())),
        "{se}"
    );
    assert!(installed().contains("hello@0.1.0"));
    // --publisher must match what is served...
    let out = install(
        "acme/hello:0.3.0",
        &["--publisher", &publisher.fingerprint_hex()],
    );
    assert!(!out.status.success());
    assert!(s(&out).1.contains("ENTANGLE-E0945"), "{}", s(&out).1);
    // ...and stating the new publisher re-pins the repository. (The default
    // directory refuses another publisher's package, so use --out.)
    let out = install(
        "acme/hello:0.3.0",
        &[
            "--publisher",
            &rival.fingerprint_hex(),
            "--out",
            home.path().join("rival").to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", s(&out).1);
    let pins = std::fs::read_to_string(home.path().join(".entangle/oci-publishers.toml")).unwrap();
    assert!(
        pins.contains(&rival.fingerprint_hex()) && !pins.contains(&publisher.fingerprint_hex()),
        "{pins}"
    );
    // --publisher is for oci:// only.
    let out = entangle(&home)
        .args(["plugins", "install", "./x.tar.zst", "--publisher"])
        .arg(publisher.fingerprint_hex())
        .output()
        .unwrap();
    assert!(!out.status.success() && s(&out).1.contains("--publisher"));
}

/// With mirror keys configured, a floating tag is resolved through the
/// verified signed listing: a source whose listing does not verify (here the
/// mirror's, unsigned) cannot serve it, and the digest the listing names is
/// what is pulled from the origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oci_floating_tags_resolve_through_the_verified_listing() {
    let mirror = MockRegistry::start(MockOptions::default()).await;
    let origin = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    let mirror_key = kp(50);
    trust(&home, &[&publisher]);
    let v1 = pack(&files(&publisher, "tool", 1, "1.0.0")).unwrap();
    let v2 = pack(&files(&publisher, "tool", 1, "2.0.0")).unwrap();
    // The mirror's `latest` is the old release; the origin's is the new one,
    // and the origin's signed listing says so.
    seed(&mirror, "acme/tool", "latest", &v1);
    seed(&origin, "acme/tool", "2.0.0", &v2);
    seed(&origin, "acme/tool", "latest", &v2);
    let mut keys = MirrorKeyring::new();
    keys.add_public_key(&mirror_key.public(), "mirror");
    keys.save(&home.path().join(".entangle/mirror-keys.toml"))
        .unwrap();
    let reference =
        Reference::parse(&format!("oci://{}/acme/tool:latest", origin.registry())).unwrap();
    let client = OciClient::for_reference(&reference, Default::default()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let digest = entangle_oci::Digest::of(&origin.manifest_bytes("acme/tool", "2.0.0").unwrap());
    let listing = MirrorListing {
        version: 1,
        repository: "acme/tool".into(),
        tags: [("latest".to_owned(), digest.clone())].into(),
        generated_at: now - 60,
        expires_at: now + 86_400,
    };
    publish_listing(&client, &reference, &listing, &mirror_key)
        .await
        .unwrap();
    std::fs::write(
        home.path().join(".entangle/mirror.toml"),
        format!("url = \"{}\"\n", mirror.origin()),
    )
    .unwrap();
    let out = entangle(&home)
        .env("ENTANGLE_ALLOW_LOCAL", "1")
        .args([
            "plugins",
            "install",
            &format!("oci://{}/acme/tool:latest", origin.registry()),
        ])
        .arg("--no-load")
        .output()
        .unwrap();
    let (so, se) = s(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(
        se.contains("ENTANGLE-E0945") && se.contains("unsigned"),
        "{se}"
    );
    assert!(so.contains(&format!("tag latest -> {digest}")), "{so}");
    assert!(origin
        .requests()
        .iter()
        .any(|r| r.path == format!("/v2/acme/tool/manifests/{digest}")));
    assert!(
        std::fs::read_to_string(home.path().join(".entangle/plugins/tool/entangle.toml"))
            .unwrap()
            .contains("tool@2.0.0")
    );
}

/// Two signed listings through the CLI: after the newer one has been seen,
/// the older is refused until the operator accepts it; the record is 0600.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tags_refuses_a_rolled_back_listing_until_the_operator_accepts_it() {
    let mock = MockRegistry::start(MockOptions::default()).await;
    let home = TempDir::new().unwrap();
    let publisher = kp(1);
    let mirror_key = kp(50);
    seed(
        &mock,
        "acme/tool",
        "1.0.0",
        &pack(&files(&publisher, "tool", 1, "1.0.0")).unwrap(),
    );
    let mut keys = MirrorKeyring::new();
    keys.add_public_key(&mirror_key.public(), "mirror");
    keys.save(&home.path().join(".entangle/mirror-keys.toml"))
        .unwrap();

    let reference =
        Reference::parse(&format!("oci://{}/acme/tool:latest", mock.registry())).unwrap();
    let client = OciClient::for_reference(&reference, Default::default()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let listing = |generated_at: u64| MirrorListing {
        version: 1,
        repository: "acme/tool".into(),
        tags: [(
            "1.0.0".to_owned(),
            entangle_oci::Digest::of(&mock.manifest_bytes("acme/tool", "1.0.0").unwrap()),
        )]
        .into(),
        generated_at,
        expires_at: now + 86_400,
    };
    let tags = |extra: &[&str]| {
        entangle(&home)
            .args(["plugins", "tags"])
            .arg(format!("oci://{}/acme/tool", mock.registry()))
            .args(["--require-verified"])
            .args(extra)
            .output()
            .unwrap()
    };
    let state_file = home.path().join(".entangle/mirror-listing-state.toml");

    // The newer listing is seen first.
    publish_listing(&client, &reference, &listing(now - 60), &mirror_key)
        .await
        .unwrap();
    let out = tags(&[]);
    assert!(out.status.success(), "{}", s(&out).1);
    assert!(s(&out).0.contains("listing:    verified"), "{}", s(&out).0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&state_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }
    let recorded = std::fs::read_to_string(&state_file).unwrap();
    assert!(
        recorded.contains(&format!("generated_at = {}", now - 60)),
        "{recorded}"
    );

    // Then an older one, still correctly signed and unexpired.
    publish_listing(&client, &reference, &listing(now - 7 * 86_400), &mirror_key)
        .await
        .unwrap();
    let out = tags(&[]);
    let (so, se) = s(&out);
    assert!(!out.status.success(), "{so}\n{se}");
    assert!(
        so.contains("ROLLED BACK") && so.contains("ENTANGLE-E0820"),
        "{so}"
    );
    assert!(so.contains("not covered by a verified listing"), "{so}");
    assert!(
        se.contains("ENTANGLE-E0820") && se.contains("--accept-older-listing"),
        "{se}"
    );
    assert_eq!(std::fs::read_to_string(&state_file).unwrap(), recorded);
    // JSON carries the same verdict.
    let out = entangle(&home)
        .args(["plugins", "tags", "--json"])
        .arg(format!("oci://{}/acme/tool", mock.registry()))
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verification"]["status"], "rolled_back");
    assert_eq!(v["verification"]["newest_seen"], now - 60);
    assert_eq!(v["source"], "origin");

    // The operator's reset.
    let out = tags(&["--accept-older-listing"]);
    assert!(out.status.success(), "{}", s(&out).1);
    assert!(std::fs::read_to_string(&state_file)
        .unwrap()
        .contains(&format!("generated_at = {}", now - 7 * 86_400)));
    assert!(tags(&[]).status.success());
}
