//! `[plugins] disabled` is honoured, and `entangle plugins enable|disable`
//! edit it (spec §9.4.1 step 4 writes the list; nothing used to read it).
#![cfg(unix)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use predicates::prelude::*;
use tempfile::TempDir;

fn entangle(home: &Path) -> Command {
    let mut c = Command::cargo_bin("entangle").expect("entangle binary built");
    c.env("HOME", home).env_remove("ENTANGLE_ALLOW_LOCAL");
    c
}

struct Env {
    _tmp: TempDir,
    home: PathBuf,
    pkg: PathBuf,
    id: String,
}

impl Env {
    fn new(config: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("h");
        let cdir = home.join(".entangle");
        std::fs::create_dir_all(&cdir).unwrap();
        let kp = IdentityKeyPair::generate();
        let mut kr = Keyring::new();
        kr.add(TrustEntry {
            fingerprint: kp.fingerprint(),
            public_key: *kp.public().as_bytes(),
            publisher_name: "t".into(),
            added_at: 0,
            note: String::new(),
        });
        kr.save(&cdir.join("keyring.toml")).unwrap();
        let id = format!("{}/tiny@0.1.0", kp.fingerprint_hex());
        let pkg = tmp.path().join("pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        let wasm = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../entangle-host/tests/fixtures/hello-pong.wasm"
        ))
        .unwrap();
        let manifest = format!(
            "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 2\nruntime = \"wasm\"\n\n[capabilities]\n"
        );
        std::fs::write(pkg.join("entangle.toml"), &manifest).unwrap();
        std::fs::write(pkg.join("plugin.wasm"), &wasm).unwrap();
        let bundle = sign_artifact(&wasm, manifest.as_bytes(), &kp);
        std::fs::write(
            pkg.join("plugin.wasm.sig"),
            toml::to_string(&bundle).unwrap(),
        )
        .unwrap();
        std::fs::write(cdir.join("config.toml"), config).unwrap();
        Self {
            _tmp: tmp,
            home,
            pkg,
            id,
        }
    }

    fn config(&self) -> String {
        std::fs::read_to_string(self.home.join(".entangle/config.toml")).unwrap()
    }

    fn load_local(&self) -> assert_cmd::assert::Assert {
        entangle(&self.home)
            .args(["--allow-local", "plugins", "load"])
            .arg(&self.pkg)
            .assert()
    }
}

#[test]
fn local_kernel_refuses_a_disabled_plugin_naming_the_remedy() {
    let e = Env::new("");
    let cfg = format!("# keep me\n[plugins]\ndisabled = [\"{}\"]\n", e.id);
    std::fs::write(e.home.join(".entangle/config.toml"), &cfg).unwrap();
    e.load_local()
        .failure()
        .stderr(
            predicate::str::contains("ENTANGLE-E0759").and(predicate::str::contains(format!(
                "entangle plugins enable {}",
                e.id
            ))),
        );
    // Not disabled: the same package loads.
    std::fs::write(e.home.join(".entangle/config.toml"), "").unwrap();
    e.load_local()
        .success()
        .stdout(predicate::str::contains(format!("loaded {}", e.id)));
}

#[test]
fn disable_then_enable_round_trips_and_preserves_the_file() {
    let e = Env::new("# operator notes\n[security]\nmax_tier_allowed = 5 # all\n");
    entangle(&e.home)
        .args(["plugins", "disable", &e.id])
        .assert()
        .success();
    let cfg = e.config();
    assert!(
        cfg.starts_with("# operator notes\n[security]\nmax_tier_allowed = 5 # all\n"),
        "{cfg}"
    );
    assert!(cfg.contains(&e.id), "{cfg}");
    // Idempotent.
    entangle(&e.home)
        .args(["plugins", "disable", &e.id])
        .assert()
        .success()
        .stdout(predicate::str::contains("already disabled"));
    assert_eq!(e.config().matches(&e.id).count(), 1);

    // Disabled means the load is refused now.
    e.load_local()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0759"));

    entangle(&e.home)
        .args(["plugins", "enable", &e.id])
        .assert()
        .success();
    assert!(!e.config().contains(&e.id), "{}", e.config());
    assert!(e.config().starts_with("# operator notes\n"));
    e.load_local().success();
    entangle(&e.home)
        .args(["plugins", "enable", &e.id])
        .assert()
        .success()
        .stdout(predicate::str::contains("is not disabled"));
}

#[test]
fn enable_is_refused_when_the_tier_is_above_the_ceiling() {
    let e = Env::new("");
    // Lowering to 3 disabled a tier-5 plugin and audited its tier.
    let id = format!("{}/big@1.0.0", "ab".repeat(16));
    std::fs::write(
        e.home.join(".entangle/config.toml"),
        format!("[security]\nmax_tier_allowed = 3\n[plugins]\ndisabled = [\"{id}\"]\n"),
    )
    .unwrap();
    std::fs::write(
        e.home.join(".entangle/audit.log"),
        format!("{{\"code\":\"ENTANGLE-W0214\",\"plugin\":\"{id}\",\"tier\":5}}\n"),
    )
    .unwrap();
    entangle(&e.home)
        .args(["plugins", "enable", &id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0760").and(predicate::str::contains("tier 5")));
    assert!(e.config().contains(&id), "nothing changed");

    // Raising the ceiling first makes it allowed.
    std::fs::write(
        e.home.join(".entangle/config.toml"),
        format!("[security]\nmax_tier_allowed = 5\n[plugins]\ndisabled = [\"{id}\"]\n"),
    )
    .unwrap();
    entangle(&e.home)
        .args(["plugins", "enable", &id])
        .assert()
        .success();
    assert!(!e.config().contains(&id));
}

#[test]
fn enable_checks_an_installed_manifest_against_the_ceiling() {
    let e = Env::new("[security]\nmax_tier_allowed = 1\n");
    // tier-2 package installed under ~/.entangle/plugins/tiny
    let inst = e.home.join(".entangle/plugins/tiny");
    std::fs::create_dir_all(&inst).unwrap();
    std::fs::copy(e.pkg.join("entangle.toml"), inst.join("entangle.toml")).unwrap();
    let cfg = format!(
        "[security]\nmax_tier_allowed = 1\n[plugins]\ndisabled = [\"{}\"]\n",
        e.id
    );
    std::fs::write(e.home.join(".entangle/config.toml"), cfg).unwrap();
    entangle(&e.home)
        .args(["plugins", "enable", &e.id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0760"));
}

#[test]
fn malformed_ids_are_rejected() {
    let e = Env::new("");
    entangle(&e.home)
        .args(["plugins", "disable", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid plugin id"));
    assert_eq!(e.config(), "");
}
