//! End-to-end tests for the one-command install path:
//! `entangle plugins available`, `entangle plugins install <NAME>`, and
//! `entangle quickstart`.
//!
//! Every test builds its **own** temporary catalog. Nothing here depends on the
//! repository's `plugins/` directory existing — a test that reads the real
//! catalog would be a test of someone else's file layout, and would fail or pass
//! for reasons unrelated to this code.
//!
//! Compiling wasm is never exercised by default: the install tests package a
//! pre-built (fake) artifact via `--wasm`, and the one test that runs a real
//! `cargo build --target wasm32-wasip2` is `#[ignore]`d.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `entangle` with `$HOME` pointed at `tmp` and every catalog-affecting
/// variable cleared, so a developer's real environment cannot leak in.
fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    cmd.env_remove("ENTANGLE_CATALOG");
    cmd.env_remove("ENTANGLE_SDK_PATH");
    cmd.env_remove("ENTANGLE_ALLOW_LOCAL");
    cmd
}

fn init(tmp: &TempDir) {
    entangle(tmp)
        .args(["init", "--non-interactive"])
        .assert()
        .success();
}

fn entangle_dir(tmp: &TempDir) -> PathBuf {
    tmp.path().join(".entangle")
}

/// A minimal wasm header — enough to copy, hash and sign.
const FAKE_WASM: &[u8] = b"\0asm\x01\x00\x00\x00";

/// Write a plugin project into `catalog`: a manifest, a README, and a pre-built
/// artifact so `--wasm` can skip cargo entirely.
fn catalog_plugin(catalog: &Path, name: &str, tier: u8, description: &str) -> PathBuf {
    let dir = catalog.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("entangle.toml"),
        format!(
            r#"[plugin]
id = "PUBLISHER_PLACEHOLDER/{name}@0.1.0"
version = "0.1.0"
tier = {tier}
runtime = "wasm"
description = "{description}"

[capabilities]

[build]
target = "wasm32-wasip2"
"#
        ),
    )
    .unwrap();
    std::fs::write(dir.join("README.md"), format!("# {name}\n")).unwrap();
    std::fs::write(dir.join("prebuilt.wasm"), FAKE_WASM).unwrap();
    dir
}

/// A catalog directory holding two plugins.
fn two_plugin_catalog(root: &Path) -> PathBuf {
    let catalog = root.join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    catalog_plugin(
        &catalog,
        "json-query",
        1,
        "query JSON with a path expression",
    );
    catalog_plugin(&catalog, "csv-stats", 2, "summarise CSV columns");
    catalog
}

/// Number of entries in the on-disk keyring.
fn keyring_entries(tmp: &TempDir) -> Vec<String> {
    let path = entangle_dir(tmp).join("keyring.toml");
    let kr = entangle_signing::Keyring::load(&path).expect("keyring must load");
    kr.entries()
        .map(|e| format!("{}:{}", hex::encode(e.fingerprint), e.publisher_name))
        .collect()
}

// ---------------------------------------------------------------------------
// Catalog resolution order
// ---------------------------------------------------------------------------

/// `--catalog` beats `$ENTANGLE_CATALOG`, which beats `./plugins`, which beats
/// `~/.entangle/catalog`. Each level is proved by putting a *differently named*
/// plugin in each candidate and seeing which one is listed.
#[test]
fn catalog_resolution_prefers_flag_then_env_then_cwd_then_home() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);

    let flag_cat = tmp.path().join("from-flag");
    std::fs::create_dir_all(&flag_cat).unwrap();
    catalog_plugin(&flag_cat, "flag-plugin", 1, "via --catalog");

    let env_cat = tmp.path().join("from-env");
    std::fs::create_dir_all(&env_cat).unwrap();
    catalog_plugin(&env_cat, "env-plugin", 1, "via $ENTANGLE_CATALOG");

    let workdir = tmp.path().join("work");
    let cwd_cat = workdir.join("plugins");
    std::fs::create_dir_all(&cwd_cat).unwrap();
    catalog_plugin(&cwd_cat, "cwd-plugin", 1, "via ./plugins");

    let home_cat = entangle_dir(&tmp).join("catalog");
    std::fs::create_dir_all(&home_cat).unwrap();
    catalog_plugin(&home_cat, "home-plugin", 1, "via ~/.entangle/catalog");

    // 1. --catalog wins over everything.
    entangle(&tmp)
        .args(["plugins", "available", "--catalog"])
        .arg(&flag_cat)
        .env("ENTANGLE_CATALOG", &env_cat)
        .current_dir(&workdir)
        .assert()
        .success()
        .stdout(predicate::str::contains("flag-plugin"))
        .stdout(predicate::str::contains("env-plugin").not())
        .stdout(predicate::str::contains("--catalog"));

    // 2. $ENTANGLE_CATALOG wins when no flag is given.
    entangle(&tmp)
        .args(["plugins", "available"])
        .env("ENTANGLE_CATALOG", &env_cat)
        .current_dir(&workdir)
        .assert()
        .success()
        .stdout(predicate::str::contains("env-plugin"))
        .stdout(predicate::str::contains("cwd-plugin").not())
        .stdout(predicate::str::contains("ENTANGLE_CATALOG"));

    // 3. ./plugins wins over the home catalog.
    entangle(&tmp)
        .args(["plugins", "available"])
        .current_dir(&workdir)
        .assert()
        .success()
        .stdout(predicate::str::contains("cwd-plugin"))
        .stdout(predicate::str::contains("home-plugin").not())
        .stdout(predicate::str::contains("./plugins"));

    // 4. ~/.entangle/catalog is the last resort — run from a directory that has
    //    no ./plugins of its own.
    let bare = tmp.path().join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    entangle(&tmp)
        .args(["plugins", "available"])
        .current_dir(&bare)
        .assert()
        .success()
        .stdout(predicate::str::contains("home-plugin"))
        .stdout(predicate::str::contains("~/.entangle/catalog"));
}

/// With no catalog anywhere the command must fail loudly, list every location it
/// tried, and print commands that fix it — and must not imply a registry exists.
#[test]
fn no_catalog_anywhere_names_every_location_and_the_fix() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let bare = tmp.path().join("bare");
    std::fs::create_dir_all(&bare).unwrap();

    entangle(&tmp)
        .args(["plugins", "available"])
        .current_dir(&bare)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no plugin catalog found"))
        .stderr(predicate::str::contains("--catalog"))
        .stderr(predicate::str::contains("ENTANGLE_CATALOG"))
        .stderr(predicate::str::contains("./plugins"))
        .stderr(predicate::str::contains("~/.entangle/catalog"))
        .stderr(predicate::str::contains("git clone"))
        .stderr(predicate::str::contains("no published plugin registry"));

    // `install` fails the same way — the resolution error is shared.
    entangle(&tmp)
        .args(["plugins", "install", "json-query"])
        .current_dir(&bare)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no plugin catalog found"));
}

/// A `--catalog` that does not exist must be an error, never a silent
/// fall-through to `./plugins`.
#[test]
fn an_explicit_catalog_that_is_missing_does_not_fall_through() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let workdir = tmp.path().join("work");
    let cwd_cat = workdir.join("plugins");
    std::fs::create_dir_all(&cwd_cat).unwrap();
    catalog_plugin(&cwd_cat, "cwd-plugin", 1, "via ./plugins");

    entangle(&tmp)
        .args(["plugins", "available", "--catalog"])
        .arg(tmp.path().join("does-not-exist"))
        .current_dir(&workdir)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a directory"))
        .stderr(predicate::str::contains("--catalog"));

    entangle(&tmp)
        .args(["plugins", "available"])
        .env("ENTANGLE_CATALOG", tmp.path().join("also-missing"))
        .current_dir(&workdir)
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE_CATALOG"));
}

// ---------------------------------------------------------------------------
// `plugins available`
// ---------------------------------------------------------------------------

#[test]
fn available_lists_name_tier_and_description_from_each_manifest() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let catalog = two_plugin_catalog(tmp.path());

    entangle(&tmp)
        .args(["plugins", "available", "--catalog"])
        .arg(&catalog)
        .assert()
        .success()
        .stdout(predicate::str::contains("NAME"))
        .stdout(predicate::str::contains("json-query"))
        .stdout(predicate::str::contains(
            "query JSON with a path expression",
        ))
        .stdout(predicate::str::contains("csv-stats"))
        .stdout(predicate::str::contains("summarise CSV columns"))
        .stdout(predicate::str::contains("entangle plugins install"));
}

#[test]
fn available_json_is_machine_readable() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let catalog = two_plugin_catalog(tmp.path());

    let out = entangle(&tmp)
        .args(["plugins", "available", "--json", "--catalog"])
        .arg(&catalog)
        .output()
        .unwrap();
    assert!(out.status.success(), "available --json must succeed");

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("must emit valid JSON");
    assert_eq!(v["source"], "flag");
    assert_eq!(v["catalog"], catalog.display().to_string());
    let plugins = v["plugins"].as_array().unwrap();
    assert_eq!(plugins.len(), 2);
    // Sorted by name: csv-stats then json-query.
    assert_eq!(plugins[0]["name"], "csv-stats");
    assert_eq!(plugins[0]["tier"], 2);
    assert_eq!(plugins[1]["name"], "json-query");
    assert_eq!(plugins[1]["tier"], 1);
    assert_eq!(plugins[1]["version"], "0.1.0");
    assert_eq!(plugins[1]["runtime"], "wasm");
    assert!(v["problems"].as_array().unwrap().is_empty());
}

/// A catalog that exists but holds no plugin projects explains the layout
/// instead of printing an empty table.
#[test]
fn available_on_an_empty_catalog_explains_the_expected_layout() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let empty = tmp.path().join("empty-catalog");
    std::fs::create_dir_all(&empty).unwrap();

    entangle(&tmp)
        .args(["plugins", "available", "--catalog"])
        .arg(&empty)
        .assert()
        .success()
        .stdout(predicate::str::contains("No plugins found"))
        .stdout(predicate::str::contains("entangle.toml"));
}

/// One unreadable manifest must not hide the readable ones.
#[test]
fn available_reports_a_broken_plugin_without_hiding_the_others() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let catalog = two_plugin_catalog(tmp.path());
    let broken = catalog.join("broken");
    std::fs::create_dir_all(&broken).unwrap();
    std::fs::write(broken.join("entangle.toml"), "not = = valid toml").unwrap();

    entangle(&tmp)
        .args(["plugins", "available", "--catalog"])
        .arg(&catalog)
        .assert()
        .success()
        .stdout(predicate::str::contains("json-query"))
        .stderr(predicate::str::contains("skipped"))
        .stderr(predicate::str::contains("broken"));
}

/// `search` is an accepted alias — that is the word people type.
#[test]
fn search_is_an_alias_for_available() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let catalog = two_plugin_catalog(tmp.path());

    entangle(&tmp)
        .args(["plugins", "search", "--catalog"])
        .arg(&catalog)
        .assert()
        .success()
        .stdout(predicate::str::contains("json-query"));
}

// ---------------------------------------------------------------------------
// `plugins install`
// ---------------------------------------------------------------------------

/// The core claim: one command builds, signs, trusts, and reports a ready
/// `invoke` line — and the user never runs `keyring add` by hand.
#[test]
fn install_builds_signs_and_trusts_the_users_own_key() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let catalog = two_plugin_catalog(tmp.path());

    assert!(
        keyring_entries(&tmp).is_empty(),
        "a fresh keyring must start empty"
    );

    entangle(&tmp)
        .args(["plugins", "install", "json-query", "--no-load", "--catalog"])
        .arg(&catalog)
        .arg("--wasm")
        .arg(catalog.join("json-query/prebuilt.wasm"))
        .assert()
        .success()
        .stdout(predicate::str::contains("[1/4] catalog:"))
        .stdout(predicate::str::contains("trusted your own publisher key"))
        .stdout(predicate::str::contains("entangle plugins invoke"));

    // The signed package landed in ~/.entangle/plugins/<name>/.
    let dist = entangle_dir(&tmp).join("plugins/json-query");
    for f in ["plugin.wasm", "entangle.toml", "plugin.wasm.sig"] {
        assert!(dist.join(f).exists(), "{f} missing from {}", dist.display());
    }

    // The manifest is fully qualified and signed by *this* user's key.
    let vm = entangle_manifest::load_manifest(&dist.join("entangle.toml")).unwrap();
    let pem = std::fs::read_to_string(entangle_dir(&tmp).join("identity.key")).unwrap();
    let kp = entangle_signing::IdentityKeyPair::from_pem(&pem).unwrap();
    assert_eq!(vm.plugin_id.name, "json-query");
    assert_eq!(vm.plugin_id.publisher, kp.fingerprint_hex());

    // And that key is now trusted, so a load would verify.
    let entries = keyring_entries(&tmp);
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one trusted key: {entries:?}"
    );
    assert!(
        entries[0].ends_with(":self"),
        "own key should be trusted as \"self\": {entries:?}"
    );
    let bundle: entangle_signing::SignatureBundle =
        toml::from_str(&std::fs::read_to_string(dist.join("plugin.wasm.sig")).unwrap()).unwrap();
    let keyring =
        entangle_signing::Keyring::load(&entangle_dir(&tmp).join("keyring.toml")).unwrap();
    entangle_signing::verify_artifact(
        &std::fs::read(dist.join("plugin.wasm")).unwrap(),
        &std::fs::read(dist.join("entangle.toml")).unwrap(),
        &bundle,
        &keyring,
    )
    .expect("the installed package must verify against the keyring install just wrote");
}

/// Installing twice must not error and must not add a second copy of the key —
/// `keyring add` is not idempotent by accident here, it is by construction.
#[test]
fn installing_twice_is_idempotent_for_the_keyring() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let catalog = two_plugin_catalog(tmp.path());

    let install = || {
        entangle(&tmp)
            .args(["plugins", "install", "json-query", "--no-load", "--catalog"])
            .arg(&catalog)
            .arg("--wasm")
            .arg(catalog.join("json-query/prebuilt.wasm"))
            .output()
            .unwrap()
    };

    let first = install();
    assert!(first.status.success());
    let first_out = String::from_utf8_lossy(&first.stdout).to_string();
    assert!(
        first_out.contains("trusted your own publisher key"),
        "{first_out}"
    );

    let second = install();
    assert!(
        second.status.success(),
        "a second install must not fail: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_out = String::from_utf8_lossy(&second.stdout).to_string();
    assert!(
        second_out.contains("already trusted"),
        "second install should report the key as already trusted:\n{second_out}"
    );

    let entries = keyring_entries(&tmp);
    assert_eq!(entries.len(), 1, "the key was added twice: {entries:?}");

    // `keyring add` of the same key is likewise a no-op, not an error.
    let pem = std::fs::read_to_string(entangle_dir(&tmp).join("identity.key")).unwrap();
    let kp = entangle_signing::IdentityKeyPair::from_pem(&pem).unwrap();
    entangle(&tmp)
        .args([
            "keyring",
            "add",
            &hex::encode(kp.public().as_bytes()),
            "--name",
            "some-other-name",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("already trusted"));
    let entries = keyring_entries(&tmp);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].ends_with(":self"),
        "an existing name must not be overwritten: {entries:?}"
    );
}

#[test]
fn install_of_an_unknown_name_lists_what_is_available() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let catalog = two_plugin_catalog(tmp.path());

    entangle(&tmp)
        .args(["plugins", "install", "json", "--catalog"])
        .arg(&catalog)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no plugin named"))
        .stderr(predicate::str::contains("Did you mean: json-query"))
        .stderr(predicate::str::contains("entangle plugins available"));
}

#[test]
fn install_without_an_identity_says_how_to_get_one() {
    let tmp = TempDir::new().unwrap(); // deliberately no `entangle init`
    let catalog = two_plugin_catalog(tmp.path());

    entangle(&tmp)
        .args(["plugins", "install", "json-query", "--no-load", "--catalog"])
        .arg(&catalog)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no identity key"))
        .stderr(predicate::str::contains("entangle init --non-interactive"))
        .stderr(predicate::str::contains("entangle quickstart"));
}

/// A missing compile target must produce the exact `rustup` fix, not a wall of
/// cargo output — and must be detected *before* anything is compiled.
#[test]
fn a_missing_wasm_target_prints_the_rustup_command() {
    let tmp = TempDir::new().unwrap();
    init(&tmp);
    let catalog = two_plugin_catalog(tmp.path());

    entangle(&tmp)
        .args([
            "plugins",
            "install",
            "json-query",
            "--no-load",
            "--target",
            "wasm32-unknown-nonexistent",
            "--catalog",
        ])
        .arg(&catalog)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "rustup target add wasm32-unknown-nonexistent",
        ));
}

// ---------------------------------------------------------------------------
// `quickstart`
// ---------------------------------------------------------------------------

/// Quickstart must be safe to run twice: the identity is created once and never
/// regenerated, and the user's own key is trusted exactly once.
///
/// The catalog here is deliberately empty, which stops the run before the (slow)
/// wasm build while still exercising every step that *mutates* state — identity
/// creation and keyring trust — twice.
#[test]
fn quickstart_is_safe_to_run_twice() {
    let tmp = TempDir::new().unwrap();
    let empty = tmp.path().join("empty-catalog");
    std::fs::create_dir_all(&empty).unwrap();

    let quickstart = || {
        entangle(&tmp)
            .args(["quickstart", "--catalog"])
            .arg(&empty)
            .output()
            .unwrap()
    };

    let first = quickstart();
    let first_out = String::from_utf8_lossy(&first.stdout).to_string();
    // It got as far as identity + trust before running out of plugins to demo.
    assert!(first_out.contains("[1/6] identity"), "{first_out}");
    assert!(
        first_out.contains("trusted your own publisher key"),
        "{first_out}"
    );
    assert!(
        String::from_utf8_lossy(&first.stderr).contains("no plugin projects"),
        "an empty catalog should say so: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let id_after_first = std::fs::read_to_string(entangle_dir(&tmp).join("identity.key")).unwrap();
    let keyring_after_first = keyring_entries(&tmp);
    assert_eq!(keyring_after_first.len(), 1, "{keyring_after_first:?}");

    let second = quickstart();
    let second_out = String::from_utf8_lossy(&second.stdout).to_string();
    assert!(
        second_out.contains("Already initialized"),
        "the second run must not re-init: {second_out}"
    );
    assert!(
        second_out.contains("already trusted"),
        "the second run must not re-add the key: {second_out}"
    );

    // Nothing was clobbered.
    let id_after_second = std::fs::read_to_string(entangle_dir(&tmp).join("identity.key")).unwrap();
    assert_eq!(
        id_after_first, id_after_second,
        "identity.key was regenerated by a second quickstart"
    );
    assert_eq!(
        keyring_after_first,
        keyring_entries(&tmp),
        "the keyring changed on a second quickstart"
    );
    // No stray backups were made.
    let backups: Vec<_> = std::fs::read_dir(entangle_dir(&tmp))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".bak"))
        .collect();
    assert!(backups.is_empty(), "unexpected backups: {backups:?}");
}

/// Quickstart on a host with no catalog fails with the same actionable error as
/// `install`, and says nothing about a registry.
#[test]
fn quickstart_without_a_catalog_explains_how_to_get_one() {
    let tmp = TempDir::new().unwrap();
    let bare = tmp.path().join("bare");
    std::fs::create_dir_all(&bare).unwrap();

    entangle(&tmp)
        .args(["quickstart"])
        .current_dir(&bare)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no plugin catalog found"))
        .stderr(predicate::str::contains("git clone"))
        .stderr(predicate::str::contains("--catalog /path/to"));

    // ...but it still created the identity on the way, so the next attempt with
    // a catalog has nothing left to set up.
    assert!(entangle_dir(&tmp).join("identity.key").exists());
}

#[test]
fn quickstart_rejects_an_unknown_starter_by_name() {
    let tmp = TempDir::new().unwrap();
    let catalog = two_plugin_catalog(tmp.path());

    entangle(&tmp)
        .args(["quickstart", "--plugin", "does-not-exist", "--catalog"])
        .arg(&catalog)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no plugin named"))
        .stderr(predicate::str::contains("Available: csv-stats, json-query"));
}

// ---------------------------------------------------------------------------
// The real thing (opt-in)
// ---------------------------------------------------------------------------

/// `entangle quickstart` against the repository's own `plugins/` catalog, with
/// nothing faked: real cargo build, real signature, real load, real invoke.
///
/// `#[ignore]`d because it compiles wasm (needs the `wasm32-wasip2` target and a
/// reachable registry) and takes minutes, and because it requires the top-level
/// `plugins/` catalog to be present.
///
/// ```text
/// rustup target add wasm32-wasip2
/// cargo test -p entangle-cli --test catalog -- --ignored
/// ```
#[test]
#[ignore = "compiles real wasm: needs the wasm32-wasip2 target, a reachable registry, and ./plugins"]
fn quickstart_against_the_repository_catalog() {
    let repo_plugins = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("plugins");
    assert!(
        repo_plugins.is_dir(),
        "expected a catalog at {}",
        repo_plugins.display()
    );

    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["quickstart", "--catalog"])
        .arg(&repo_plugins)
        .timeout(std::time::Duration::from_secs(900))
        .assert()
        .success()
        .stdout(predicate::str::contains("What just happened"))
        .stdout(predicate::str::contains("What to try next"));

    // A second run must still succeed (idempotency, with the build cached).
    entangle(&tmp)
        .args(["quickstart", "--catalog"])
        .arg(&repo_plugins)
        .timeout(std::time::Duration::from_secs(900))
        .assert()
        .success()
        .stdout(predicate::str::contains("already trusted"));
}
