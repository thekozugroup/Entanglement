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

// ---------------------------------------------------------------------------
// The wizard (spec §9.2, §9.1.1, §9.4.2, §11 #16-17)
// ---------------------------------------------------------------------------

/// Spawning a script another thread is still writing fails with ETXTBSY;
/// the tests that write fake binaries take turns.
static FAKE: std::sync::Mutex<()> = std::sync::Mutex::new(());

const ACTIVE: &str = r#"{"Version":"1.76.1-t1","BackendState":"Running",
 "Self":{"Online":true,"DNSName":"me.tail1.ts.net.","TailscaleIPs":["100.64.0.1"]},
 "CurrentTailnet":{"Name":"example.com","MagicDNSEnabled":true},
 "User":{"1":{"LoginName":"alice@example.com"},"2":{"LoginName":"bob@example.com"}},"Peer":{}}"#;

/// A fake `tailscale` on `PATH`: `status --json`, `version` and
/// `switch --list` answer from files next to it.
struct FakeTailscale {
    dir: TempDir,
}

impl FakeTailscale {
    fn new(status: &str, version: &str, profiles: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        let script = dir.path().join("tailscale");
        std::fs::write(
            &script,
            "#!/bin/sh\nd=$(dirname \"$0\")\ncase \"$1\" in\n  version) [ -f \"$d/version-fails\" ] && \
             { echo 'tailscale: unknown command' >&2; exit 1; }; cat \"$d/version\" ;;\n  \
             status) cat \"$d/status.json\" ;;\n  switch) cat \"$d/profiles\" ;;\n  *) exit 2 ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(dir.path().join("status.json"), status).unwrap();
        std::fs::write(
            dir.path().join("version"),
            format!("{version}\n  tailscale commit: x\n"),
        )
        .unwrap();
        std::fs::write(dir.path().join("profiles"), profiles).unwrap();
        Self { dir }
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.dir.path().display())
    }

    /// From now on `tailscale version` fails (exit 1, no version printed).
    fn version_fails(self) -> Self {
        std::fs::write(self.dir.path().join("version-fails"), "").unwrap();
        self
    }
}

const ONE_PROFILE: &str = "ID    Tailnet      Account\n1a2b  example.com  alice@example.com*\n";
const TWO_PROFILES: &str = "ID    Tailnet      Account\n1a2b  example.com  alice@example.com*\n\
                            3c4d  corp.ts.net  admin@corp.ts.net\n";

fn daemon_config(tmp: &TempDir) -> entangle_bin::config::Config {
    let text = std::fs::read_to_string(entangle_dir(tmp).join("config.toml")).unwrap();
    toml::from_str(&text).unwrap_or_else(|e| panic!("daemon refuses:\n{text}\n{e}"))
}

fn output_of(a: &assert_cmd::assert::Assert) -> String {
    let o = a.get_output();
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn headless_single_node_writes_the_label_and_no_transports() {
    let tmp = TempDir::new().unwrap();
    let a = entangle(&tmp)
        .args([
            "init",
            "--headless",
            "--single-node",
            "--identity-label",
            "ci-box",
        ])
        .assert()
        .success();
    let out = output_of(&a);
    let cfg = daemon_config(&tmp);
    assert_eq!(cfg.node_label(), Some("ci-box"));
    assert!(cfg.mesh.transports.is_empty());
    assert!(!cfg.mesh.multi_node);
    assert!(!out.contains("Pairing"), "{out}");
    assert!(
        !out.contains('\u{1b}'),
        "no colour without a terminal:\n{out}"
    );
}

/// `--transport tailscale` on an active tailnet: the transport is really on
/// (both keys), the shared-tailnet note, acl-mode and the binary trust line
/// are printed, the firewall is left alone (ports printed instead), and the
/// node is not written as multi-node nor its own key allowlisted.
#[test]
fn headless_tailscale_on_an_active_tailnet() {
    let _g = FAKE.lock().unwrap_or_else(|e| e.into_inner());
    let fake = FakeTailscale::new(ACTIVE, "1.76.1", ONE_PROFILE);
    let tmp = TempDir::new().unwrap();
    let a = entangle(&tmp)
        .env("PATH", fake.path())
        .args([
            "init",
            "--headless",
            "--transport",
            "tailscale,local",
            "--label",
            "lab",
        ])
        .assert()
        .success();
    let out = output_of(&a);
    let cfg = daemon_config(&tmp);
    assert!(entangle_bin::tailscale::enabled(&cfg.mesh), "{out}");
    assert_eq!(cfg.mesh.transports, ["tailscale", "local"]);
    assert_eq!(cfg.mesh.tailscale.acl_mode, "entangle-on-top");
    assert!(
        !cfg.mesh.multi_node,
        "never multi-node with an empty allowlist"
    );
    let peers = entangle_peers::PeerStore::open(entangle_dir(&tmp).join("peers.toml")).unwrap();
    assert!(
        peers.is_empty(),
        "the node's own key is not seeded into the allowlist"
    );
    for needle in [
        "tailnet 'example.com' may be shared with other Entanglement users",
        "acl-mode = \"entangle-on-top\"",
        "Entanglement trusts the local Tailscale binary",
        "version 1.76.1",
        "This tailnet has 2 accounts",
        "init does not change your firewall",
        "UDP 5353",
        "entangle pair --print-code",
        "entangle config set mesh.multi_node true",
    ] {
        assert!(out.contains(needle), "missing {needle:?}:\n{out}");
    }
}

/// Spec §9.1.1: each unusable tailnet ends init with its message and exit
/// code, before anything is written.
#[test]
fn tailscale_failure_modes_exit_with_the_spec_codes_and_write_nothing() {
    let _g = FAKE.lock().unwrap_or_else(|e| e.into_inner());
    let cases = [
        (
            r#"{"BackendState":"NeedsLogin"}"#,
            "1.76.1",
            65,
            "tailnet not authenticated",
        ),
        (
            r#"{"BackendState":"Stopped"}"#,
            "1.76.1",
            65,
            "tailnet stopped",
        ),
        (
            r#"{"BackendState":"Running","Self":{"Online":false}}"#,
            "1.76.1",
            75,
            "authenticated but offline",
        ),
        (ACTIVE, "1.58.0", 69, "ENTANGLE-E0891"),
    ];
    for (status, version, code, needle) in cases {
        let fake = FakeTailscale::new(status, version, ONE_PROFILE);
        let tmp = TempDir::new().unwrap();
        let a = entangle(&tmp)
            .env("PATH", fake.path())
            .args(["init", "--headless", "--transport", "tailscale"])
            .assert()
            .code(code);
        let out = output_of(&a);
        assert!(out.contains(needle), "{needle}:\n{out}");
        assert!(!entangle_dir(&tmp).exists(), "{needle}: files were written");
    }
    // No binary at all.
    let empty = TempDir::new().unwrap();
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .env("PATH", empty.path())
        .args(["init", "--headless", "--transport", "tailscale"])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("tailscale binary not found"))
        .stderr(predicate::str::contains("--transport local,iroh"));
}

/// Spec §11 #17: the 1.62.0 floor holds when `tailscale version` cannot
/// say its version — tailscaled's own (`Version` in `status --json`) is
/// checked instead, and with no version at all the transport is refused —
/// and a tailscaled older than the floor is refused even when the CLI is
/// new enough.
#[test]
fn the_version_floor_does_not_fail_open() {
    let _g = FAKE.lock().unwrap_or_else(|e| e.into_inner());
    let old_daemon = ACTIVE.replace("1.76.1-t1", "1.50.0-t1");
    let no_version = ACTIVE.replace("\"Version\":\"1.76.1-t1\",", "");
    assert_ne!(no_version, ACTIVE);
    let cases = [
        (
            FakeTailscale::new(&old_daemon, "1.76.1", ONE_PROFILE).version_fails(),
            "ENTANGLE-E0891",
            "1.50.0",
        ),
        (
            FakeTailscale::new(&no_version, "1.76.1", ONE_PROFILE).version_fails(),
            "ENTANGLE-E0893",
            "1.62.0",
        ),
        (
            FakeTailscale::new(&old_daemon, "1.76.1", ONE_PROFILE),
            "ENTANGLE-E0891",
            "1.50.0",
        ),
    ];
    for (fake, code, needle) in cases {
        let tmp = TempDir::new().unwrap();
        let a = entangle(&tmp)
            .env("PATH", fake.path())
            .args(["init", "--headless", "--transport", "tailscale"])
            .assert()
            .code(69);
        let out = output_of(&a);
        assert!(out.contains(code) && out.contains(needle), "{code}:\n{out}");
        assert!(!entangle_dir(&tmp).exists(), "{code}: files were written");
    }

    // tailscaled's version stands in for the CLI's when it is new enough.
    let fake = FakeTailscale::new(ACTIVE, "1.76.1", ONE_PROFILE).version_fails();
    let tmp = TempDir::new().unwrap();
    let a = entangle(&tmp)
        .env("PATH", fake.path())
        .args(["init", "--headless", "--transport", "tailscale"])
        .assert()
        .success();
    assert!(
        output_of(&a).contains("version 1.76.1"),
        "{}",
        output_of(&a)
    );
    assert!(entangle_bin::tailscale::enabled(&daemon_config(&tmp).mesh));
}

#[test]
fn several_tailscale_profiles_need_confirmation() {
    let _g = FAKE.lock().unwrap_or_else(|e| e.into_inner());
    let fake = FakeTailscale::new(ACTIVE, "1.76.1", TWO_PROFILES);
    let run = |extra: &[&str]| {
        let tmp = TempDir::new().unwrap();
        let mut args = vec!["init", "--headless", "--transport", "tailscale"];
        args.extend_from_slice(extra);
        let a = entangle(&tmp).env("PATH", fake.path()).args(&args).assert();
        (tmp, a)
    };
    let (_t, a) = run(&[]);
    let out = output_of(&a.code(64));
    assert!(
        out.contains("multiple Tailscale profiles") && out.contains("--tailscale-profile"),
        "{out}"
    );
    let (_t, a) = run(&["--tailscale-profile", "corp.ts.net"]);
    let out = output_of(&a.code(64));
    assert!(out.contains("tailscale switch corp.ts.net"), "{out}");
    let (t, a) = run(&["--tailscale-profile", "example.com"]);
    a.success();
    assert!(entangle_bin::tailscale::enabled(&daemon_config(&t).mesh));
}

/// The interactive wizard reads plain lines from stdin when there is no
/// terminal (spec §9.4.2): no cursor movement, every prompt on its own line.
#[test]
fn interactive_wizard_runs_on_plain_line_prompts() {
    let _g = FAKE.lock().unwrap_or_else(|e| e.into_inner());
    let fake = FakeTailscale::new(ACTIVE, "1.76.1", TWO_PROFILES);
    let tmp = TempDir::new().unwrap();
    // label, multi-node?, tailscale?, confirm profile, local?, iroh?, tier,
    // identity, pair now?
    let answers = "studio-mac\ny\ny\ny\ny\nn\n4\ng\nn\n";
    let a = entangle(&tmp)
        .env("PATH", fake.path())
        .env("TERM", "dumb")
        .arg("init")
        .write_stdin(answers)
        .assert()
        .success();
    let out = output_of(&a);
    let cfg = daemon_config(&tmp);
    assert_eq!(cfg.node_label(), Some("studio-mac"));
    assert_eq!(cfg.mesh.transports, ["tailscale", "local"]);
    assert!(cfg.mesh.tailscale.enabled && !cfg.mesh.multi_node);
    assert_eq!(
        cfg.security.max_tier_allowed,
        entangle_types::tier::Tier::Privileged
    );
    for needle in [
        "Will this daemon ever talk to another Entanglement node? [y/N]:",
        "tailscale 1.76.1",
        "multiple tailnets/profiles detected",
        "Pair another device now? [Y/n]:",
        "entangle pair --print-code",
    ] {
        assert!(out.contains(needle), "missing {needle:?}:\n{out}");
    }
    assert!(
        !out.contains('\r') && !out.contains('\u{1b}'),
        "cursor or colour codes:\n{out:?}"
    );
}

#[test]
fn interactive_single_node_and_an_unconfirmed_profile() {
    let _g = FAKE.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .arg("init")
        .write_stdin("\nn\n\n\n")
        .assert()
        .success();
    let cfg = daemon_config(&tmp);
    assert!(cfg.mesh.transports.is_empty() && cfg.node_label().is_some());

    let fake = FakeTailscale::new(ACTIVE, "1.76.1", TWO_PROFILES);
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .env("PATH", fake.path())
        .arg("init")
        .write_stdin("box\ny\ny\nn\n")
        .assert()
        .code(64)
        .stderr(predicate::str::contains("not confirmed"));
    assert!(!entangle_dir(&tmp).exists());

    // Input that ends early is an error, not a silent default.
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .arg("init")
        .write_stdin("box\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--headless"));
}

/// With an identity already on disk the wizard still offers to import a
/// PEM (keeping it is the default); importing a different key asks for
/// confirmation and backs the old one up first (docs/install.md).
#[test]
fn the_wizard_can_replace_an_existing_identity_with_a_backup() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--headless", "--single-node"])
        .assert()
        .success();
    let dir = entangle_dir(&tmp);
    let old = std::fs::read_to_string(dir.join("identity.key")).unwrap();
    // Not fully initialised: the wizard runs again.
    std::fs::remove_file(dir.join("config.toml")).unwrap();
    std::fs::remove_file(dir.join("keyring.toml")).unwrap();

    // The key to import: another device's identity.
    let other = TempDir::new().unwrap();
    entangle(&other)
        .args(["init", "--headless", "--single-node"])
        .assert()
        .success();
    let pem_path = entangle_dir(&other).join("identity.key");
    let pem = std::fs::read_to_string(&pem_path).unwrap();
    assert_ne!(old, pem);

    // label, multi-node?, tier, identity (keep/import), PEM path, overwrite?,
    // clear peers.toml?
    let answers = format!("box\nn\n5\ni\n{}\ny\nn\n", pem_path.display());
    let a = entangle(&tmp)
        .env("TERM", "dumb")
        .arg("init")
        .write_stdin(answers)
        .assert()
        .success();
    let out = output_of(&a);
    assert_eq!(
        std::fs::read_to_string(dir.join("identity.key")).unwrap(),
        pem,
        "the imported key replaced the old one:\n{out}"
    );
    let backups: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("identity.key.bak-")
        })
        .collect();
    assert_eq!(backups.len(), 1, "{out}");
    assert_eq!(std::fs::read_to_string(backups[0].path()).unwrap(), old);
    assert!(
        out.contains("Overwrite the existing identity.key?"),
        "{out}"
    );

    // Keeping it is the default.
    std::fs::remove_file(dir.join("keyring.toml")).unwrap();
    std::fs::remove_file(dir.join("config.toml")).unwrap();
    entangle(&tmp)
        .arg("init")
        .write_stdin("box\nn\n5\n\n")
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dir.join("identity.key")).unwrap(),
        pem
    );
}

/// config.toml often exists before init (`entangle config set`, `wrapper
/// enable`, `security set-max-tier` create it). The flags given to init
/// are written into it (validated as the daemon loads it), defaults are not,
/// and the notes printed are only for transports the file really has. A
/// ~/.entangle created loosely by another command is tightened to 0700.
#[test]
fn init_applies_its_flags_to_an_existing_config_and_notes_only_what_is_there() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["config", "set", "node.label", "studio"])
        .assert()
        .success();
    let a = entangle(&tmp)
        .args([
            "init",
            "--headless",
            "--max-tier",
            "3",
            "--transport",
            "local,iroh",
            "--label",
            "lab",
        ])
        .assert()
        .success();
    let out = output_of(&a);
    let cfg = daemon_config(&tmp);
    assert_eq!(cfg.node_label(), Some("lab"), "{out}");
    assert_eq!(cfg.mesh.transports, ["local", "iroh"], "{out}");
    assert_eq!(
        cfg.security.max_tier_allowed,
        entangle_types::tier::Tier::Networked,
        "{out}"
    );
    assert!(!cfg.mesh.multi_node);
    assert!(out.contains("Updated"), "{out}");
    assert!(out.contains("UDP 5353"), "{out}");
    let mode = std::fs::metadata(entangle_dir(&tmp))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "{mode:o}");

    // No flags: nothing in the file changes (no default transport is
    // added), and no firewall or pairing notes for transports it lacks.
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["config", "set", "security.max_tier_allowed", "4"])
        .assert()
        .success();
    let before = std::fs::read_to_string(entangle_dir(&tmp).join("config.toml")).unwrap();
    let a = entangle(&tmp)
        .args(["init", "--headless"])
        .assert()
        .success();
    let out = output_of(&a);
    assert_eq!(
        std::fs::read_to_string(entangle_dir(&tmp).join("config.toml")).unwrap(),
        before,
        "{out}"
    );
    assert!(out.contains("Kept existing"), "{out}");
    assert!(
        !out.contains("Firewall") && !out.contains("Pairing"),
        "notes for transports config.toml does not have:\n{out}"
    );
}

/// Interactively, an existing config.toml is kept and its questions are
/// not asked (their answers would have nowhere to go but over the file):
/// only the identity question remains, and the output says how to change a
/// setting.
#[test]
fn the_wizard_keeps_an_existing_config_and_asks_only_for_the_identity() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["config", "set", "security.max_tier_allowed", "3"])
        .assert()
        .success();
    let before = std::fs::read_to_string(entangle_dir(&tmp).join("config.toml")).unwrap();
    let a = entangle(&tmp)
        .env("TERM", "dumb")
        .arg("init")
        .write_stdin("\n")
        .assert()
        .success();
    let out = output_of(&a);
    assert!(!out.contains("Label ["), "{out}");
    assert!(!out.contains("max_tier_allowed ["), "{out}");
    assert!(out.contains("entangle config set"), "{out}");
    assert_eq!(
        std::fs::read_to_string(entangle_dir(&tmp).join("config.toml")).unwrap(),
        before
    );
    assert!(entangle_dir(&tmp).join("identity.key").exists());
}

/// NO_COLOR wins over CLICOLOR_FORCE (spec §9.4.2).
#[test]
fn no_color_is_honoured() {
    let tmp = TempDir::new().unwrap();
    let a = entangle(&tmp)
        .env("CLICOLOR_FORCE", "1")
        .args(["init", "--headless", "--transport", "local"])
        .assert()
        .success();
    assert!(output_of(&a).contains("\u{1b}[1m"), "forced colour is used");
    let tmp = TempDir::new().unwrap();
    let a = entangle(&tmp)
        .env("CLICOLOR_FORCE", "1")
        .env("NO_COLOR", "1")
        .args(["init", "--headless", "--transport", "local"])
        .assert()
        .success();
    assert!(!output_of(&a).contains('\u{1b}'));
}

#[test]
fn bad_flags_are_usage_errors() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["init", "--headless", "--transport", "wifi"])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("ENTANGLE-E0884"));
    entangle(&tmp)
        .args([
            "init",
            "--headless",
            "--single-node",
            "--transport",
            "local",
        ])
        .assert()
        .failure();
    assert!(!entangle_dir(&tmp).exists());
}
