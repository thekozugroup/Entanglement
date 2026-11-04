//! `entangle config set|get|unset` end to end (spec §6.1.1, §6.4, §9.2).
//!
//! Each test runs the real binary with `HOME` pointed at a fresh tempdir.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn entangle(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", home.path())
        .env_remove("XDG_RUNTIME_DIR")
        .env("NO_COLOR", "1");
    cmd
}

fn cfg_path(home: &TempDir) -> std::path::PathBuf {
    home.path().join(".entangle/config.toml")
}

fn write_cfg(home: &TempDir, text: &str) {
    let p = cfg_path(home);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

const HAND_EDITED: &str = "# my notes: keep me\n\
[mesh]\n\
transports = [\"local\"]   # LAN only for now\n\
\n\
[security]\n\
max_tier_allowed = 4 # ceiling\n";

/// The shipped liveness hint (`entangle config set mesh.tailscale.enabled
/// false`) names a working command, and its inverse enables the transport
/// as the daemon needs it: both `[mesh.tailscale] enabled` and the
/// `transports` entry. Comments, order and the file mode survive.
#[test]
fn tailscale_switch_edits_both_places_and_preserves_the_file() {
    let home = TempDir::new().unwrap();
    write_cfg(&home, HAND_EDITED);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(cfg_path(&home), std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    entangle(&home)
        .args(["config", "set", "mesh.tailscale.enabled", "true"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "set mesh.tailscale.enabled = true",
        ))
        .stdout(predicate::str::contains(
            "takes effect when the daemon (re)starts",
        ));
    let text = std::fs::read_to_string(cfg_path(&home)).unwrap();
    assert!(
        text.starts_with(
            "# my notes: keep me\n[mesh]\ntransports = [\"local\", \"tailscale\"]   # LAN only for now\n"
        ),
        "{text}"
    );
    assert!(text.contains("max_tier_allowed = 4 # ceiling"), "{text}");
    assert!(
        text.contains("[mesh.tailscale]\nenabled = true\n"),
        "{text}"
    );
    let cfg: entangle_bin::config::Config = toml::from_str(&text).unwrap();
    assert!(entangle_bin::tailscale::enabled(&cfg.mesh));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(cfg_path(&home))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "the file mode is kept");
    }

    entangle(&home)
        .args(["config", "get", "mesh.tailscale.enabled"])
        .assert()
        .success()
        .stdout("true\n");

    entangle(&home)
        .args(["config", "set", "mesh.tailscale.enabled", "false"])
        .assert()
        .success();
    let cfg: entangle_bin::config::Config =
        toml::from_str(&std::fs::read_to_string(cfg_path(&home)).unwrap()).unwrap();
    assert_eq!(cfg.mesh.transports, ["local"]);
    assert!(!cfg.mesh.tailscale.enabled);
}

/// A value of the wrong type, or a file the daemon would refuse, is
/// reported and nothing is written.
#[test]
fn refused_edits_leave_the_file_byte_for_byte_unchanged() {
    let home = TempDir::new().unwrap();
    write_cfg(&home, HAND_EDITED);
    for (args, code) in [
        (vec!["mesh.tailscale.port", "99999"], "ENTANGLE-E0781"),
        (vec!["security.max_tier_allowed", "9"], "ENTANGLE-E0781"),
        (vec!["mesh.tailscale.prot", "1"], "ENTANGLE-E0780"),
        (vec!["mesh.overrides.bob", "iroh"], "ENTANGLE-E0782"),
        // multi-node with no paired peer: the daemon would not start.
        (vec!["mesh.multi_node", "true"], "ENTANGLE-E0050"),
    ] {
        let mut all = vec!["config", "set"];
        all.extend(args.iter().copied());
        entangle(&home)
            .args(&all)
            .assert()
            .failure()
            .stderr(predicate::str::contains(code));
        assert_eq!(
            std::fs::read_to_string(cfg_path(&home)).unwrap(),
            HAND_EDITED,
            "{args:?} changed the file"
        );
    }
}

#[test]
fn metrics_listen_is_validated_when_enabled() {
    let home = TempDir::new().unwrap();
    write_cfg(&home, "[metrics]\nlisten = \"0.0.0.0:9464\"\n");
    entangle(&home)
        .args(["config", "set", "metrics.enabled", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENTANGLE-E0782"))
        .stderr(predicate::str::contains("E0656"));
    assert_eq!(
        std::fs::read_to_string(cfg_path(&home)).unwrap(),
        "[metrics]\nlisten = \"0.0.0.0:9464\"\n"
    );
}

#[test]
fn label_get_unset_and_the_listing() {
    let home = TempDir::new().unwrap();
    entangle(&home)
        .args(["config", "set", "node.label", "alice-laptop"])
        .assert()
        .success();
    entangle(&home)
        .args(["config", "get", "node.label"])
        .assert()
        .success()
        .stdout("alice-laptop\n");
    entangle(&home)
        .args(["config", "get", "mesh.tailscale.port", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"value\":41643"))
        .stdout(predicate::str::contains("\"explicit\":false"));
    entangle(&home)
        .args(["config", "get"])
        .assert()
        .success()
        .stdout(predicate::str::contains("* node.label"))
        .stdout(predicate::str::contains("security.max_tier_allowed"))
        .stdout(predicate::str::contains("[reload]"));
    entangle(&home)
        .args(["config", "unset", "node.label"])
        .assert()
        .success();
    entangle(&home)
        .args(["config", "get", "node.label"])
        .assert()
        .success()
        .stdout("(unset)\n");
    entangle(&home)
        .args(["config", "set", "security.max_tier_allowed", "3"])
        .assert()
        .success()
        .stdout(predicate::str::contains("entangle config reload"));
}

/// Every `entangle config set ...` hint shipped in the code names a key the
/// command accepts with the value shown.
#[test]
fn shipped_config_set_hints_name_working_commands() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut hints = Vec::new();
    let mut stack = vec![root.join("crates"), root.join("docs")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                if !p.ends_with("target") {
                    stack.push(p);
                }
                continue;
            }
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "rs" | "md") || p.ends_with("config_set.rs") {
                continue;
            }
            // A Rust string continued over a line (`\` + newline) is one
            // command for this purpose.
            let text = std::fs::read_to_string(&p)
                .unwrap_or_default()
                .replace("\\\n", " ");
            for (i, _) in text.match_indices("entangle config set ") {
                let rest = &text[i + "entangle config set ".len()..];
                let words: Vec<&str> = rest.split_whitespace().take(2).collect();
                if words.len() == 2 {
                    let clean =
                        |w: &str| w.trim_matches(|c: char| "`'\".,;)".contains(c)).to_owned();
                    let (k, v) = (clean(words[0]), clean(words[1]));
                    if [&k, &v].iter().any(|w| w.contains(['<', '{'])) || v.is_empty() {
                        continue;
                    }
                    hints.push((p.display().to_string(), k, v));
                }
            }
        }
    }
    assert!(
        hints
            .iter()
            .any(|(_, k, v)| k == "mesh.tailscale.enabled" && v == "false"),
        "the liveness hint was not found: {hints:?}"
    );
    for (file, key, value) in hints {
        let home = TempDir::new().unwrap();
        // A paired peer, so a hint that turns multi-node on is not refused
        // for want of one.
        let peers = home.path().join(".entangle/peers.toml");
        std::fs::create_dir_all(peers.parent().unwrap()).unwrap();
        let k = entangle_signing::IdentityKeyPair::generate();
        let id = entangle_types::peer_id::PeerId::from_public_key_bytes(k.public().as_bytes());
        entangle_peers::PeerStore::open(&peers)
            .unwrap()
            .add(entangle_peers::TrustedPeer::new(
                id,
                hex::encode(k.public().as_bytes()),
                "p".into(),
            ))
            .unwrap();
        let out = entangle(&home)
            .args(["config", "set", &key, &value])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{file}: `entangle config set {key} {value}` failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The pairing commands are printed when a transport is switched on with no
/// device paired, and not when one is switched off.
#[test]
fn enabling_a_transport_with_no_peer_prints_the_pairing_commands() {
    let home = TempDir::new().unwrap();
    entangle(&home)
        .args(["config", "set", "mesh.iroh.enabled", "true"])
        .assert()
        .success()
        .stdout(predicate::str::contains("entangle pair --print-code"));
    entangle(&home)
        .args(["config", "set", "mesh.local.enabled", "true"])
        .assert()
        .success();
    entangle(&home)
        .args(["config", "set", "mesh.local.enabled", "false"])
        .assert()
        .success()
        .stdout(predicate::str::contains("entangle pair").not());
}
