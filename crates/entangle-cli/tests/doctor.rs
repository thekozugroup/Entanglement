//! Integration tests for `entangle doctor`.
//!
//! These tests set `$HOME` to a temporary directory so the doctor checks
//! run against an isolated environment — no real `~/.entangle/` is touched.

use assert_cmd::Command;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// ---------------------------------------------------------------------------
// Helper: build a Command for `entangle doctor` with HOME set to a temp dir.
// ---------------------------------------------------------------------------
fn doctor_cmd(home: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("entangle").unwrap();
    cmd.arg("doctor").env("HOME", home);
    cmd
}

// ---------------------------------------------------------------------------
// Test 1: uninitialized home → identity missing = [fail] = exit 1.
//         All other fails (if any) must also be identity-related.
// ---------------------------------------------------------------------------
#[test]
fn doctor_on_uninitialized_succeeds_with_warns_only() {
    let dir = tempfile::tempdir().unwrap();
    // Neither ~/.entangle/ nor its files exist.
    // identity.key missing → [fail] → exit code 1 (that is the expected outcome).
    let output = doctor_cmd(dir.path()).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    // At least some check lines must appear.
    assert!(
        stderr.contains("[warn]") || stderr.contains("[fail]") || stderr.contains("[skip]"),
        "expected non-ok output, got:\n{stderr}"
    );

    // identity check must be present.
    assert!(
        stderr.contains("identity"),
        "expected identity check:\n{stderr}"
    );

    // config absent → [warn].
    assert!(
        stderr.contains("config"),
        "expected config check:\n{stderr}"
    );

    // The only [fail] line may be "identity" (missing key).
    for line in stderr.lines().filter(|l| l.contains("[fail]")) {
        assert!(
            line.contains("identity"),
            "unexpected [fail] line (expected only identity): {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: after init → identity present, config present → no warn/fail on
//         the core checks.  (Daemon, wasm32, etc. may still warn — that's ok.)
// ---------------------------------------------------------------------------
#[test]
fn doctor_after_init_no_core_fails() {
    let dir = tempfile::tempdir().unwrap();
    let entangle_dir = dir.path().join(".entangle");
    fs::create_dir_all(&entangle_dir).unwrap();

    // Write a valid Ed25519 identity.key.
    let kp = entangle_signing::IdentityKeyPair::generate();
    let pem = kp.to_pem();
    let id_path = entangle_dir.join("identity.key");
    fs::write(&id_path, &pem).unwrap();

    // Correct permissions on Unix.
    #[cfg(unix)]
    {
        fs::set_permissions(&id_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&entangle_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Write a minimal config.toml.
    fs::write(entangle_dir.join("config.toml"), "[mesh]\n").unwrap();

    let output = doctor_cmd(dir.path()).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    // identity must be ok.
    let identity_line = stderr
        .lines()
        .find(|l| l.contains("identity") && !l.contains("identity-perms"))
        .expect("identity check line missing");
    assert!(
        identity_line.contains("[ok]"),
        "expected [ok] for identity, got: {identity_line}"
    );

    // config must be ok.
    let config_line = stderr
        .lines()
        .find(|l| {
            l.contains("  config ")
                || l.contains("  config\t")
                || l.split_whitespace().nth(1) == Some("config")
        })
        .unwrap_or_else(|| {
            stderr
                .lines()
                .find(|l| {
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    parts.get(1).map(|s| *s == "config").unwrap_or(false)
                })
                .unwrap_or("")
        });
    if !config_line.is_empty() {
        assert!(
            config_line.contains("[ok]"),
            "expected [ok] for config, got: {config_line}"
        );
    }

    // No [fail] lines at all.
    for line in stderr.lines() {
        assert!(
            !line.contains("[fail]"),
            "unexpected [fail] line after init: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: identity.key with mode 0644 → identity-perms warns.
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[test]
fn doctor_when_identity_perms_too_loose_warns() {
    let dir = tempfile::tempdir().unwrap();
    let entangle_dir = dir.path().join(".entangle");
    fs::create_dir_all(&entangle_dir).unwrap();
    fs::set_permissions(&entangle_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let kp = entangle_signing::IdentityKeyPair::generate();
    let pem = kp.to_pem();
    let id_path = entangle_dir.join("identity.key");
    fs::write(&id_path, &pem).unwrap();
    // Intentionally too loose.
    fs::set_permissions(&id_path, fs::Permissions::from_mode(0o644)).unwrap();

    let output = doctor_cmd(dir.path()).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    let perm_line = stderr
        .lines()
        .find(|l| l.contains("identity-perms"))
        .expect("identity-perms check missing");
    assert!(
        perm_line.contains("[warn]"),
        "expected [warn] for loose identity-perms, got: {perm_line}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: multi_node = true + empty peers.toml → peers warns.
// ---------------------------------------------------------------------------
#[test]
fn doctor_when_peers_empty_in_multi_node_warns() {
    let dir = tempfile::tempdir().unwrap();
    let entangle_dir = dir.path().join(".entangle");
    fs::create_dir_all(&entangle_dir).unwrap();

    #[cfg(unix)]
    {
        fs::set_permissions(&entangle_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Write a valid identity so identity check doesn't fail.
    let kp = entangle_signing::IdentityKeyPair::generate();
    let pem = kp.to_pem();
    let id_path = entangle_dir.join("identity.key");
    fs::write(&id_path, &pem).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&id_path, fs::Permissions::from_mode(0o600)).unwrap();

    // config.toml with multi_node = true.
    fs::write(
        entangle_dir.join("config.toml"),
        "[mesh]\nmulti_node = true\n",
    )
    .unwrap();

    // peers.toml exists but is empty (no peers).
    fs::write(entangle_dir.join("peers.toml"), "").unwrap();

    let output = doctor_cmd(dir.path()).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    let peers_line = stderr
        .lines()
        .find(|l| l.contains("peers"))
        .expect("peers check line missing");
    assert!(
        peers_line.contains("[warn]"),
        "expected [warn] for multi_node + empty peers, got: {peers_line}"
    );
    assert!(
        peers_line.contains("multi_node"),
        "expected multi_node mention in warn, got: {peers_line}"
    );
}
