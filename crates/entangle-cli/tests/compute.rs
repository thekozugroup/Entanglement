//! CLI integration tests for the `entangle compute` subcommand.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn entangle(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("entangle").expect("entangle binary built");
    cmd.env("HOME", tmp.path());
    cmd
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `entangle compute dispatch --help` must list all expected flags.
#[test]
fn compute_dispatch_help_lists_all_flags() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["compute", "dispatch", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("integrity"))
        .stdout(predicate::str::contains("replicas"))
        .stdout(predicate::str::contains("allow"))
        .stdout(predicate::str::contains("timeout-ms"))
        .stdout(predicate::str::contains("cpu-cores"))
        .stdout(predicate::str::contains("memory-bytes"))
        .stdout(predicate::str::contains("gpu"))
        .stdout(predicate::str::contains("semantic-equivalent"))
        .stdout(predicate::str::contains("--metric"))
        .stdout(predicate::str::contains("--metric-dir"))
        .stdout(predicate::str::contains("--threshold"))
        .stdout(predicate::str::contains("--quorum"))
        .stdout(predicate::str::contains("--json"));
}

/// `semantic-equivalent` needs a metric and a threshold; the CLI says so
/// before contacting anything.
#[test]
fn semantic_equivalent_requires_metric_and_threshold() {
    let tmp = TempDir::new().unwrap();
    let plugin = "0123456789abcdef0123456789abcdef/demo@0.1.0";
    let metric = "0123456789abcdef0123456789abcdef/metric-bleu-4@0.1.0";
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            plugin,
            "--integrity",
            "semantic-equivalent",
        ])
        .args(["--threshold", "0.2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--metric"));
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            plugin,
            "--integrity",
            "semantic-equivalent",
        ])
        .args(["--metric", metric])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--threshold"));
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            plugin,
            "--integrity",
            "semantic-equivalent",
        ])
        .args(["--metric", metric, "--threshold", "0.2", "--replicas", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--replicas 2"));
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            plugin,
            "--integrity",
            "semantic-equivalent",
        ])
        .args(["--metric", metric, "--threshold", "nan"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--threshold"));
}

/// A well-formed semantic-equivalent request gets as far as the daemon: the
/// remaining error is the usual "daemon not running", not a flag problem.
#[test]
fn semantic_equivalent_flags_parse_through_to_the_daemon_call() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args([
            "compute",
            "dispatch",
            "0123456789abcdef0123456789abcdef/demo@0.1.0",
            "--integrity",
            "semantic-equivalent",
            "--metric",
            "0123456789abcdef0123456789abcdef/metric-bleu-4@0.1.0",
            "--threshold",
            "0.15",
            "--replicas",
            "3",
            "--quorum",
            "2",
            "--json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not running"));
}

/// Without a daemon running (and without --allow-local), `compute dispatch`
/// must fail with a clear error message.
#[test]
fn compute_dispatch_with_no_daemon_errors_clearly() {
    let tmp = TempDir::new().unwrap();
    // Point the socket at a path that will never exist.
    entangle(&tmp)
        .args(["compute", "dispatch", "pub/nonexistent@0.1.0"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("daemon not running")
                .or(predicate::str::contains("not running")),
        );
}

/// The `compute` subcommand itself should require a subcommand.
#[test]
fn compute_subcommand_required() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp).arg("compute").assert().failure();
}

/// `entangle compute --help` should mention dispatch.
#[test]
fn compute_help_mentions_dispatch() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["compute", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dispatch"));
}

// ---------------------------------------------------------------------------
// Review fixes: stray integrity flags, and the --allow-local path
// ---------------------------------------------------------------------------

const METRIC: &str = "0123456789abcdef0123456789abcdef/metric-bleu-4@0.1.0";
const PLUGIN: &str = "0123456789abcdef0123456789abcdef/demo@0.1.0";

/// `--metric`, `--metric-dir`, `--threshold` and `--quorum` only mean
/// something under `--integrity semantic-equivalent`. Forgetting that flag
/// used to run the task once, unverified, and exit 0; now it is an error
/// before anything is contacted, for every other mode.
#[test]
fn semantic_flags_without_semantic_equivalent_are_refused() {
    let tmp = TempDir::new().unwrap();
    let cases: [(&[&str], &str); 5] = [
        (&["--metric", METRIC], "--metric"),
        (&["--threshold", "0.15"], "--threshold"),
        (&["--quorum", "2"], "--quorum"),
        (&["--metric-dir", "/nonexistent"], "--metric-dir"),
        (
            &["--integrity", "deterministic", "--metric", METRIC],
            "--metric",
        ),
    ];
    for (flags, named) in cases {
        entangle(&tmp)
            .args(["compute", "dispatch", PLUGIN])
            .args(flags)
            .assert()
            .failure()
            .stderr(predicate::str::contains(named))
            .stderr(predicate::str::contains("semantic-equivalent"));
    }
}

/// `--quorum` is range-checked against the replica pair count locally, not
/// only after the daemon has loaded the metric package.
#[test]
fn semantic_quorum_out_of_range_is_refused_locally() {
    let tmp = TempDir::new().unwrap();
    for quorum in ["0", "4"] {
        entangle(&tmp)
            .args(["compute", "dispatch", PLUGIN])
            .args(["--integrity", "semantic-equivalent", "--metric", METRIC])
            .args(["--threshold", "0.2", "--replicas", "3", "--quorum", quorum])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--quorum"));
    }
}

/// Write a signed tier-1 package for `hello-pong.wasm` under `dir` and trust
/// its publisher in `home`'s keyring. Returns the plugin id.
fn install_hello(home: &TempDir, dir: &std::path::Path) -> String {
    use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
    let kp = IdentityKeyPair::generate();
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../entangle-host/tests/fixtures/hello-pong.wasm"
    ))
    .expect("hello-pong fixture");
    let id = format!("{}/hello@0.1.0", kp.fingerprint_hex());
    let manifest =
        format!("[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n");
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join("plugin.wasm"), &wasm).unwrap();
    let bundle = sign_artifact(&wasm, manifest.as_bytes(), &kp);
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    let mut keyring = Keyring::new();
    keyring.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "self".into(),
        added_at: 0,
        note: String::new(),
    });
    keyring
        .save(&home.path().join(".entangle/keyring.toml"))
        .unwrap();
    id
}

/// `--allow-local` with no daemon loads the task plugin from its package
/// directory (`--plugin-dir`, default `~/.entangle/plugins/<name>`) and runs
/// it; before, the fresh kernel never had the plugin and every local dispatch
/// failed "not loaded".
#[test]
fn allow_local_dispatch_loads_and_runs_the_task_plugin() {
    let tmp = TempDir::new().unwrap();
    let pkg = tmp.path().join("pkg");
    let id = install_hello(&tmp, &pkg);
    entangle(&tmp)
        .args(["--allow-local", "compute", "dispatch", &id])
        .args(["--input", "world", "--plugin-dir"])
        .arg(&pkg)
        .assert()
        .success()
        .stdout(predicate::str::contains("Hello, world!"));

    // Default location, and a package that is not the requested plugin.
    let default_dir = tmp.path().join(".entangle/plugins/hello");
    std::fs::create_dir_all(default_dir.parent().unwrap()).unwrap();
    std::fs::rename(&pkg, &default_dir).unwrap();
    entangle(&tmp)
        .args(["--allow-local", "compute", "dispatch", &id])
        .args(["--input", "world"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Hello, world!"));
    entangle(&tmp)
        .args(["--allow-local", "compute", "dispatch", PLUGIN])
        .args(["--input", "world", "--plugin-dir"])
        .arg(&default_dir)
        .assert()
        .failure()
        .stderr(predicate::str::contains("holds"));
}

/// Without a package to load the local path says so instead of "not loaded".
#[test]
fn allow_local_dispatch_without_a_plugin_package_explains_itself() {
    let tmp = TempDir::new().unwrap();
    entangle(&tmp)
        .args(["--allow-local", "compute", "dispatch", PLUGIN])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--plugin-dir"));
}
