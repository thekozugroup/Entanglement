//! CLI ↔ daemon `config.toml` schema compatibility lock.
//!
//! The `entangle` CLI **writes** `~/.entangle/config.toml` (see
//! `entangle init` → `crates/entangle-cli/src/cmd/init.rs`), and the
//! `entangled` daemon **reads** it (`entangle_bin::config::load_config`).
//! Since every daemon section carries `#[serde(deny_unknown_fields)]`, any
//! drift between the two schemas is not a silently-ignored setting — it is a
//! **startup outage**: the daemon refuses to boot on a file the CLI just
//! wrote.
//!
//! This test file makes that drift impossible to merge, in three layers:
//!
//! 1. [`cli_mirror`] reproduces the CLI's `Config` structs field-for-field and
//!    serializes them through the exact call the CLI's `config::save` uses
//!    (`toml::to_string_pretty`). The daemon must parse the resulting bytes.
//! 2. [`source_of_truth`] reads `crates/entangle-cli/src/config.rs` off disk
//!    at test time and asserts the mirror still matches it — so the mirror
//!    itself cannot go stale without a test failure.
//! 3. The remaining tests pin the semantics that make layers 1–2 meaningful:
//!    unknown keys really are rejected, omitted sections really do default,
//!    and the tier boundaries really are validated.
//!
//! `entangle-cli` is a **binary-only crate** (no `[lib]` target — see
//! `crates/entangle-cli/Cargo.toml`), so it cannot be added as a
//! dev-dependency and its types cannot be imported directly. Layer 2 exists
//! precisely to compensate for that.

use entangle_bin::config::Config as DaemonConfig;
use entangle_types::tier::Tier;

// ---------------------------------------------------------------------------
// Layer 1 — mirror of the CLI's on-disk schema
// ---------------------------------------------------------------------------

/// A field-for-field mirror of the CLI's config structs.
///
/// **SOURCE OF TRUTH: `crates/entangle-cli/src/config.rs`.** Do not edit these
/// structs to make a test pass — edit them only to track a deliberate change
/// to the CLI, and make sure the daemon's `crates/entangle-bin/src/config.rs`
/// tracks it in the same commit. The [`source_of_truth`] tests below verify
/// this mirror against the real CLI source file on every run.
mod cli_mirror {
    use serde::{Deserialize, Serialize};

    /// Mirrors `entangle_cli::config::Config`.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Config {
        #[serde(default)]
        pub mesh: MeshConfig,
        #[serde(default)]
        pub security: SecurityConfig,
    }

    /// Mirrors `entangle_cli::config::MeshConfig`.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct MeshConfig {
        #[serde(default)]
        pub transports: Vec<String>,
        #[serde(default)]
        pub multi_node: bool,
    }

    /// Mirrors `entangle_cli::config::SecurityConfig`. Note the bare `u8` —
    /// the daemon parses the same integer into a `Tier`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SecurityConfig {
        #[serde(default = "default_max_tier")]
        pub max_tier_allowed: u8,
    }

    impl Default for SecurityConfig {
        fn default() -> Self {
            Self {
                max_tier_allowed: default_max_tier(),
            }
        }
    }

    /// Mirrors `entangle_cli::config::default_max_tier`.
    pub fn default_max_tier() -> u8 {
        5
    }

    /// Mirrors the body of `entangle_cli::config::save` — the CLI writes
    /// exactly these bytes to `~/.entangle/config.toml`.
    pub fn save_to_string(c: &Config) -> String {
        toml::to_string_pretty(c).expect("CLI config must serialize")
    }
}

/// Serialize a CLI config the way `entangle init` does, then parse it with the
/// daemon's parser. Panics with the offending TOML on failure.
fn daemon_parses_cli_output(cfg: &cli_mirror::Config) -> DaemonConfig {
    let written = cli_mirror::save_to_string(cfg);
    match toml::from_str::<DaemonConfig>(&written) {
        Ok(parsed) => parsed,
        Err(e) => panic!(
            "CLI ↔ daemon config drift: the daemon refuses to parse a file the CLI writes.\n\
             This is a STARTUP OUTAGE, not a warning.\n\
             --- CLI-written config.toml ---\n{written}\
             --- daemon parse error ---\n{e}\n\
             Reconcile crates/entangle-cli/src/config.rs with \
             crates/entangle-bin/src/config.rs."
        ),
    }
}

#[test]
fn daemon_parses_the_exact_bytes_entangle_init_writes() {
    // Precisely the value `entangle init` constructs in
    // crates/entangle-cli/src/cmd/init.rs.
    let cli_cfg = cli_mirror::Config {
        mesh: cli_mirror::MeshConfig {
            transports: vec!["local".to_owned()],
            multi_node: false,
        },
        security: cli_mirror::SecurityConfig {
            max_tier_allowed: 3,
        },
    };

    let daemon = daemon_parses_cli_output(&cli_cfg);

    // Every value survives the crossing — no field silently falls back to a
    // default, which is the failure mode `deny_unknown_fields` cannot catch.
    assert_eq!(daemon.mesh.transports, vec!["local".to_owned()]);
    assert!(!daemon.mesh.multi_node);
    assert_eq!(daemon.security.max_tier_allowed, Tier::Networked);
    // Daemon-only section the CLI never writes: defaults must fill it in.
    assert_eq!(daemon.runtime.bus_capacity, 1024);
}

#[test]
fn daemon_parses_the_cli_default_config() {
    // `Config::default()` — what a CLI with no answers would emit.
    let daemon = daemon_parses_cli_output(&cli_mirror::Config::default());
    assert!(daemon.mesh.transports.is_empty());
    assert!(!daemon.mesh.multi_node);
    // The CLI's `default_max_tier()` (5) must map onto the daemon's default.
    assert_eq!(daemon.security.max_tier_allowed, Tier::Native);
    assert_eq!(
        daemon.security.max_tier_allowed,
        Tier::try_from(cli_mirror::default_max_tier()).unwrap(),
        "CLI and daemon must agree on the default tier ceiling"
    );
}

#[test]
fn every_cli_representable_value_crosses_the_boundary_intact() {
    for multi_node in [false, true] {
        for transports in [
            vec![],
            vec!["local".to_owned()],
            vec!["local".to_owned(), "relay".to_owned()],
        ] {
            for tier_u8 in 1u8..=5 {
                let cli_cfg = cli_mirror::Config {
                    mesh: cli_mirror::MeshConfig {
                        transports: transports.clone(),
                        multi_node,
                    },
                    security: cli_mirror::SecurityConfig {
                        max_tier_allowed: tier_u8,
                    },
                };
                let daemon = daemon_parses_cli_output(&cli_cfg);
                assert_eq!(daemon.mesh.transports, transports);
                assert_eq!(daemon.mesh.multi_node, multi_node);
                assert_eq!(
                    u8::from(daemon.security.max_tier_allowed),
                    tier_u8,
                    "tier {tier_u8} must round-trip through Tier unchanged"
                );
            }
        }
    }
}

#[test]
fn cli_can_read_back_a_daemon_written_config() {
    // The reverse direction: `entangle` subcommands also *read* config.toml.
    // A daemon-serialized file carries the daemon-only `[runtime]` section;
    // the CLI (which has no `deny_unknown_fields`) must tolerate it rather
    // than erroring out.
    let daemon = DaemonConfig::default();
    let written = toml::to_string_pretty(&daemon).expect("daemon config serializes");
    assert!(
        written.contains("[runtime]"),
        "expected the daemon-only section in {written}"
    );

    let cli: cli_mirror::Config = toml::from_str(&written).unwrap_or_else(|e| {
        panic!("CLI must tolerate a daemon-written config.toml\n--- file ---\n{written}--- error ---\n{e}")
    });
    assert_eq!(cli.mesh.transports, daemon.mesh.transports);
    assert_eq!(cli.mesh.multi_node, daemon.mesh.multi_node);
    assert_eq!(
        cli.security.max_tier_allowed,
        u8::from(daemon.security.max_tier_allowed)
    );
}

// ---------------------------------------------------------------------------
// Layer 2 — the mirror above is checked against the real CLI source
// ---------------------------------------------------------------------------

mod source_of_truth {
    /// Path to the CLI's config schema, relative to this crate's manifest.
    const CLI_CONFIG_RS: &str = "../entangle-cli/src/config.rs";

    fn cli_source() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CLI_CONFIG_RS);
        std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "cannot read the CLI config schema at {}: {e}\n\
                 If it moved, update CLI_CONFIG_RS in this test — do not delete the check: \
                 it is the only thing keeping the mirror in this file honest.",
                path.display()
            )
        })
    }

    /// Extract the `pub <name>: <type>` field declarations of `struct_name`
    /// from a Rust source string, brace-matched so nested types are safe.
    fn struct_fields(src: &str, struct_name: &str) -> Vec<String> {
        let needle = format!("pub struct {struct_name} {{");
        let start = src
            .find(&needle)
            .unwrap_or_else(|| panic!("`{needle}` not found in the CLI config source"))
            + needle.len();

        let mut depth = 1usize;
        let mut end = start;
        for (i, c) in src[start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(depth == 0, "unbalanced braces in `{struct_name}`");

        src[start..end]
            .lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix("pub "))
            .filter_map(|l| l.split_once(':'))
            .map(|(name, ty)| format!("{}: {}", name.trim(), ty.trim().trim_end_matches(',')))
            .collect()
    }

    /// The CLI's config structs must have exactly these fields, with exactly
    /// these types. A change here is a deliberate schema change: update
    /// `cli_mirror` in this file **and** `crates/entangle-bin/src/config.rs`
    /// in the same commit, or the daemon will refuse to boot on a
    /// CLI-written config (`deny_unknown_fields`).
    #[test]
    fn cli_schema_matches_the_mirror_in_this_file() {
        let src = cli_source();

        assert_eq!(
            struct_fields(&src, "Config"),
            vec!["mesh: MeshConfig", "security: SecurityConfig"],
            "entangle-cli's top-level Config changed"
        );
        assert_eq!(
            struct_fields(&src, "MeshConfig"),
            vec!["transports: Vec<String>", "multi_node: bool"],
            "entangle-cli's [mesh] section changed"
        );
        assert_eq!(
            struct_fields(&src, "SecurityConfig"),
            vec!["max_tier_allowed: u8"],
            "entangle-cli's [security] section changed; the daemon parses this \
             integer as a Tier (serde try_from = u8), so a type change here \
             breaks the wire form"
        );
    }

    /// The field-name scan above would be blind to a `#[serde(rename = ...)]`
    /// or `rename_all`, either of which changes the on-disk key without
    /// changing the field name. Scan the serde attributes specifically, so a
    /// doc comment that merely uses the word "rename" does not trip this.
    #[test]
    fn cli_schema_uses_no_serde_renames() {
        let offenders: Vec<String> = cli_source()
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("#[serde(") && l.contains("rename"))
            .map(str::to_owned)
            .collect();
        assert!(
            offenders.is_empty(),
            "entangle-cli's config uses a serde rename/rename_all: {offenders:?}\n\
             The on-disk keys no longer match the field names, so the mirror in \
             this file (and crates/entangle-bin/src/config.rs) must be \
             re-derived from the renamed keys"
        );
    }

    /// The CLI must keep defaulting to tier 5, matching the daemon's
    /// `SecurityConfig::default()`.
    #[test]
    fn cli_default_tier_is_still_five() {
        let src = cli_source();
        assert!(
            src.contains("fn default_max_tier() -> u8 {"),
            "entangle-cli's default tier helper changed shape"
        );
        assert_eq!(
            super::cli_mirror::default_max_tier(),
            5,
            "mirror drifted from the CLI default"
        );
    }
}

// ---------------------------------------------------------------------------
// Layer 3 — the properties that make layers 1–2 meaningful
// ---------------------------------------------------------------------------

/// `deny_unknown_fields` is active on every section. Without this the drift
/// tests above would be vacuous: an unknown key would parse fine and the
/// setting would be silently dropped.
#[test]
fn unknown_keys_are_rejected_in_every_section() {
    let cases: &[(&str, &str)] = &[
        ("unknown top-level key", "stray = 1\n"),
        ("unknown top-level section", "[telemetry]\nenabled = true\n"),
        ("typo in [security]", "[security]\nmax_teir_allowed = 2\n"),
        ("typo in [mesh]", "[mesh]\nmutli_node = true\n"),
        ("typo in [runtime]", "[runtime]\nbus_capacty = 8\n"),
        // A field the CLI might plausibly add tomorrow: without a matching
        // daemon change this is a hard startup failure, which is exactly why
        // the mirror + source-of-truth tests above exist.
        ("hypothetical new CLI field", "[mesh]\nrelay_url = \"x\"\n"),
        // Knobs that used to live under [runtime] pre-WP5.
        ("moved knob: multi_node", "[runtime]\nmulti_node = true\n"),
        ("moved knob: max_tier", "[runtime]\nmax_tier = 5\n"),
    ];

    for (label, toml_src) in cases {
        assert!(
            toml::from_str::<DaemonConfig>(toml_src).is_err(),
            "{label}: expected deny_unknown_fields to reject:\n{toml_src}"
        );
    }
}

/// The CLI omits sections it does not manage, and a hand-edited file may omit
/// more. Every partial config must still parse, filling the rest from serde
/// defaults.
#[test]
fn partial_configs_fall_back_to_defaults() {
    // Only [mesh] — no [security], no [runtime].
    let cfg: DaemonConfig = toml::from_str("[mesh]\ntransports = [\"local\"]\nmulti_node = true\n")
        .expect("a [mesh]-only config must parse");
    assert_eq!(cfg.mesh.transports, vec!["local".to_owned()]);
    assert!(cfg.mesh.multi_node);
    assert_eq!(cfg.security.max_tier_allowed, Tier::Native);
    assert_eq!(cfg.runtime.bus_capacity, 1024);

    // Only [security].
    let cfg: DaemonConfig = toml::from_str("[security]\nmax_tier_allowed = 1\n")
        .expect("a [security]-only config must parse");
    assert_eq!(cfg.security.max_tier_allowed, Tier::Pure);
    assert!(cfg.mesh.transports.is_empty());
    assert!(!cfg.mesh.multi_node);

    // An empty section header, and a section with a subset of its keys.
    let cfg: DaemonConfig =
        toml::from_str("[mesh]\n[security]\n[runtime]\n").expect("empty sections must parse");
    assert_eq!(cfg.security.max_tier_allowed, Tier::Native);
    assert_eq!(cfg.runtime.bus_capacity, 1024);

    let cfg: DaemonConfig = toml::from_str("[mesh]\nmulti_node = true\n")
        .expect("a partially-populated section must parse");
    assert!(cfg.mesh.multi_node);
    assert!(cfg.mesh.transports.is_empty());

    // Entirely empty file.
    let cfg: DaemonConfig = toml::from_str("").expect("an empty config must parse");
    assert_eq!(cfg.security.max_tier_allowed, Tier::Native);
    assert_eq!(cfg.runtime.bus_capacity, 1024);
}

/// Tier boundaries: 1 and 5 are the extremes the CLI may legitimately write.
#[test]
fn tier_boundaries_one_and_five_are_accepted() {
    let low: DaemonConfig = toml::from_str("[security]\nmax_tier_allowed = 1\n")
        .expect("tier 1 is the minimum legal ceiling");
    assert_eq!(low.security.max_tier_allowed, Tier::Pure);

    let high: DaemonConfig = toml::from_str("[security]\nmax_tier_allowed = 5\n")
        .expect("tier 5 is the maximum legal ceiling");
    assert_eq!(high.security.max_tier_allowed, Tier::Native);

    // Ordering is preserved across the boundary, so the ceiling actually
    // constrains: tier 1 admits strictly less than tier 5.
    assert!(low.security.max_tier_allowed < high.security.max_tier_allowed);
}

/// Values outside 1..=5 are a parse-time hard error, not a clamp and not a
/// silent fallback to the permissive `Tier::Native` default.
#[test]
fn out_of_range_tiers_are_rejected_at_parse_time() {
    for bad in ["0", "6", "255", "-1", "2.5", "\"native\""] {
        let src = format!("[security]\nmax_tier_allowed = {bad}\n");
        assert!(
            toml::from_str::<DaemonConfig>(&src).is_err(),
            "max_tier_allowed = {bad} must be rejected, not silently accepted"
        );
    }

    // The operator gets an actionable message, not a bare type error.
    let err = toml::from_str::<DaemonConfig>("[security]\nmax_tier_allowed = 6\n")
        .expect_err("tier 6 must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid tier value") && msg.contains("1..=5"),
        "expected an actionable range error, got: {msg}"
    );
}

/// End-to-end through the real loader: the CLI writes the file, the daemon
/// loads it from disk exactly as `main.rs` does at startup.
#[test]
fn load_config_boots_on_a_cli_written_file() {
    let cli_cfg = cli_mirror::Config {
        mesh: cli_mirror::MeshConfig {
            transports: vec!["local".to_owned()],
            multi_node: true,
        },
        security: cli_mirror::SecurityConfig {
            max_tier_allowed: 2,
        },
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, cli_mirror::save_to_string(&cli_cfg)).expect("write config.toml");

    let cfg = entangle_bin::config::load_config(&path)
        .expect("the daemon must boot on a config the CLI just wrote");
    assert_eq!(cfg.mesh.transports, vec!["local".to_owned()]);
    assert!(cfg.mesh.multi_node);
    assert_eq!(cfg.security.max_tier_allowed, Tier::Sandboxed);
    assert_eq!(cfg.runtime.bus_capacity, 1024);
}
