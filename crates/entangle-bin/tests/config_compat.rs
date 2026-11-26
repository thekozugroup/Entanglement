//! Compatibility with configurations written before the CLI and daemon shared
//! a schema. The CLI integration test `init_non_interactive_creates_all_files`
//! exercises the current binary and reads its generated file with the daemon parser.

use entangle_bin::config::Config as DaemonConfig;
use entangle_types::tier::Tier;

/// Frozen historical on-disk format for reading operator files across upgrades.
mod legacy_cli {
    use serde::{Deserialize, Serialize};

    /// Original two-section configuration.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Config {
        #[serde(default)]
        pub mesh: MeshConfig,
        #[serde(default)]
        pub security: SecurityConfig,
    }

    /// Original mesh configuration.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct MeshConfig {
        #[serde(default)]
        pub transports: Vec<String>,
        #[serde(default)]
        pub multi_node: bool,
    }

    /// The original security section wrote a bare `u8`;
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

    /// Historical default ceiling.
    pub fn default_max_tier() -> u8 {
        5
    }

    /// Serialize a historical CLI configuration.
    pub fn save_to_string(c: &Config) -> String {
        toml::to_string_pretty(c).expect("CLI config must serialize")
    }
}

/// Serialize a CLI config the way `entangle init` does, then parse it with the
/// daemon's parser. Panics with the offending TOML on failure.
fn daemon_parses_cli_output(cfg: &legacy_cli::Config) -> DaemonConfig {
    let written = legacy_cli::save_to_string(cfg);
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
fn daemon_parses_the_bytes_written_by_legacy_init() {
    // Precisely the value `entangle init` constructs in
    // crates/entangle-cli/src/cmd/init.rs.
    let cli_cfg = legacy_cli::Config {
        mesh: legacy_cli::MeshConfig {
            transports: vec!["local".to_owned()],
            multi_node: false,
        },
        security: legacy_cli::SecurityConfig {
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
    let daemon = daemon_parses_cli_output(&legacy_cli::Config::default());
    assert!(daemon.mesh.transports.is_empty());
    assert!(!daemon.mesh.multi_node);
    // The CLI's `default_max_tier()` (5) must map onto the daemon's default.
    assert_eq!(daemon.security.max_tier_allowed, Tier::Native);
    assert_eq!(
        daemon.security.max_tier_allowed,
        Tier::try_from(legacy_cli::default_max_tier()).unwrap(),
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
                let cli_cfg = legacy_cli::Config {
                    mesh: legacy_cli::MeshConfig {
                        transports: transports.clone(),
                        multi_node,
                    },
                    security: legacy_cli::SecurityConfig {
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

    let cli: legacy_cli::Config = toml::from_str(&written).unwrap_or_else(|e| {
        panic!("CLI must tolerate a daemon-written config.toml\n--- file ---\n{written}--- error ---\n{e}")
    });
    assert_eq!(cli.mesh.transports, daemon.mesh.transports);
    assert_eq!(cli.mesh.multi_node, daemon.mesh.multi_node);
    assert_eq!(
        cli.security.max_tier_allowed,
        u8::from(daemon.security.max_tier_allowed)
    );
}

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
    let cli_cfg = legacy_cli::Config {
        mesh: legacy_cli::MeshConfig {
            transports: vec!["local".to_owned()],
            multi_node: true,
        },
        security: legacy_cli::SecurityConfig {
            max_tier_allowed: 2,
        },
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, legacy_cli::save_to_string(&cli_cfg)).expect("write config.toml");

    let cfg = entangle_bin::config::load_config(&path)
        .expect("the daemon must boot on a config the CLI just wrote");
    assert_eq!(cfg.mesh.transports, vec!["local".to_owned()]);
    assert!(cfg.mesh.multi_node);
    assert_eq!(cfg.security.max_tier_allowed, Tier::Sandboxed);
    assert_eq!(cfg.runtime.bus_capacity, 1024);
}
